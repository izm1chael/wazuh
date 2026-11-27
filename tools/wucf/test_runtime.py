import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from catalogue import provision, public_metadata
from health import project
from ledger import ContractError, Ledger
from runtime import Batch, Receipt, run


class Provider:
    def __init__(self, batches):
        self.batches = iter(batches)
        self.positions = []

    def fetch(self, current):
        self.positions.append(current)
        return next(self.batches)


class Sink:
    def __init__(self, mode="durable"):
        self.mode = mode
        self.calls = []

    def deliver(self, pid, body):
        self.calls.append((pid, body))
        if self.mode == "exception":
            raise RuntimeError("sensitive internal error")
        return Receipt(pid if self.mode != "wrong" else "f" * 64, self.mode)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "state.db"
        self.config = {"provider": "entra", "dataset": "signins",
                       "credential_ref": "opaque-ref", "interval_seconds": 60}
        self.source = provision("env", "instance", self.config)
        self.ledger = Ledger(self.path, self.source.ledger_scope())
        self.addCleanup(lambda: self.ledger.close())
        self.event = {"id": "e1", "payload": {"value": 1}}

    def test_pagination_and_budget(self):
        provider = Provider([Batch("a", [self.event], True),
                             Batch("b", [], True)])
        result = run(self.ledger, provider, Sink(), 2)
        self.assertEqual(result.status, "budget_exhausted")
        self.assertEqual(result.acknowledged_pages, 2)
        self.assertEqual(provider.positions, [None, "a"])
        self.assertEqual(self.ledger.state()["cursor"], "b")

    def test_restart_retries_pending_before_provider(self):
        first = Sink("exception")
        result = run(self.ledger, Provider([Batch("a", [self.event])]), first)
        self.assertEqual(result.status, "delivery_unknown")
        self.assertIsNone(self.ledger.state()["cursor"])
        self.ledger.close()
        self.ledger = Ledger(self.path, self.source.ledger_scope())
        provider = Provider([Batch("a", [])])
        sink = Sink()
        result = run(self.ledger, provider, sink)
        self.assertEqual(sink.calls, first.calls)
        self.assertEqual(provider.positions, ["a"])
        self.assertEqual(result.status, "idle")

    def test_wrong_and_weak_receipts(self):
        for mode in ("wrong", "socket_sent"):
            result = run(self.ledger, Provider([Batch("a", [self.event])]), Sink(mode))
            self.assertEqual(result.status, "delivery_unconfirmed")
            self.assertIsNone(self.ledger.state()["cursor"])

    def test_invalid_page_not_delivered(self):
        for batch in (Batch(None, [self.event]), Batch("a", [self.event] * 2),
                      Batch("a", [], 1), Batch(None, [], True)):
            sink = Sink()
            self.assertEqual(run(self.ledger, Provider([batch]), sink).status,
                             "invalid_provider_page")
            self.assertEqual(sink.calls, [])

    def test_empty_poll_is_not_coverage(self):
        result = run(self.ledger, Provider([Batch(None, [])]), Sink())
        health = project(self.source, result, datetime.now(timezone.utc))
        self.assertEqual(health["coverage"], "unknown")
        self.assertEqual(health["state"], "no_events_observed")
        self.assertNotIn("credential_ref", health)

    def test_provider_error_is_redacted(self):
        result = run(self.ledger, Provider([]), Sink())
        self.assertEqual(result.status, "provider_error")
        self.assertFalse(result.pending)

    def test_provisioning_strict_and_revision_bound(self):
        for extra in ({"url": "https://example.com"}, {"tenant": "other"},
                      {"interval_seconds": True}, {"dataset": "unknown"}):
            with self.assertRaises(ContractError):
                provision("env", "instance", {**self.config, **extra})
        other = provision("other", "instance", self.config)
        self.assertNotEqual(other.revision, self.source.revision)
        self.assertNotIn("credential_ref", public_metadata(self.source))
        self.assertFalse(public_metadata(self.source)["activation_supported"])
        with self.assertRaises(ContractError):
            Ledger(self.path, other.ledger_scope())

    def test_budget_rejects_unbounded_values(self):
        for budget in (True, 0, 101):
            with self.assertRaises(ContractError):
                run(self.ledger, Provider([]), Sink(), budget)


if __name__ == "__main__":
    unittest.main()
