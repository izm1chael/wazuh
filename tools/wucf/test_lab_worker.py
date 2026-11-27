import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from execution_plan import prepare, register
from lab_worker import run_claimed
from ledger import ContractError, Ledger
from management import Management
from runtime import Batch
from spool import LocalSpool


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.plan = prepare("env-a", "source-a", "signins", "a"*64, "key-v1", "b"*64, 300)
        self.m = Management(base / "management.db", "env-a")
        self.addCleanup(self.m.close)
        self.ledger = Ledger(base / "ledger.db", self.plan.ledger_scope())
        self.addCleanup(self.ledger.close)
        self.spool = LocalSpool(base / "spool.db", self.plan.ledger_scope(), max_pages=1)
        self.addCleanup(self.spool.close)
        register(self.m, self.plan, "operator", 100)
        self.m.change("source-a", "signins", 0, "admit_lab", "operator", 100, "c"*64)
        self.claim = self.m.claim("worker", 100, 30)
        self.now = 101
        self.provider = Mock()
        self.factory = Mock(return_value=self.provider)
        self.event = {"id": "event-1", "payload": {"test": True}}

    def run_job(self):
        return run_claimed(self.m, self.plan, self.claim, "worker", lambda: self.now,
                           self.ledger, self.spool, self.factory)

    def test_actual_spool_and_ledger_advance_and_schedule(self):
        self.provider.fetch.return_value = Batch("next", [self.event])
        result = self.run_job()
        self.assertEqual((result.status, result.boundary, result.acknowledged_events), ("complete", "local_spool", 1))
        self.assertEqual(self.ledger.state()["cursor"], "next")
        self.assertEqual(self.spool.read()[0][1]["events"], [self.event])
        self.assertEqual(self.m.get("source-a", "signins")["due"], 401)
        self.factory.assert_called_once_with(self.plan)

    def test_spool_quota_leaves_pending_and_requires_review(self):
        self.provider.fetch.side_effect = [Batch("next", [self.event], True), Batch("later", [{"id": "event-2", "payload": {}}])]
        result = self.run_job()
        self.assertEqual(result.status, "delivery_unknown")
        self.assertEqual(self.ledger.state()["cursor"], "next")
        self.assertEqual(self.ledger.state()["pending"]["following"], "later")
        self.assertEqual(self.m.get("source-a", "signins")["state"], "review")

    def test_expired_before_provider_construction(self):
        self.now = 130
        with self.assertRaises(ContractError):
            self.run_job()
        self.factory.assert_not_called()
        self.assertEqual(self.spool.read(), [])
        self.assertIsNone(self.m.claim("other", 130))

    def test_expired_during_provider_leaves_claim_intact(self):
        def fetch(_):
            self.now = 130
            return Batch("next", [self.event])
        self.provider.fetch.side_effect = fetch
        with self.assertRaises(ContractError):
            self.run_job()
        self.assertEqual(self.spool.read(), [])
        self.assertIsNone(self.ledger.state()["cursor"])
        self.assertIsNone(self.m.claim("other", 130))

    def test_stale_claim_cannot_poll_twice(self):
        self.provider.fetch.return_value = Batch(None, [])
        self.assertEqual(self.run_job().status, "idle")
        with self.assertRaises(ContractError):
            self.run_job()
        self.factory.assert_called_once()


if __name__ == "__main__":
    unittest.main()
