import tempfile
import unittest
from pathlib import Path

from ledger import ContractError, Ledger, scope


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "ledger.db"
        self.scope = scope("env-a", "connector-a", "signins", "a" * 64)
        self.ledger = Ledger(self.path, self.scope)
        self.addCleanup(self.close)
        self.events = [{"id": "event-1", "payload": {"result": "success"}}]

    def close(self):
        if self.ledger is not None:
            self.ledger.close()
            self.ledger = None

    def reopen(self):
        self.close()
        self.ledger = Ledger(self.path, self.scope)

    def stage(self):
        return self.ledger.stage(0, None, "position-1", self.events)

    def test_restart_retains_pending_and_advances_only_after_ack(self):
        pid = self.stage()
        self.reopen()
        self.assertEqual(self.ledger.state()["pending_id"], pid)
        self.assertIsNone(self.ledger.state()["cursor"])
        self.assertEqual(self.stage(), pid)
        self.assertEqual(self.ledger.acknowledge(pid, "durable"), 1)
        self.reopen()
        self.assertEqual(self.ledger.state()["cursor"], "position-1")
        self.assertIsNone(self.ledger.state()["pending"])
        self.assertEqual(self.ledger.acknowledge(pid, "durable"), 1)

    def test_wrong_ack_and_socket_send_do_not_advance(self):
        pid = self.stage()
        for bad, level in [(pid, "socket_sent"), ("b" * 64, "durable")]:
            with self.assertRaises(ContractError):
                self.ledger.acknowledge(bad, level)
        self.assertEqual(self.ledger.state()["generation"], 0)
        self.assertEqual(self.ledger.state()["pending_id"], pid)

    def test_conflicting_page_and_stale_checkpoint(self):
        pid = self.stage()
        with self.assertRaises(ContractError):
            self.ledger.stage(0, None, "position-2", self.events)
        self.ledger.acknowledge(pid, "durable")
        with self.assertRaises(ContractError):
            self.stage()

    def test_cross_scope_and_revision_fail_closed(self):
        for other in (scope("env-b", "connector-a", "signins", "a" * 64),
                      scope("env-a", "connector-a", "signins", "b" * 64)):
            with self.assertRaises(ContractError):
                Ledger(self.path, other)

    def test_empty_page_requires_new_position(self):
        pid = self.ledger.stage(0, None, "position-1", [])
        self.ledger.acknowledge(pid, "durable")
        with self.assertRaises(ContractError):
            self.ledger.stage(1, "position-1", "position-1", [])

    def test_invalid_payloads_and_duplicate_ids(self):
        for events in ([self.events[0]] * 2, [{"id": "x", "payload": {"v": float("nan")}}],
                       [{"id": "x", "payload": {"v": "x" * 65536}}],
                       [{"id": "x", "payload": []}], [{"id": "x", "payload": {}, "secret": "x"}]):
            with self.assertRaises(ContractError):
                self.ledger.stage(0, None, "position-1", events)
        self.assertIsNone(self.ledger.state()["pending"])

    def test_invalid_cursor_and_generation(self):
        for next_cursor in ("", None, "x" * 4097, chr(0xd800)):
            with self.assertRaises(ContractError):
                self.ledger.stage(0, None, next_cursor, self.events)
        with self.assertRaises(ContractError):
            self.ledger.stage(True, None, "position-1", self.events)

    def test_pending_tampering_detected(self):
        self.stage()
        with self.ledger.db:
            self.ledger.db.execute("UPDATE checkpoint SET pending_body=? WHERE singleton=1",
                                   (b"{}",))
        with self.assertRaises(ContractError):
            self.ledger.state()

    def test_two_connections_cannot_replace_pending(self):
        other = Ledger(self.path, self.scope)
        self.addCleanup(other.close)
        pid = self.stage()
        self.assertEqual(other.stage(0, None, "position-1", self.events), pid)
        with self.assertRaises(ContractError):
            other.stage(0, None, "position-2", self.events)
        other.acknowledge(pid, "durable")
        self.assertEqual(self.ledger.state()["generation"], 1)


if __name__ == "__main__":
    unittest.main()
