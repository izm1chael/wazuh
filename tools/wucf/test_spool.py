import tempfile
import unittest
from pathlib import Path

from ledger import ContractError, Ledger, page, scope
from runtime import Batch, run
from spool import LocalSpool


class Provider:
    def fetch(self, _):
        return Batch("next", [{"id": "e", "payload": {"test": True}}])


class SpoolTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "spool.db"
        self.scope = scope("env", "source", "signins", "a" * 64)
        self.spool = LocalSpool(self.path, self.scope, max_pages=1)
        self.addCleanup(lambda: self.spool.close())
        self.ledger = Ledger(Path(temp.name) / "checkpoint.db", self.scope)
        self.addCleanup(self.ledger.close)

    def pending(self, following="next"):
        self.ledger.stage(0, None, following, [{"id": "e", "payload": {"test": True}}])
        state = self.ledger.state()
        return state["pending_id"], state["pending"]

    def test_local_receipt_survives_restart_and_replay(self):
        pid, body = self.pending()
        receipt = self.spool.deliver(pid, body)
        self.assertEqual(receipt.durability, "durable")
        self.spool.close()
        self.spool = LocalSpool(self.path, self.scope, max_pages=1)
        self.assertEqual(self.spool.deliver(pid, body), receipt)
        self.assertEqual(self.spool.read(), [(pid, body)])
        self.assertIsNone(self.ledger.state()["cursor"])
        self.ledger.acknowledge(pid, receipt.durability)
        self.assertEqual(self.ledger.state()["cursor"], "next")

    def test_runtime_retains_raw_page_in_local_spool(self):
        result = run(self.ledger, Provider(), self.spool)
        self.assertEqual(result.status, "complete")
        self.assertEqual(len(self.spool.read()), 1)

    def test_quota_blocks_second_page_without_cursor_advance(self):
        result = run(self.ledger, Provider(), self.spool)
        self.assertEqual(result.status, "complete")
        self.ledger.stage(1, "next", "later", [])
        result = run(self.ledger, Provider(), self.spool)
        self.assertEqual(result.status, "delivery_unknown")
        self.assertEqual(self.ledger.state()["cursor"], "next")
        self.assertEqual(len(self.spool.read()), 1)

    def test_digest_and_scope_rejected(self):
        pid, body = self.pending()
        for bad_id, bad_body in (("b" * 64, body),
                                 (pid, {**body, "scope": {**self.scope, "environment": "other"}})):
            with self.assertRaises(ContractError):
                self.spool.deliver(bad_id, bad_body)
        with self.assertRaises(ContractError):
            LocalSpool(self.path, {**self.scope, "environment": "other"})

    def test_conflicting_generation_rejected(self):
        pid, body = self.pending()
        self.spool.deliver(pid, body)
        changed = {**body, "following": "different"}
        new_id, _ = page(self.scope, 0, None, "different", body["events"])
        with self.assertRaises(ContractError):
            self.spool.deliver(new_id, changed)


if __name__ == "__main__":
    unittest.main()
