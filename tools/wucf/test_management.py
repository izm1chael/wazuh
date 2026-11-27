import tempfile
import unittest
from pathlib import Path

from ledger import ContractError
from management import Management

REV = "a" * 64
EVIDENCE = "b" * 64


class ManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "management.db"
        self.m = Management(self.path, "env-a")
        self.addCleanup(self.close)

    def close(self):
        if self.m:
            self.m.close()
            self.m = None

    def register(self, instance="source-a", now=100):
        return self.m.register(instance, "signins", REV, 300, "operator", now)

    def admit(self, instance="source-a", now=100):
        self.register(instance, now)
        return self.m.change(instance, "signins", 0, "admit_lab", "operator", now, EVIDENCE)

    def test_default_draft_no_claim_and_version_checked_admission(self):
        self.assertEqual(self.register()["state"], "draft")
        self.assertIsNone(self.m.claim("worker", 100))
        with self.assertRaises(ContractError):
            self.m.change("source-a", "signins", 1, "admit_lab", "operator", 100, EVIDENCE)
        with self.assertRaises(ContractError):
            self.m.change("source-a", "signins", 0, "admit_lab", "operator", 100, "bad")
        ready = self.m.change("source-a", "signins", 0, "admit_lab", "operator", 100, EVIDENCE)
        self.assertEqual(ready["state"], "ready")
        self.assertEqual(ready["version"], 1)

    def test_persistent_single_claim_and_fairness(self):
        self.admit("a")
        self.admit("b")
        job = self.m.claim("worker", 100)
        self.assertEqual(job["instance"], "a")
        self.close()
        self.m = Management(self.path, "env-a")
        self.assertIsNone(self.m.claim("other", 101))
        result = self.m.finish("a", "signins", job["lease"], "worker", 102, "complete", "local_spool")
        self.assertEqual(result["due"], 402)
        self.assertEqual(self.m.claim("other", 102)["instance"], "b")

    def test_claim_token_actor_boundary_and_lifecycle(self):
        self.admit()
        job = self.m.claim("worker", 100)
        for token, actor, boundary in (("c"*64, "worker", "local_spool"), (job["lease"], "other", "local_spool"), (job["lease"], "worker", "native")):
            with self.assertRaises(ContractError):
                self.m.finish("source-a", "signins", token, actor, 101, "idle", boundary)
        with self.assertRaises(ContractError):
            self.m.change("source-a", "signins", job["version"], "pause", "operator", 101)
        self.assertNotIn("lease", self.m.get("source-a", "signins"))
        self.m.finish("source-a", "signins", job["lease"], "worker", 102, "idle", "local_spool")
        with self.assertRaises(ContractError):
            self.m.finish("source-a", "signins", job["lease"], "worker", 102, "idle", "local_spool")

    def test_expiry_blocks_until_attested_recovery(self):
        self.admit()
        job = self.m.claim("worker", 100, 30)
        self.assertIsNone(self.m.claim("other", 130))
        with self.assertRaises(ContractError):
            self.m.finish("source-a", "signins", job["lease"], "worker", 130, "idle", "local_spool")
        review = self.m.recover_expired("source-a", "signins", job["version"], "operator", 131, EVIDENCE)
        self.assertEqual(review["state"], "review")
        self.assertIsNone(self.m.claim("other", 131))
        paused = self.m.change("source-a", "signins", review["version"], "reconcile", "operator", 132, EVIDENCE)
        self.m.change("source-a", "signins", paused["version"], "resume_lab", "operator", 133)
        self.assertNotEqual(self.m.claim("worker", 133)["lease"], job["lease"])

    def test_error_requires_review_no_automatic_retry(self):
        self.admit()
        job = self.m.claim("worker", 100)
        result = self.m.finish("source-a", "signins", job["lease"], "worker", 101, "provider_error", "local_spool")
        self.assertEqual(result["state"], "review")
        self.assertIsNone(self.m.claim("worker", 1000))
        with self.assertRaises(ContractError):
            self.m.change("source-a", "signins", result["version"], "resume_lab", "operator", 1000)

    def test_revocation_terminal_and_environment_binding(self):
        self.admit()
        revoked = self.m.change("source-a", "signins", 1, "revoke", "operator", 101)
        self.assertEqual(revoked["state"], "revoked")
        with self.assertRaises(ContractError):
            self.m.change("source-a", "signins", revoked["version"], "resume_lab", "operator", 102)
        with self.assertRaises(ContractError):
            Management(self.path, "env-b")
        with self.assertRaises(ContractError):
            self.register(now=103)

    def test_budget_exhausted_and_clock_regression(self):
        self.admit()
        job = self.m.claim("worker", 100)
        result = self.m.finish("source-a", "signins", job["lease"], "worker", 101, "budget_exhausted", "local_spool")
        self.assertEqual(result["due"], 161)
        with self.assertRaises(ContractError):
            self.m.claim("worker", 100)
        self.assertIsNone(self.m.claim("worker", 160))
        self.assertIsNotNone(self.m.claim("worker", 161))

    def test_two_connections_and_audit_rollback(self):
        self.admit()
        other = Management(self.path, "env-a")
        self.addCleanup(other.close)
        self.m.claim("worker", 100)
        self.assertIsNone(other.claim("worker", 100))
        with self.assertRaises(ContractError):
            self.m.register("b", "signins", REV, 300, "bad actor", 100)
        with self.assertRaises(ContractError):
            other.get("b", "signins")


if __name__ == "__main__":
    unittest.main()
