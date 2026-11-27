import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from execution_plan import bind_claim, prepare, register, validate
from ledger import ContractError, Ledger
from management import Management


def plan(**changes):
    return prepare(**{"environment": "env-a", "instance": "source-a", "dataset": "signins",
                     "provider_revision": "a" * 64, "credential_generation": "key-v1",
                     "content_revision": "b" * 64, "interval": 300, **changes})


class ExecutionPlanTests(unittest.TestCase):
    def test_revision_changes_with_all_dimensions(self):
        original = plan()
        for key, value in (("environment", "env-b"), ("instance", "source-b"),
                           ("dataset", "audit"), ("provider_revision", "c" * 64),
                           ("credential_generation", "key-v2"), ("content_revision", "d" * 64),
                           ("interval", 600)):
            self.assertNotEqual(original.revision, plan(**{key: value}).revision)
        self.assertEqual(original, plan())

    def test_forged_plan_rejected(self):
        for changed in (replace(plan(), boundary="native"), replace(plan(), revision="f" * 64),
                        replace(plan(), credential_generation="key-v2")):
            with self.assertRaises(ContractError):
                validate(changed)

    def test_management_and_ledger_binding(self):
        p = plan()
        with tempfile.TemporaryDirectory() as temp:
            db = Management(Path(temp) / "management.db", "env-a")
            self.addCleanup(db.close)
            register(db, p, "operator", 100)
            db.change(p.instance, p.dataset, 0, "admit_lab", "operator", 100, "c" * 64)
            claim = db.claim("worker", 100)
            ledger = Ledger(Path(temp) / "ledger.db", p.ledger_scope())
            self.addCleanup(ledger.close)
            spool = SimpleNamespace(scope=p.ledger_scope())
            self.assertEqual(bind_claim(p, claim, ledger, spool), p.ledger_scope())
            for changed in ({**claim, "environment": "env-b"}, {**claim, "boundary": "native"},
                            {**claim, "revision": "d" * 64}, {**claim, "lease": "bad"},
                            {**claim, "state": "paused"}):
                with self.assertRaises(ContractError):
                    bind_claim(p, changed, ledger, spool)
            with self.assertRaises(ContractError):
                bind_claim(p, claim, ledger, SimpleNamespace(scope=plan(credential_generation="key-v2").ledger_scope()))
            with self.assertRaises(ContractError):
                register(db, plan(environment="env-b"), "operator", 100)
            with self.assertRaises(ContractError):
                Ledger(Path(temp) / "ledger.db", plan(content_revision="e" * 64).ledger_scope())


if __name__ == "__main__":
    unittest.main()
