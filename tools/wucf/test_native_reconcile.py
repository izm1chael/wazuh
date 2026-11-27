import tempfile
import unittest
from pathlib import Path

from delivery_inbox import DeliveryInbox
from ledger import ContractError, canonical, digest, scope
from native_reconcile import Observation, Reconciliation


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.scope = scope("env", "source", "audit", "a" * 64)
        self.inbox = DeliveryInbox(Path(temp.name) / "inbox.db", self.scope)
        self.addCleanup(self.inbox.close)
        self.recon = Reconciliation(Path(temp.name) / "reconcile.db", self.scope)
        self.addCleanup(self.recon.close)
        self.events = [{"id": "e1", "payload": {"x": 1}}, {"id": "e2", "payload": {"x": 2}}]
        self.inbox.accept("delivery", self.events)

    def observation(self, index, outcome, evidence):
        event = self.events[index]
        return Observation(event["id"], digest(canonical(event["payload"])), outcome, evidence)

    def test_unknown_then_partial_and_conservation(self):
        self.assertEqual(self.recon.summary(self.inbox, 1)["unknown"], 2)
        row = self.observation(0, "native_confirmed", "evidence")
        self.recon.record(self.inbox, 1, [row])
        self.recon.record(self.inbox, 1, [row])
        result = self.recon.summary(self.inbox, 1)
        self.assertEqual(result["reported_native_confirmed"], 1)
        self.assertEqual(result["unknown"], 1)
        self.assertFalse(result["native_delivery_qualified"])
        self.assertFalse(result["deletion_supported"])
        self.assertEqual(self.inbox.read()[0][2], self.events)

    def test_wrong_payload_scope_and_conflicting_evidence(self):
        with self.assertRaises(ContractError):
            self.recon.record(self.inbox, 1, [Observation("e1", "f" * 64, "native_confirmed", "proof")])
        row = self.observation(0, "native_confirmed", "proof")
        self.recon.record(self.inbox, 1, [row])
        with self.assertRaises(ContractError):
            self.recon.record(self.inbox, 1, [self.observation(0, "native_rejected", "other")])
        self.assertEqual(self.recon.summary(self.inbox, 1)["reported_native_rejected"], 0)

    def test_unknown_cannot_claim_proof(self):
        with self.assertRaises(ContractError):
            self.recon.record(self.inbox, 1, [self.observation(0, "unknown", "proof")])
        self.recon.record(self.inbox, 1, [self.observation(0, "unknown", None)])
        self.assertEqual(self.recon.summary(self.inbox, 1)["unknown"], 2)
