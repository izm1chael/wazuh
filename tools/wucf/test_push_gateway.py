import json
import tempfile
import unittest
from pathlib import Path

from delivery_inbox import DeliveryInbox
from enrollment import Enrollment
from ledger import ContractError, scope
from push_gateway import SignedPush, sign


class GatewayTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.scope = scope("env", "source", "audit", "a" * 64)
        self.inbox = DeliveryInbox(Path(temp.name) / "inbox.db", self.scope)
        self.addCleanup(self.inbox.close)
        self.enrollment = Enrollment(Path(temp.name) / "enrollment.db", self.scope)
        self.addCleanup(self.enrollment.close)
        self.key = b"k" * 32
        self.push = SignedPush(self.inbox, "relay", lambda *_: self.key, lambda: 1000)
        self.body = json.dumps([{"id": "event", "payload": {"message": "test"}}]).encode()
        self.nonce = "n" * 24

    def signature(self, body=None, epoch=1000, nonce=None, scope_value=None):
        return sign(self.key, scope_value or self.scope, "relay", epoch,
                    nonce or self.nonce, self.body if body is None else body)

    def test_signed_batch_and_retry(self):
        self.assertFalse(self.push.accept(1000, self.nonce, self.signature(), self.body).duplicate)
        self.assertTrue(self.push.accept(1000, self.nonce, self.signature(), self.body).duplicate)
        self.assertEqual(len(self.inbox.read()), 1)
        self.assertEqual(len(self.inbox.read()[0][2]), 1)
        self.assertEqual(self.inbox.read()[0][2][0]["payload"], {"message": "test"})
        with self.assertRaises(ContractError):
            self.push.accept(1000, self.nonce, self.signature(self.body + b" "), self.body + b" ")

    def test_cross_scope_stale_bad_signature_and_duplicate_json(self):
        for epoch, signature, body in (
                (1000, self.signature(scope_value={**self.scope, "environment": "other"}), self.body),
                (600, self.signature(epoch=600), self.body),
                (1000, "a" * 64, self.body),
                (1000, self.signature(b'[{"id":"x","id":"y","payload":{}}]'),
                 b'[{"id":"x","id":"y","payload":{}}]')):
            with self.assertRaises(ContractError):
                self.push.accept(epoch, self.nonce, signature, body)
        self.assertEqual(self.inbox.read(), [])

    def test_enrollment_one_time_certificate_bound_and_revocable(self):
        cert = "b" * 64
        token = self.enrollment.issue("relay", cert, 1000)
        with self.assertRaises(ContractError):
            self.enrollment.redeem("relay", token, "c" * 64, 1001)
        identity = self.enrollment.redeem("relay", token, cert, 1001)
        self.assertEqual(identity, self.enrollment.authorize("relay", cert, 1002))
        with self.assertRaises(ContractError):
            self.enrollment.redeem("relay", token, cert, 1002)
        self.enrollment.revoke("relay", 1003)
        with self.assertRaises(ContractError):
            self.enrollment.authorize("relay", cert, 1004)

    def test_expired_and_clock_regression_rejected(self):
        cert = "d" * 64
        token = self.enrollment.issue("expired", cert, 1000, ttl=30)
        with self.assertRaises(ContractError):
            self.enrollment.redeem("expired", token, cert, 1030)
        with self.assertRaises(ContractError):
            self.enrollment.redeem("expired", token, cert, 999)
