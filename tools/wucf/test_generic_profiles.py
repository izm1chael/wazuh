import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from delivery_inbox import DeliveryInbox
from generic_profiles import ApprovedREST, ImmutableJsonObjects, RestProfile
from ledger import ContractError, scope
from syslog_relay import prepare_lines


class GenericTests(unittest.TestCase):
    def test_profile_allowlist_and_scope(self):
        profile = RestProfile("approved", "api.example.test", "/v1/audit",
                              "items", "id", "account", "time", "next",
                              "from_time", "to_time", "account_id", "token", "limit")
        now = lambda: datetime(2026, 1, 1, 1, 10, tzinfo=timezone.utc)
        initial = "2026-01-01T00:00:00Z"
        class Transport:
            def get(self, url, **kwargs):
                return json.dumps({"items": [{"id": "e", "account": "acct", "time": initial}]}).encode()
        with self.assertRaises(ContractError):
            ApprovedREST(profile, frozenset(), "acct", initial, Transport(), now)
        provider = ApprovedREST(profile, frozenset({profile.revision()}), "acct", initial, Transport(), now)
        self.assertEqual(provider.fetch(None).events[0]["payload"]["id"], "e")
        provider = ApprovedREST(profile, frozenset({profile.revision()}), "other", initial, Transport(), now)
        with self.assertRaises(ContractError):
            provider.fetch(None)

    def test_immutable_object_retry(self):
        with tempfile.TemporaryDirectory() as temp:
            inbox = DeliveryInbox(Path(temp) / "inbox.db", scope("env", "source", "audit", "a" * 64))
            self.addCleanup(inbox.close)
            class Client:
                def get_version(self, *args, **kwargs):
                    return b'[{"id":"e","account":"acct"}]'
            provider = ImmutableJsonObjects("namespace", "logs/", "acct", Client(), inbox)
            self.assertFalse(provider.collect("logs/a.json", "v1").duplicate)
            self.assertTrue(provider.collect("logs/a.json", "v1").duplicate)
            for key, version in (("other/a.json", "v1"), ("logs/../a.json", "v1"), ("logs/a.json", "latest")):
                with self.assertRaises(ContractError):
                    provider.collect(key, version)

    def test_relay_sequence_stable_and_raw(self):
        body = prepare_lines("stream", 0, [b"<34>1 message"])
        self.assertEqual(body, prepare_lines("stream", 0, [b"<34>1 message"]))
        self.assertEqual(json.loads(body)[0]["payload"], {"raw_syslog": "<34>1 message"})
        self.assertNotEqual(body, prepare_lines("stream", 1, [b"<34>1 message"]))
        for line in (b"<192>bad", b"no-pri", b"<1>x\ny", b"<1>\xff"):
            with self.assertRaises(ContractError):
                prepare_lines("stream", 0, [line])
