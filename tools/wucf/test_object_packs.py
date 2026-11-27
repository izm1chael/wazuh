import gzip
import json
import tempfile
import unittest
from pathlib import Path

from delivery_inbox import DeliveryInbox
from ledger import ContractError, scope
from object_packs import CloudTrailQueue, Microsoft365Feed

TENANT = "00000000-1111-2222-3333-444444444444"
ACCOUNT = "123456789012"
START = "2026-01-01T00:00:00Z"
END = "2026-01-01T01:00:00Z"


def raw(obj):
    return json.dumps(obj).encode()


class InboxTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "inbox.db"
        self.scope = scope("env", "source", "audit", "a" * 64)
        self.inbox = DeliveryInbox(self.path, self.scope)
        self.addCleanup(lambda: self.inbox.close())

    def test_retry_restart_and_conflict(self):
        event = [{"id": "event", "payload": {"a": 1}}]
        self.assertFalse(self.inbox.accept("unit", event).duplicate)
        self.inbox.close()
        self.inbox = DeliveryInbox(self.path, self.scope)
        self.assertTrue(self.inbox.accept("unit", event).duplicate)
        self.assertEqual(self.inbox.read()[0][2], event)
        with self.assertRaises(ContractError):
            self.inbox.accept("unit", [{"id": "event", "payload": {"a": 2}}])
        with self.assertRaises(ContractError):
            DeliveryInbox(self.path, {**self.scope, "environment": "other"})

    def test_m365_content_retry_and_tenant_validation(self):
        class Client:
            def list_content(self, url, **kwargs):
                return raw([{"contentId": "blob", "contentType": "Audit.General",
                             "contentCreated": START,
                             "contentUri": f"https://manage.office.com/api/v1.0/{TENANT}/activity/feed/audit/blob"}]), None

            def get(self, url, **kwargs):
                return raw([{"Id": "e", "OrganizationId": TENANT}])
        provider = Microsoft365Feed(TENANT, TENANT, "Audit.General", Client(), self.inbox)
        following, receipts = provider.step(START, END)
        self.assertIsNone(following)
        self.assertFalse(receipts[0].duplicate)
        self.assertTrue(provider.step(START, END)[1][0].duplicate)
        with self.assertRaises(ContractError):
            provider.content_url("https://evil.test/audit/blob", "blob")
        with self.assertRaises(ContractError):
            provider.content_url(f"https://manage.office.com/api/v1.0/{TENANT}/activity/feed/audit/other", "blob")

    def test_m365_continuation_keeps_window_and_content_type(self):
        from graph import stamp
        from urllib.parse import urlencode
        provider = Microsoft365Feed(TENANT, TENANT, "Audit.General", object(), self.inbox)
        query = {"contentType": "Audit.General", "startTime": START, "endTime": END, "nextPage": "opaque"}
        url = f"https://manage.office.com/api/v1/{TENANT}/activity/feed/subscriptions/content?"
        self.assertIn("PublisherIdentifier=", provider.list_continuation(url + urlencode(query), stamp(START), stamp(END)))
        for changed in ({"contentType": "Audit.Exchange"}, {"endTime": START}, {"PublisherIdentifier": "other"}):
            with self.assertRaises(ContractError):
                provider.list_continuation(url + urlencode({**query, **changed}), stamp(START), stamp(END))

    def test_queue_delete_only_after_local_durability(self):
        class Objects:
            def get_version(self, bucket, key, version, **kwargs):
                return gzip.compress(raw({"Records": [{"eventID": "e", "recipientAccountId": ACCOUNT}]}))
        class Queue:
            def __init__(self):
                self.calls = []
            def delete(self, handle):
                self.calls.append(handle)
        queue = Queue()
        provider = CloudTrailQueue("audit-bucket", "AWSLogs/", [ACCOUNT], Objects(), queue, self.inbox)
        item = {"eventSource": "aws:s3", "eventName": "ObjectCreated:Put",
                "s3": {"bucket": {"name": "audit-bucket"},
                       "object": {"key": "AWSLogs%2Ftest.json.gz", "versionId": "v1"}}}
        note = raw({"Records": [item]})
        self.assertFalse(provider.process(note, "receipt")[0].duplicate)
        self.assertTrue(provider.process(note, "retry")[0].duplicate)
        self.assertEqual(queue.calls, ["receipt", "retry"])
        item["s3"]["object"]["versionId"] = "null"
        with self.assertRaises(ContractError):
            provider.process(raw({"Records": [item]}), "invalid")
        self.assertEqual(queue.calls, ["receipt", "retry"])

    def test_queue_quota_does_not_ack(self):
        class Objects:
            def get_version(self, *args, **kwargs):
                return gzip.compress(raw({"Records": [{"eventID": "e", "recipientAccountId": ACCOUNT}]}))
        class Queue:
            def delete(self, handle):
                raise AssertionError("must not delete")
        self.inbox.max_units = 1
        self.inbox.accept("existing", [])
        provider = CloudTrailQueue("audit-bucket", "AWSLogs/", [ACCOUNT], Objects(), Queue(), self.inbox)
        item = {"eventSource": "aws:s3", "eventName": "ObjectCreated:Put",
                "s3": {"bucket": {"name": "audit-bucket"},
                       "object": {"key": "AWSLogs/test.json.gz", "versionId": "v1"}}}
        with self.assertRaises(ContractError):
            provider.process(raw({"Records": [item]}), "receipt")
