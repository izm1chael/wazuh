import json
import unittest
from datetime import datetime, timezone

from graph import GraphProvider, approved_url, position, stamp
from ledger import ContractError
from retry import retry

START = "2026-01-01T00:00:00Z"
NOW = datetime(2026, 1, 1, 1, 10, tzinfo=timezone.utc)
PATH = "/v1.0/auditLogs/signIns"
URL = "https://graph.microsoft.com" + PATH + "?%24skiptoken=abc"


class Transport:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.urls = []

    def get(self, url, **bounds):
        self.urls.append((url, bounds))
        return json.dumps(next(self.responses)).encode()


class GraphTests(unittest.TestCase):
    def provider(self, responses):
        transport = Transport(responses)
        return GraphProvider("signins", START, transport, lambda: NOW), transport

    def test_closed_window_and_page_resume(self):
        item = {"id": "provider-id", "createdDateTime": START, "other": {"x": 1}}
        graph, transport = self.provider([{"value": [item], "@odata.nextLink": URL},
                                          {"value": []}])
        first = graph.fetch(None)
        self.assertTrue(first.more)
        self.assertEqual(first.events[0]["payload"], item)
        second = graph.fetch(first.following)
        self.assertEqual(transport.urls[1][0], URL)
        self.assertFalse(second.more)
        self.assertEqual(second.following, position(stamp("2026-01-01T01:00:00Z")))
        self.assertEqual(graph.fetch(second.following).following, second.following)

    def test_endpoint_and_redirect_like_urls_rejected(self):
        for url in ("http://graph.microsoft.com" + PATH + "?x=1",
                    "https://graph.microsoft.com.evil.test" + PATH + "?x=1",
                    "https://user@graph.microsoft.com" + PATH + "?x=1",
                    "https://graph.microsoft.com:443" + PATH + "?x=1",
                    "https://graph.microsoft.com/v1.0/users?x=1",
                    URL + "#fragment", URL + "\\x", URL + "\n"):
            with self.assertRaises(ContractError):
                approved_url(url, PATH)

    def test_unapproved_continuation_rejected(self):
        graph, _ = self.provider([{"value": [], "@odata.nextLink": "https://evil.test/?x=1"}])
        with self.assertRaises(ContractError):
            graph.fetch(None)

    def test_boundary_and_missing_identity_rejected(self):
        for item in ({"id": "e", "createdDateTime": "2026-01-01T01:00:00Z"},
                     {"createdDateTime": START}, {"id": "e", "createdDateTime": "bad"}):
            graph, _ = self.provider([{"value": [item]}])
            with self.assertRaises(ContractError):
                graph.fetch(None)

    def test_persistent_window_page_budget(self):
        from graph import MAX_WINDOW_PAGES
        graph, transport = self.provider([])
        current = position(stamp(START), stamp("2026-01-01T01:00:00Z"), URL, MAX_WINDOW_PAGES)
        with self.assertRaises(ContractError):
            graph.fetch(current)
        self.assertEqual(transport.urls, [])

    def test_retry_policy(self):
        self.assertEqual(retry(429, 1, NOW, "120").delay_seconds, 120)
        self.assertEqual(retry(503, 3, NOW).delay_seconds, 8)
        self.assertEqual(retry(401, 1, NOW).disposition, "credential_or_permission_review")
        self.assertEqual(retry(429, 9, NOW).disposition, "retry_budget_exhausted")
        self.assertEqual(retry(429, 1, NOW, "999999").disposition, "operator_deferred")
        self.assertEqual(retry(429, 1, NOW, "bad").disposition, "invalid_retry_after")


if __name__ == "__main__":
    unittest.main()
