import json
import unittest
from datetime import datetime, timezone

from ledger import ContractError
from windowed_packs import AzureActivity, GoogleWorkspace, position
from graph import stamp

START = "2026-01-01T00:00:00Z"
END = "2026-01-01T01:00:00Z"
NOW = datetime(2026, 1, 1, 1, 10, tzinfo=timezone.utc)
SUB = "00000000-1111-2222-3333-444444444444"
CUSTOMER = "C0123"


class Transport:
    def __init__(self, *responses):
        self.responses = iter(responses)
        self.calls = []

    def get(self, url, **bounds):
        self.calls.append((url, bounds))
        return json.dumps(next(self.responses)).encode()


class PacksTests(unittest.TestCase):
    def test_azure_page_and_resume(self):
        path = f"/subscriptions/{SUB}/providers/microsoft.insights/eventtypes/management/values"
        next_url = f"https://management.azure.com{path}?token=1"
        event = {"eventDataId": "event", "subscriptionId": SUB, "eventTimestamp": START}
        transport = Transport({"value": [event], "nextLink": next_url}, {"value": []})
        provider = AzureActivity(SUB, START, transport, lambda: NOW)
        first = provider.fetch(None)
        self.assertTrue(first.more)
        self.assertEqual(first.events[0]["payload"], event)
        final = provider.fetch(first.following)
        self.assertEqual(transport.calls[1][0], next_url)
        self.assertEqual(final.following, position(stamp(END)))
        self.assertFalse(final.more)

    def test_azure_scope_and_continuation(self):
        for response in ({"value": [], "nextLink": "https://evil.test/?x=1"},
                         {"value": [{"eventDataId": "e", "subscriptionId": "other", "eventTimestamp": START}]}):
            provider = AzureActivity(SUB, START, Transport(response), lambda: NOW)
            with self.assertRaises(ContractError):
                provider.fetch(None)

    def test_google_stable_token_and_event(self):
        item = {"id": {"customerId": CUSTOMER, "applicationName": "login",
                       "time": END, "uniqueQualifier": "-123"}, "events": [{"name": "login_success"}]}
        transport = Transport({"kind": "reports#activities", "items": [item], "nextPageToken": "abc+/"},
                              {"kind": "reports#activities", "items": [item]})
        provider = GoogleWorkspace(CUSTOMER, "login", START, transport, lambda: NOW)
        first = provider.fetch(None)
        final = provider.fetch(first.following)
        self.assertEqual(first.events, final.events)
        self.assertIn("pageToken=abc%2B%2F", transport.calls[1][0])
        self.assertFalse(final.more)

    def test_google_scope_and_unknown_response(self):
        for response in ({}, {"kind": "reports#activities", "items": [{"id": {"customerId": "other"}}]}):
            provider = GoogleWorkspace(CUSTOMER, "login", START, Transport(response), lambda: NOW)
            with self.assertRaises(ContractError):
                provider.fetch(None)

    def test_empty_horizon_does_not_call_transport(self):
        transport = Transport()
        provider = GoogleWorkspace(CUSTOMER, "admin", END, transport, lambda: NOW)
        self.assertEqual(provider.fetch(None).following, None)
        self.assertEqual(transport.calls, [])
