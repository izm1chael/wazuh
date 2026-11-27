"""Offline transport contracts. No live DNS, network, or real credentials."""
import json
import socket
import unittest
from unittest.mock import patch

from graph import HOST
from ledger import ContractError
from microsoft_transport import LOGIN, MicrosoftTransport, TransportError, public_ip, request

TENANT = "11111111-1111-1111-1111-111111111111"
CLIENT = "22222222-2222-2222-2222-222222222222"
URL = "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=100"


def answers(*ips):
    return lambda *a, **kw: [(socket.AF_INET6 if ":" in ip else socket.AF_INET,
                              socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in ips]


class TransportTests(unittest.TestCase):
    def test_dns_all_answers_must_be_public(self):
        self.assertEqual(public_ip(HOST, answers("8.8.8.8")), "8.8.8.8")
        for ip in ("127.0.0.1", "169.254.169.254", "10.0.0.1", "::1",
                   "::ffff:8.8.8.8", "224.0.0.1", "100.64.0.1", "192.0.2.1"):
            with self.subTest(ip=ip), self.assertRaises(TransportError):
                public_ip(HOST, answers("8.8.8.8", ip))
        with self.assertRaises(TransportError):
            public_ip("example.org", answers("8.8.8.8"))

    def test_fixed_oauth_and_graph_hosts(self):
        calls = []
        def http(*args):
            calls.append(args)
            if args[0] == LOGIN:
                return b'{"access_token":"token-value","token_type":"Bearer"}'
            return b'{"value":[]}'
        transport = MicrosoftTransport(TENANT, CLIENT, lambda: "dummy-secret", http)
        self.assertEqual(transport.get(URL, 1024, 15), b'{"value":[]}')
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][:3], (LOGIN, "POST", f"/{TENANT}/oauth2/v2.0/token"))
        self.assertIn(b"grant_type=client_credentials", calls[0][4])
        self.assertIn(b"client_secret=dummy-secret", calls[0][4])
        self.assertEqual(calls[1][:3], (HOST, "GET", "/v1.0/auditLogs/signIns?$top=100"))
        self.assertEqual(calls[1][3]["Authorization"], "Bearer token-value")
        self.assertIsNone(calls[1][4])
        self.assertNotIn("dummy-secret", repr(calls[1]))

    def test_url_rejection_precedes_secret_resolution(self):
        def forbidden():
            self.fail("resolver must not be reached")
        transport = MicrosoftTransport(TENANT, CLIENT, forbidden)
        for url in ("http://graph.microsoft.com/v1.0/auditLogs/signIns?q=1",
                    "https://graph.microsoft.com.evil.test/v1.0/auditLogs/signIns?q=1",
                    "https://graph.microsoft.com@evil.test/v1.0/auditLogs/signIns?q=1",
                    "https://graph.microsoft.com/v1.0/users?q=1",
                    URL + "#fragment", URL + "\\", URL + "\n"):
            with self.subTest(url=url), self.assertRaises(ContractError):
                transport.get(url, 1024, 15)

    def test_token_rejection_is_redacted(self):
        for token in ("bad\r\nAuthorization: evil", "", "x" * 16385):
            def http(*args):
                return json.dumps({"access_token": token, "token_type":"Bearer"}).encode()
            transport = MicrosoftTransport(TENANT, CLIENT, lambda: "dummy-secret", http)
            with self.assertRaisesRegex(TransportError, "^invalid_token_response$"):
                transport.get(URL, 1024, 15)
        def failure():
            raise RuntimeError("dummy-secret")
        with self.assertRaisesRegex(TransportError, "^credential_unavailable$"):
            MicrosoftTransport(TENANT, CLIENT, failure).get(URL, 1024, 15)

    @patch("microsoft_transport.PinnedHTTPS")
    @patch("microsoft_transport.public_ip", return_value="8.8.8.8")
    def test_redirect_rejected_without_following(self, resolve, connection):
        conn = connection.return_value
        response = conn.getresponse.return_value
        response.status = 302
        response.getheader.return_value = None
        with self.assertRaises(TransportError) as caught:
            request(HOST, "GET", "/v1.0/auditLogs/signIns?q=1", {}, None, 1024, 15)
        self.assertEqual(caught.exception.status, 302)
        conn.request.assert_called_once()
        response.read.assert_not_called()
        conn.close.assert_called_once()

    @patch("microsoft_transport.PinnedHTTPS")
    @patch("microsoft_transport.public_ip", return_value="8.8.8.8")
    def test_bounded_read_and_retry_after(self, resolve, connection):
        conn = connection.return_value
        response = conn.getresponse.return_value
        response.status = 200
        response.getheader.return_value = "identity"
        response.read.return_value = b"x" * 1025
        with self.assertRaisesRegex(TransportError, "^response_budget_exceeded$"):
            request(HOST, "GET", "/v1.0/auditLogs/signIns?q=1", {}, None, 1024, 15)
        response.read.assert_called_once_with(1025)
        response.status = 429
        response.getheader.return_value = "120"
        with self.assertRaises(TransportError) as caught:
            request(HOST, "GET", "/v1.0/auditLogs/signIns?q=1", {}, None, 1024, 15)
        self.assertEqual(caught.exception.retry_after, 120)


if __name__ == "__main__":
    unittest.main()
