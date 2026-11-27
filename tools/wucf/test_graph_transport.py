import unittest
from unittest.mock import Mock, patch

from graph_transport import GraphHTTPS, TransportFailure, approved_addresses

URL = "https://graph.microsoft.com/v1.0/auditLogs/signIns?%24top=100"
IP = "1.1.1.1"  # Test-only address; never contacted.


class TransportTests(unittest.TestCase):
    def test_dns_rejects_private_mixed_and_special_addresses(self):
        for addresses in ([], ["127.0.0.1"], [IP, "10.1.1.1"], ["::1"],
                          ["169.254.169.254"], ["224.0.0.1"], ["::ffff:1.1.1.1"],
                          ["example.com"], ["fe80::1%eth0"]):
            with self.assertRaises(TransportFailure):
                approved_addresses(addresses)
        self.assertEqual(approved_addresses([IP, IP]), (IP,))

    def response(self, status=200, headers=None, body=b"{}"):
        response = Mock()
        response.status = status
        response.getheader.side_effect = (headers or {}).get
        response.read.return_value = body
        return response

    def test_single_pinned_request_and_no_proxy_or_redirect(self):
        resolver = Mock(return_value=[IP])
        token = Mock(return_value="fake-token")
        transport = GraphHTTPS("signins", resolver, token)
        with patch("graph_transport._PinnedConnection") as connection:
            instance = connection.return_value
            instance.getresponse.return_value = self.response(302, {"Location": "https://evil.test"})
            with self.assertRaises(TransportFailure) as caught:
                transport.get(URL, max_bytes=100, timeout_seconds=10)
            self.assertEqual(caught.exception.status, 302)
            connection.assert_called_once_with(IP, 10)
            resolver.assert_called_once_with("graph.microsoft.com")
            self.assertEqual(instance.request.call_count, 1)
            self.assertEqual(instance.request.call_args.args[:2], ("GET", "/v1.0/auditLogs/signIns?%24top=100"))
            instance.close.assert_called_once()

    def test_oversize_and_nonidentity_rejected(self):
        transport = GraphHTTPS("signins", lambda _: [IP], lambda: "fake-token")
        for response in (self.response(headers={"Content-Length": "101"}),
                         self.response(headers={"Content-Encoding": "gzip"}),
                         self.response(body=b"x" * 101),
                         self.response(headers={"Content-Length": "4"}, body=b"{}")):
            with patch("graph_transport._PinnedConnection") as connection:
                connection.return_value.getresponse.return_value = response
                with self.assertRaises(TransportFailure):
                    transport.get(URL, max_bytes=100, timeout_seconds=10)

    def test_invalid_credential_never_connects(self):
        transport = GraphHTTPS("signins", lambda _: [IP], lambda: "bad\r\nheader")
        with patch("graph_transport._PinnedConnection") as connection:
            with self.assertRaises(TransportFailure):
                transport.get(URL, max_bytes=100, timeout_seconds=10)
            connection.assert_not_called()

    def test_response_read_is_bounded(self):
        transport = GraphHTTPS("signins", lambda _: [IP], lambda: "fake-token")
        with patch("graph_transport._PinnedConnection") as connection:
            response = self.response(headers={"Content-Length": "2"})
            connection.return_value.getresponse.return_value = response
            self.assertEqual(transport.get(URL, max_bytes=100, timeout_seconds=10), b"{}")
            response.read.assert_called_once_with(101)


if __name__ == "__main__":
    unittest.main()
