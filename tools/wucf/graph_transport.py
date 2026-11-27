"""Fixed-host TLS candidate for Graph, no credential persistence or service.

A trusted caller supplies a scope-bound token supplier and controlled resolver.
DNS lookup and token acquisition must be bounded by that caller. Socket
timeouts are inactivity limits, not hard end-to-end deadlines.
"""
import http.client
import ipaddress
import re
import socket
import ssl
from urllib.parse import urlsplit

from graph import HOST, MAX_RESPONSE, PATHS, approved_url
from ledger import ContractError

BEARER = re.compile(r"[A-Za-z0-9._~+/-]{1,16384}={0,4}", re.ASCII)


class TransportFailure(Exception):
    def __init__(self, code, status=None, retry_after=None):
        super().__init__(code)
        self.status = status
        self.retry_after = retry_after


def approved_addresses(values):
    """Reject mixed, private, special-use and non-numeric DNS answers."""
    if not isinstance(values, (list, tuple)) or not 1 <= len(values) <= 16:
        raise TransportFailure("invalid_resolution")
    output = []
    for value in values:
        try:
            if not isinstance(value, str) or "%" in value:
                raise ValueError()
            address = ipaddress.ip_address(value)
        except ValueError:
            raise TransportFailure("invalid_resolution") from None
        if (not address.is_global or address.is_multicast or address.is_reserved
                or address.is_loopback or address.is_link_local
                or getattr(address, "ipv4_mapped", None) is not None):
            raise TransportFailure("unapproved_resolution")
        output.append(str(address))
    return tuple(dict.fromkeys(output))


class _PinnedConnection(http.client.HTTPSConnection):
    def __init__(self, address, timeout):
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        super().__init__(HOST, 443, timeout=timeout, context=context)
        self.address = address
        self.context = context

    def connect(self):
        # Connect only to an admitted numeric address; use original hostname
        # for certificate validation and SNI. No second hostname resolution.
        family = socket.AF_INET6 if ":" in self.address else socket.AF_INET
        raw = socket.socket(family, socket.SOCK_STREAM)
        try:
            raw.settimeout(self.timeout)
            raw.connect((self.address, 443))
            self.sock = self.context.wrap_socket(raw, server_hostname=HOST)
        except BaseException:
            raw.close()
            raise


class GraphHTTPS:
    def __init__(self, dataset, resolve, token_supplier):
        if dataset not in PATHS:
            raise ContractError("unknown Graph profile")
        self.path = PATHS[dataset][0]
        self.resolve = resolve
        self.token_supplier = token_supplier

    def get(self, url, *, max_bytes, timeout_seconds):
        approved_url(url, self.path)
        if (type(max_bytes) is not int or not 1 <= max_bytes <= MAX_RESPONSE
                or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 30):
            raise ContractError("invalid transport budget")
        connection = None
        try:
            addresses = approved_addresses(self.resolve(HOST))
            token = self.token_supplier()
            if not isinstance(token, str) or not BEARER.fullmatch(token):
                raise TransportFailure("invalid_credential")
            parts = urlsplit(url)
            connection = _PinnedConnection(addresses[0], timeout_seconds)
            connection.request("GET", parts.path + "?" + parts.query,
                               headers={"Authorization": "Bearer " + token,
                                        "Accept": "application/json",
                                        "Accept-Encoding": "identity",
                                        "Connection": "close"})
            response = connection.getresponse()
            if response.status != 200:
                hint = response.getheader("Retry-After")
                # Never propagate arbitrary response bodies or sensitive URLs.
                if not isinstance(hint, str) or len(hint) > 128 or not re.fullmatch(
                        r"[A-Za-z0-9 ,:+-]+", hint):
                    hint = None
                raise TransportFailure("http_rejected", response.status, hint)
            encoding = response.getheader("Content-Encoding")
            if encoding not in (None, "identity"):
                raise TransportFailure("unsupported_encoding")
            length = response.getheader("Content-Length")
            if length is not None:
                if not re.fullmatch(r"[0-9]{1,10}", length) or int(length) > max_bytes:
                    raise TransportFailure("response_budget")
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes or (length is not None and len(body) != int(length)):
                raise TransportFailure("response_budget_or_truncation")
            return body
        except TransportFailure:
            raise
        except Exception:
            raise TransportFailure("transport_failed") from None
        finally:
            if connection is not None:
                connection.close()
