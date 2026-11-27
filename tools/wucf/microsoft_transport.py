"""Opt-in public Microsoft cloud transport candidate; no registration or secret store."""
import http.client
import ipaddress
import json
import re
import socket
import ssl
from urllib.parse import urlencode

from graph import HOST, PATHS, approved_url
from ledger import ContractError

LOGIN = "login.microsoftonline.com"
UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", re.ASCII)
TOKEN = re.compile(r"[A-Za-z0-9._~+/=-]{1,16384}", re.ASCII)


class TransportError(RuntimeError):
    """Fixed public reason only; never attach URL, response or credentials."""
    def __init__(self, reason, status=None, retry_after=None):
        super().__init__(reason)
        self.status = status
        self.retry_after = retry_after


def public_ip(host, resolver=socket.getaddrinfo):
    if host not in {HOST, LOGIN}:
        raise TransportError("unapproved_host")
    try:
        answers = resolver(host, 443, type=socket.SOCK_STREAM)
        if not answers or len(answers) > 32:
            raise ValueError()
        ips = [ipaddress.ip_address(answer[4][0]) for answer in answers]
        if any(not ip.is_global or ip.is_multicast or ip.is_reserved
               or ip.is_loopback or ip.is_link_local or ip.is_unspecified
               or getattr(ip, "ipv4_mapped", None) is not None for ip in ips):
            raise ValueError()
        return str(ips[0])
    except (OSError, ValueError, TypeError, IndexError):
        raise TransportError("egress_resolution_rejected") from None


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, ip, timeout):
        super().__init__(host, 443, timeout=timeout,
                         context=ssl.create_default_context())
        self.ip = ip

    def connect(self):
        raw = socket.create_connection((self.ip, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def request(host, method, target, headers, body, max_bytes, timeout):
    if host not in {HOST, LOGIN} or method not in {"GET", "POST"}:
        raise TransportError("unapproved_request")
    if not 1 <= max_bytes <= 2 * 1024 * 1024 or not 1 <= timeout <= 30:
        raise TransportError("invalid_transport_budget")
    # Resolve once; connect only to the validated numeric address while retaining
    # the original DNS name for certificate verification and HTTP Host.
    connection = PinnedHTTPS(host, public_ip(host), timeout)
    try:
        connection.request(method, target, body=body,
                           headers={**headers, "Accept-Encoding": "identity"})
        response = connection.getresponse()
        if response.status != 200:
            delay = response.getheader("Retry-After")
            retry_after = (min(int(delay), 3600) if delay and len(delay) <= 6
                           and delay.isascii() and delay.isdigit() else None)
            raise TransportError("http_rejected", response.status, retry_after)
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise TransportError("unsupported_encoding")
        raw = response.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise TransportError("response_budget_exceeded")
        return raw
    except TransportError:
        raise
    except (OSError, ValueError, http.client.HTTPException):
        raise TransportError("transport_failed") from None
    finally:
        connection.close()


class MicrosoftTransport:
    """Trusted operator provisions tenant/client and a scope-bound secret resolver.

    One access token per GET, deliberately no persisted token/cache. DNS and
    socket timeouts are not an end-to-end wall clock budget. Production needs
    network-level egress rules, rate controls, encrypted state and qualified
    scoped resolver; this class alone is not a SaaS isolation boundary.
    """
    def __init__(self, tenant_id, client_id, resolve_secret, http=request):
        if not all(isinstance(v, str) and UUID.fullmatch(v)
                   for v in (tenant_id, client_id)):
            raise ContractError("invalid Microsoft identity configuration")
        self.tenant_id, self.client_id = tenant_id, client_id
        self._resolve_secret, self._http = resolve_secret, http

    def _token(self):
        try:
            secret = self._resolve_secret()
            if not isinstance(secret, str) or not 1 <= len(secret) <= 4096:
                raise ValueError()
            form = urlencode({"client_id": self.client_id, "client_secret": secret,
                              "scope": "https://graph.microsoft.com/.default",
                              "grant_type": "client_credentials"}).encode("ascii")
        except Exception:
            raise TransportError("credential_unavailable") from None
        raw = self._http(LOGIN, "POST", f"/{self.tenant_id}/oauth2/v2.0/token",
                         {"Content-Type": "application/x-www-form-urlencoded"},
                         form, 65536, 15)
        try:
            if not isinstance(raw, bytes) or len(raw) > 65536:
                raise ValueError()
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError()
            token = data.get("access_token")
            if (not isinstance(token, str) or not TOKEN.fullmatch(token)
                    or str(data.get("token_type")).lower() != "bearer"):
                raise ValueError()
            return token
        except (ValueError, RecursionError):
            raise TransportError("invalid_token_response") from None

    def get(self, url, max_bytes, timeout_seconds):
        from urllib.parse import urlsplit
        # Validate exact reviewed Graph paths before resolving any credential.
        if not isinstance(url, str) or len(url) > 3000:
            raise ContractError("invalid Graph URL")
        try:
            parts = urlsplit(url)
        except ValueError:
            raise ContractError("invalid Graph URL") from None
        if parts.path not in {value[0] for value in PATHS.values()}:
            raise ContractError("unapproved Graph endpoint")
        approved_url(url, parts.path)
        token = self._token()
        return self._http(HOST, "GET", parts.path + "?" + parts.query,
                          {"Authorization": "Bearer " + token, "Accept": "application/json"},
                          None, max_bytes, timeout_seconds)
