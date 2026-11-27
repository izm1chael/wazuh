"""Approved generic REST/object/relay contracts, never arbitrary user URLs.

Deployment-owned configuration defines the exact profile and transport. A
profile digest is not an approval; the deployment must pin reviewed digests,
authorization, credential generation and an external network egress policy.
"""
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlencode

from delivery_inbox import DeliveryInbox
from graph import iso
from ledger import ContractError, canonical, digest, identifier
from object_packs import checked_text, decode_json
from windowed_packs import WindowedProvider

HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", re.ASCII)
PATH = re.compile(r"/[A-Za-z0-9_/-]{1,255}", re.ASCII)
FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}", re.ASCII)
TOKEN = re.compile(r"[A-Za-z0-9_.~+/=-]{1,1024}", re.ASCII)


@dataclass(frozen=True)
class RestProfile:
    profile_id: str
    host: str
    path: str
    records_field: str
    id_field: str
    account_field: str
    timestamp_field: str
    continuation_field: str
    start_parameter: str
    end_parameter: str
    account_parameter: str
    token_parameter: str
    limit_parameter: str

    def revision(self):
        identifier(self.profile_id)
        if (not isinstance(self.host, str) or not HOST.fullmatch(self.host)
                or "." not in self.host or ".." in self.host
                or not isinstance(self.path, str) or not PATH.fullmatch(self.path)
                or "//" in self.path):
            raise ContractError("invalid reviewed REST endpoint")
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            pass
        else:
            raise ContractError("literal IP endpoint rejected")
        names = tuple(getattr(self, key) for key in (
            "records_field", "id_field", "account_field", "timestamp_field",
            "continuation_field", "start_parameter", "end_parameter",
            "account_parameter", "token_parameter", "limit_parameter"))
        if any(not isinstance(name, str) or not FIELD.fullmatch(name) for name in names):
            raise ContractError("invalid reviewed field")
        if len(set(names[5:])) != 5 or names[0] == names[4] or len(set(names[1:4])) != 3:
            raise ContractError("ambiguous reviewed profile")
        return digest(canonical(self.__dict__))


class ApprovedREST(WindowedProvider):
    """Simple JSON API: explicit account, time bounds and opaque page token.

    Only a deployment-selected profile matching a pinned reviewed digest
    is admitted. Caller provides a transport that is restricted to that
    exact host/path, never follows redirects, and enforces DNS/TLS/quotas.
    Unsupported pagination or missing stable fields fails closed.
    """
    def __init__(self, profile, admitted_revisions, account, initial, transport, now, lag_seconds=600):
        if (type(profile) is not RestProfile or not isinstance(admitted_revisions, frozenset)
                or profile.revision() not in admitted_revisions):
            raise ContractError("unapproved REST profile")
        self.profile = profile
        self.host, self.path = profile.host, profile.path
        self.account = identifier(account)
        super().__init__(initial, transport, now, lag_seconds)

    def continuation(self, value):
        if not isinstance(value, str) or not TOKEN.fullmatch(value):
            raise ContractError("invalid opaque token")
        return value

    def url(self, start, end, token):
        p = self.profile
        query = {p.start_parameter: iso(start), p.end_parameter: iso(end),
                 p.account_parameter: self.account, p.limit_parameter: "100"}
        if token is not None:
            query[p.token_parameter] = token
        return f"https://{p.host}{p.path}?{urlencode(query)}"

    def extract(self, obj):
        return obj.get(self.profile.records_field), obj.get(self.profile.continuation_field)

    def identity(self, record):
        p = self.profile
        if not isinstance(record, dict) or record.get(p.account_field) != self.account:
            raise ContractError("record account mismatch")
        eid = checked_text(record.get(p.id_field), 256)
        return ["approved_rest", p.revision(), self.account, eid], record.get(p.timestamp_field)


class ImmutableJsonObjects:
    """Trusted object-store client, explicit namespace/prefix and immutable version.

    No URL or credentials from events; no listing or delete. Caller owns
    durable discovery state, signed provider metadata and acknowledgement.
    """
    def __init__(self, namespace, prefix, account, client, inbox):
        self.namespace = identifier(namespace)
        self.account = identifier(account)
        if (not isinstance(prefix, str) or not 1 <= len(prefix) <= 256
                or not prefix.endswith("/") or prefix.startswith("/")
                or any(part in {"", ".", ".."} for part in prefix[:-1].split("/"))
                or type(inbox) is not DeliveryInbox):
            raise ContractError("invalid object profile")
        self.prefix, self.client, self.inbox = prefix, client, inbox

    def collect(self, key, version):
        checked_text(key, 2048)
        checked_text(version, 256)
        if (not key.startswith(self.prefix) or not key.endswith(".json")
                or any(part in {"", ".", ".."} for part in key.split("/"))
                or version in {"null", "latest"}):
            raise ContractError("unapproved object reference")
        raw = self.client.get_version(self.namespace, key, version, max_bytes=16 * 1024 * 1024)
        records = decode_json(raw)
        if not isinstance(records, list) or len(records) > 10000:
            raise ContractError("object record budget")
        events = []
        for record in records:
            if not isinstance(record, dict) or record.get("account") != self.account:
                raise ContractError("object account mismatch")
            eid = checked_text(record.get("id"), 256)
            events.append({"id": digest(canonical(["json_object", self.namespace, self.account, eid])),
                           "payload": record})
        unit = digest(canonical(["json_object", self.namespace, key, version]))
        return self.inbox.accept(unit, events)
