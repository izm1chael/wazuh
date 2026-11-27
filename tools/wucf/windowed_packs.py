"""Azure Activity and Google Workspace Admin Reports provider candidates.

Injected authorized HTTP transport only. No arbitrary endpoint, OAuth setup,
scheduler registration or native sink. Inclusive endpoints may duplicate an
edge event across windows; scoped downstream deduplication is required.
"""
import json
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlsplit

from graph import iso, stamp
from ledger import ContractError, MAX_EVENTS, MAX_PAGE_BYTES, canonical, digest
from runtime import Batch

UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", re.ASCII)
CUSTOMER = re.compile(r"[A-Za-z0-9_-]{1,64}", re.ASCII)
GOOGLE_APPS = frozenset({"admin", "login", "drive", "token", "groups", "saml"})
MAX_RESPONSE = 2 * MAX_PAGE_BYTES
MAX_WINDOW_PAGES = 1000


def safe_url(url, host, path):
    if (not isinstance(url, str) or not 1 <= len(url) <= 3000
            or any(ord(c) < 33 or ord(c) > 126 for c in url)
            or "\\" in url):
        raise ContractError("invalid continuation")
    try:
        parts = urlsplit(url)
        if (parts.scheme, parts.netloc, parts.path) != ("https", host, path) or parts.fragment or not parts.query:
            raise ContractError("unapproved continuation")
    except ValueError as exc:
        raise ContractError("invalid continuation") from exc
    return url


def position(start, end=None, continuation=None, count=0):
    return canonical({"start": iso(start), "end": iso(end) if end else None,
                      "next": continuation, "count": count}).decode("ascii")


class WindowedProvider:
    def __init__(self, initial, transport, now, lag_seconds):
        self.initial = stamp(initial)
        if type(lag_seconds) is not int or not 60 <= lag_seconds <= 86400:
            raise ContractError("invalid lag")
        self.transport = transport
        self.now = now
        self.lag = timedelta(seconds=lag_seconds)

    def parse(self, raw):
        if raw is None:
            return self.initial, None, None, 0
        try:
            obj = json.loads(raw)
            if not isinstance(obj, dict) or set(obj) != {"start", "end", "next", "count"}:
                raise ContractError("invalid cursor")
            start = stamp(obj["start"])
            count = obj["count"]
            if start < self.initial or type(count) is not int or not 0 <= count < MAX_WINDOW_PAGES:
                raise ContractError("invalid cursor position")
            if obj["end"] is None and obj["next"] is None and count == 0:
                return start, None, None, 0
            end = stamp(obj["end"])
            if not start < end <= start + timedelta(hours=1) or count == 0:
                raise ContractError("invalid window")
            return start, end, self.continuation(obj["next"]), count
        except (ValueError, TypeError, KeyError, RecursionError, OverflowError) as exc:
            raise ContractError("invalid cursor") from exc

    def fetch(self, current):
        start, end, token, count = self.parse(current)
        clock = self.now()
        if not isinstance(clock, datetime) or clock.utcoffset() is None:
            raise ContractError("invalid clock")
        horizon = clock.astimezone(timezone.utc) - self.lag
        if end is None:
            end = min(start + timedelta(hours=1), horizon)
            if end <= start:
                return Batch(current, [])
        if end > horizon:
            raise ContractError("future window")
        url = self.url(start, end, token)
        raw = self.transport.get(safe_url(url, self.host, self.path),
                                 max_bytes=MAX_RESPONSE, timeout_seconds=15)
        if not isinstance(raw, bytes) or len(raw) > MAX_RESPONSE:
            raise ContractError("provider response budget")
        try:
            obj = json.loads(raw)
        except (ValueError, RecursionError) as exc:
            raise ContractError("invalid provider JSON") from exc
        if not isinstance(obj, dict):
            raise ContractError("invalid response shape")
        records, following = self.extract(obj)
        if not isinstance(records, list) or len(records) > MAX_EVENTS:
            raise ContractError("provider record budget")
        events = []
        for record in records:
            identity, when = self.identity(record)
            if not start <= stamp(when) <= end:
                raise ContractError("record outside inclusive provider window")
            events.append({"id": digest(canonical(identity)), "payload": record})
        if following is not None:
            following = self.continuation(following)
            if following == token or count + 1 >= MAX_WINDOW_PAGES:
                raise ContractError("pagination stalled or budget exhausted")
            return Batch(position(start, end, following, count + 1), events, True)
        return Batch(position(end), events, end < horizon)


class AzureActivity(WindowedProvider):
    host = "management.azure.com"

    def __init__(self, subscription, initial, transport, now, lag_seconds=600):
        if not isinstance(subscription, str) or not UUID.fullmatch(subscription):
            raise ContractError("invalid subscription")
        self.subscription = subscription.lower()
        self.path = f"/subscriptions/{self.subscription}/providers/microsoft.insights/eventtypes/management/values"
        super().__init__(initial, transport, now, lag_seconds)

    def continuation(self, value):
        return safe_url(value, self.host, self.path)

    def url(self, start, end, token):
        if token is not None:
            return token
        query = urlencode({"api-version": "2015-04-01",
                           "$filter": f"eventTimestamp ge '{iso(start)}' and eventTimestamp le '{iso(end)}'"})
        return f"https://{self.host}{self.path}?{query}"

    def extract(self, obj):
        return obj.get("value"), obj.get("nextLink")

    def identity(self, record):
        if not isinstance(record, dict):
            raise ContractError("invalid Activity record")
        identity = record.get("eventDataId")
        subscription = record.get("subscriptionId")
        if (not isinstance(identity, str) or not identity or len(identity) > 256
                or not isinstance(subscription, str) or subscription.lower() != self.subscription):
            raise ContractError("Activity record identity or subscription mismatch")
        return ["azure_activity", self.subscription, identity], record.get("eventTimestamp")


class GoogleWorkspace(WindowedProvider):
    host = "admin.googleapis.com"

    def __init__(self, customer, application, initial, transport, now, lag_seconds=600):
        if (not isinstance(customer, str) or not CUSTOMER.fullmatch(customer)
                or customer == "my_customer" or application not in GOOGLE_APPS):
            raise ContractError("invalid Workspace account/application")
        self.customer = customer
        self.application = application
        self.path = f"/admin/reports/v1/activity/users/all/applications/{application}"
        super().__init__(initial, transport, now, lag_seconds)

    def continuation(self, value):
        if (not isinstance(value, str) or not 1 <= len(value) <= 2048
                or any(ord(c) < 33 or ord(c) > 126 for c in value)):
            raise ContractError("invalid Workspace page token")
        return value

    def url(self, start, end, token):
        query = {"customerId": self.customer, "startTime": iso(start),
                 "endTime": iso(end), "maxResults": str(MAX_EVENTS)}
        if token is not None:
            query["pageToken"] = token
        return f"https://{self.host}{self.path}?{urlencode(query)}"

    def extract(self, obj):
        # Google may omit items for an empty page. Require the response kind.
        if obj.get("kind") not in {"reports#activities", "admin#reports#activities"}:
            raise ContractError("unexpected Workspace response")
        return obj.get("items", []), obj.get("nextPageToken")

    def identity(self, record):
        if not isinstance(record, dict) or not isinstance(record.get("id"), dict):
            raise ContractError("invalid Workspace record")
        identity = record["id"]
        unique = identity.get("uniqueQualifier")
        if (identity.get("customerId") != self.customer or identity.get("applicationName") != self.application
                or not isinstance(unique, str) or not re.fullmatch(r"-?[0-9]{1,30}", unique)):
            raise ContractError("Workspace identity mismatch")
        when = identity.get("time")
        if isinstance(when, str) and re.fullmatch(r"[0-9]{1,12}", when):
            try:
                when = iso(datetime.fromtimestamp(int(when), tz=timezone.utc))
            except (ValueError, OverflowError, OSError) as exc:
                raise ContractError("invalid Workspace timestamp") from exc
        # Normalize time for stable identity if equivalent UTC strings differ.
        return ["workspace", self.customer, self.application, iso(stamp(when)), unique], when
