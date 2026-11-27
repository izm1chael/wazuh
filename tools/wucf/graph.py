"""Entra Graph window/page adapter candidate with injected HTTP transport.

Only reviewed public-cloud paths. No OAuth or network implementation here.
Continuation URLs can contain sensitive opaque tokens: use protected state,
never log them. Native ingestion and live Graph semantics require qualification.
"""
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlsplit

from ledger import ContractError, MAX_EVENTS, MAX_PAGE_BYTES, canonical, digest
from runtime import Batch

HOST = "graph.microsoft.com"
PATHS = {"signins": ("/v1.0/auditLogs/signIns", "createdDateTime"),
         "directory_audit": ("/v1.0/auditLogs/directoryAudits", "activityDateTime")}
MAX_RESPONSE = 2 * MAX_PAGE_BYTES
MAX_WINDOW_PAGES = 1000


def stamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ContractError("invalid timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() is None:
            raise ValueError()
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise ContractError("invalid timestamp") from exc


def iso(value):
    return value.isoformat().replace("+00:00", "Z")


def approved_url(url, path):
    if (not isinstance(url, str) or not url or len(url) > 3000
            or any(ord(c) < 33 or ord(c) > 126 for c in url)
            or "\\" in url):
        raise ContractError("invalid Graph URL")
    try:
        parts = urlsplit(url)
        if (parts.scheme != "https" or parts.netloc != HOST
                or parts.path != path or parts.fragment or not parts.query):
            raise ContractError("unapproved Graph endpoint")
    except ValueError as exc:
        raise ContractError("invalid Graph URL") from exc
    # Transport must prohibit redirects and proxy overrides, validate TLS and
    # apply DNS/IP egress policy. Host validation alone is not SSRF protection.
    return url


def position(start, end=None, next_url=None, page_count=0):
    return canonical({"start": iso(start), "end": iso(end) if end else None,
                      "next": next_url, "page_count": page_count}).decode("ascii")


def parse_position(raw, initial, path):
    if raw is None:
        return initial, None, None, 0
    try:
        obj = json.loads(raw)
        if not isinstance(obj, dict) or set(obj) != {"start", "end", "next", "page_count"}:
            raise ContractError("invalid Graph position")
        start = stamp(obj["start"])
        count = obj["page_count"]
        if type(count) is not int or not 0 <= count < MAX_WINDOW_PAGES:
            raise ContractError("Graph window page budget")
        if obj["end"] is None and obj["next"] is None and count == 0:
            return start, None, None, 0
        if count == 0:
            raise ContractError("invalid Graph continuation count")
        end = stamp(obj["end"])
        if not start < end <= start + timedelta(hours=1):
            raise ContractError("invalid Graph window")
        return start, end, approved_url(obj["next"], path), count
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError) as exc:
        raise ContractError("invalid Graph position") from exc


class GraphProvider:
    """Fetch closed, half-open time windows; late arrivals need explicit replay.

    transport.get(url, max_bytes=..., timeout_seconds=...) returns raw bytes,
    with non-200 and redirects rejected by the transport. OAuth credentials
    belong to that trusted transport; no credentials pass through this class.
    now() returns an aware UTC datetime. Fixed initial time is trusted config.
    """
    def __init__(self, dataset, initial, transport, now, lag_seconds=600):
        if dataset not in PATHS or type(lag_seconds) is not int or not 60 <= lag_seconds <= 86400:
            raise ContractError("invalid Graph profile")
        self.path, self.field = PATHS[dataset]
        self.initial = stamp(initial)
        self.transport = transport
        self.now = now
        self.lag = timedelta(seconds=lag_seconds)

    def fetch(self, current):
        start, end, url, count = parse_position(current, self.initial, self.path)
        clock = self.now()
        if not isinstance(clock, datetime) or clock.utcoffset() is None:
            raise ContractError("invalid clock")
        horizon = clock.astimezone(timezone.utc) - self.lag
        if end is None:
            end = min(start + timedelta(hours=1), horizon)
            if end <= start:
                return Batch(current, [])
            query = urlencode({"$filter": f"{self.field} ge {iso(start)} and {self.field} lt {iso(end)}",
                               "$top": str(MAX_EVENTS)})
            url = f"https://{HOST}{self.path}?{query}"
        if end > horizon:
            raise ContractError("window extends beyond admitted horizon")
        raw = self.transport.get(approved_url(url, self.path),
                                 max_bytes=MAX_RESPONSE, timeout_seconds=15)
        if not isinstance(raw, bytes) or len(raw) > MAX_RESPONSE:
            raise ContractError("Graph response byte budget")
        try:
            data = json.loads(raw)
        except (ValueError, RecursionError) as exc:
            raise ContractError("invalid Graph JSON") from exc
        if not isinstance(data, dict) or not isinstance(data.get("value"), list):
            raise ContractError("invalid Graph page")
        if len(data["value"]) > MAX_EVENTS:
            raise ContractError("Graph page count budget")
        events = []
        for item in data["value"]:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"]:
                raise ContractError("missing stable Graph event identity")
            if not start <= stamp(item.get(self.field)) < end:
                raise ContractError("event outside admitted window")
            # Full native provider payload is preserved; no competing schema.
            eid = digest(canonical({"path": self.path, "id": item["id"]}))
            events.append({"id": eid, "payload": item})
        following = data.get("@odata.nextLink")
        if following is not None:
            following = approved_url(following, self.path)
            if following == url:
                raise ContractError("non-progressing Graph pagination")
            if count + 1 >= MAX_WINDOW_PAGES:
                raise ContractError("Graph window page budget exceeded")
            return Batch(position(start, end, following, count + 1), events, True)
        return Batch(position(end), events, end < horizon)
