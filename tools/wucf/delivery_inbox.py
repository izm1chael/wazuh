"""Retained local object/event inbox for push and queue reference adapters.

Receipt denotes committed local bytes only. No native WCS acceptance,
production encryption, drain or retention. Source scope is provisioned out
of band; delivery IDs and content digests make retry conflicts explicit.
"""
import json
import sqlite3
from dataclasses import dataclass

from ledger import ContractError, MAX_EVENT_BYTES, canonical, digest, identifier, scope

MAX_UNIT_BYTES = 16 * 1024 * 1024
MAX_UNIT_EVENTS = 10000


@dataclass(frozen=True)
class Accepted:
    delivery_id: str
    digest: str
    events: int
    duplicate: bool
    boundary: str = "local_inbox"


def validate_events(events):
    if not isinstance(events, list) or len(events) > MAX_UNIT_EVENTS:
        raise ContractError("invalid delivery event count")
    seen = set()
    total = 0
    for event in events:
        if not isinstance(event, dict) or set(event) != {"id", "payload"}:
            raise ContractError("invalid delivery event")
        eid = identifier(event["id"])
        if eid in seen or not isinstance(event["payload"], dict):
            raise ContractError("duplicate or invalid event")
        seen.add(eid)
        size = len(canonical(event))
        total += size
        if size > MAX_EVENT_BYTES or total > MAX_UNIT_BYTES:
            raise ContractError("delivery byte budget")
    raw = canonical(events)
    if len(raw) > MAX_UNIT_BYTES:
        raise ContractError("delivery byte budget")
    return raw


class DeliveryInbox:
    def __init__(self, path, scope_value, max_units=1000, max_bytes=256 * 1024 * 1024):
        try:
            self.scope = scope(**scope_value)
        except (TypeError, KeyError) as exc:
            raise ContractError("invalid inbox scope") from exc
        if (type(max_units) is not int or not 1 <= max_units <= 10000
                or type(max_bytes) is not int or not 1024 <= max_bytes <= 1024 ** 3):
            raise ContractError("invalid inbox quota")
        self.max_units, self.max_bytes = max_units, max_bytes
        self.db = sqlite3.connect(path, timeout=5)
        try:
            self.db.execute("PRAGMA synchronous=FULL")
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute("CREATE TABLE IF NOT EXISTS inbox_meta (id INTEGER PRIMARY KEY CHECK(id=1), scope BLOB NOT NULL)")
                self.db.execute("INSERT OR IGNORE INTO inbox_meta VALUES (1,?)", (canonical(self.scope),))
                self.db.execute("""CREATE TABLE IF NOT EXISTS units (
                    seq INTEGER PRIMARY KEY, delivery_id TEXT NOT NULL UNIQUE,
                    sha TEXT NOT NULL, body BLOB NOT NULL, event_count INTEGER NOT NULL)""")
                self.check_scope()
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def check_scope(self):
        row = self.db.execute("SELECT scope FROM inbox_meta WHERE id=1").fetchone()
        if row is None or row[0] != canonical(self.scope):
            raise ContractError("inbox scope mismatch")

    def accept(self, delivery_id, events):
        identifier(delivery_id)
        raw = validate_events(events)
        sha = digest(raw)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self.check_scope()
            row = self.db.execute("SELECT sha,body,event_count FROM units WHERE delivery_id=?",
                                  (delivery_id,)).fetchone()
            if row is not None:
                if row != (sha, raw, len(events)):
                    raise ContractError("delivery identity conflict")
                return Accepted(delivery_id, sha, len(events), True)
            count, used = self.db.execute("SELECT COUNT(*),COALESCE(SUM(LENGTH(body)),0) FROM units").fetchone()
            if count >= self.max_units or used + len(raw) > self.max_bytes:
                raise ContractError("inbox quota exceeded")
            self.db.execute("INSERT INTO units(delivery_id,sha,body,event_count) VALUES (?,?,?,?)",
                            (delivery_id, sha, raw, len(events)))
        return Accepted(delivery_id, sha, len(events), False)

    def read(self, after=0, limit=1):
        if (type(after) is not int or not 0 <= after < 2 ** 63
                or type(limit) is not int or not 1 <= limit <= 10):
            raise ContractError("invalid inbox read bounds")
        self.check_scope()
        out = []
        total = 0
        for seq, delivery_id, sha, raw, count in self.db.execute(
                "SELECT seq,delivery_id,sha,body,event_count FROM units WHERE seq>? ORDER BY seq LIMIT ?",
                (after, limit)):
            if not isinstance(raw, bytes) or len(raw) > MAX_UNIT_BYTES or digest(raw) != sha:
                raise ContractError("inbox integrity failure")
            if total + len(raw) > MAX_UNIT_BYTES:
                break
            body = json.loads(raw)
            if validate_events(body) != raw or len(body) != count:
                raise ContractError("inbox body integrity failure")
            identifier(delivery_id)
            out.append((seq, delivery_id, body))
            total += len(raw)
        return out
