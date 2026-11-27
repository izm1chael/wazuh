"""Offline WUCF reference protocol; no network, native ingress or service registration."""
import hashlib
import json
import re
import sqlite3

MAX_EVENTS = 100
MAX_PAGE_BYTES = 1024 * 1024
MAX_EVENT_BYTES = 64 * 1024
ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}", re.ASCII)
HEX = re.compile(r"[0-9a-f]{64}", re.ASCII)


class ContractError(ValueError):
    pass


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, RecursionError, OverflowError) as exc:
        raise ContractError("invalid JSON") from exc


def digest(data):
    return hashlib.sha256(data).hexdigest()


def identifier(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ContractError("invalid identifier")
    return value


def scope(environment, instance, dataset, revision):
    """Inputs are trusted provisioning values, not authenticated by this module."""
    if not isinstance(revision, str) or not HEX.fullmatch(revision):
        raise ContractError("invalid configuration fingerprint")
    return {"environment": identifier(environment), "instance": identifier(instance),
            "dataset": identifier(dataset), "revision": revision}


def cursor(value):
    # A provider adapter must ensure that opaque positions contain no credentials.
    if value is not None and (not isinstance(value, str) or not value or
                              len(value.encode("utf-8", errors="surrogatepass")) > 4096):
        raise ContractError("invalid cursor")
    return value


def page(scope_value, generation, previous, following, events):
    if type(generation) is not int or not 0 <= generation < 2**63 - 1:
        raise ContractError("invalid generation")
    cursor(previous)
    cursor(following)
    if following is None or following == previous:
        raise ContractError("cursor must advance")
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise ContractError("invalid page size")
    seen = set()
    total = 0
    for event in events:
        if not isinstance(event, dict) or set(event) != {"id", "payload"}:
            raise ContractError("invalid event envelope")
        eid = identifier(event["id"])
        if eid in seen or not isinstance(event["payload"], dict):
            raise ContractError("duplicate ID or invalid payload")
        seen.add(eid)
        size = len(canonical(event))
        total += size
        if size > MAX_EVENT_BYTES or total > MAX_PAGE_BYTES:
            raise ContractError("event/page byte budget exceeded")
    body = canonical({"scope": scope_value, "generation": generation,
                      "previous": previous, "following": following, "events": events})
    if len(body) > MAX_PAGE_BYTES:
        raise ContractError("page byte budget exceeded")
    return digest(body), body


class Ledger:
    """One pre-provisioned, protected lab database per scope, one worker.

    Pending raw data is plaintext; no production use. A receipt is an assertion
    from an injected trusted adapter, not proof of native ingestion or identity.
    """
    def __init__(self, path, scope_value):
        try:
            self.scope = scope(**scope_value)
        except (TypeError, KeyError) as exc:
            raise ContractError("invalid scope") from exc
        self.db = sqlite3.connect(path, timeout=5)
        try:
            self.db.execute("PRAGMA synchronous=FULL")
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute("""CREATE TABLE IF NOT EXISTS checkpoint (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    scope BLOB NOT NULL, generation INTEGER NOT NULL,
                    cursor TEXT, pending_id TEXT, pending_body BLOB,
                    last_ack TEXT)""")
                self.db.execute("INSERT OR IGNORE INTO checkpoint VALUES (1,?,0,NULL,NULL,NULL,NULL)",
                                (canonical(self.scope),))
                self._row()
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def _row(self):
        row = self.db.execute("SELECT scope,generation,cursor,pending_id,pending_body,last_ack "
                              "FROM checkpoint WHERE singleton=1").fetchone()
        if row is None or row[0] != canonical(self.scope):
            raise ContractError("database scope mismatch")
        if (row[3] is None) != (row[4] is None):
            raise ContractError("inconsistent pending state")
        if row[4] is not None:
            if not isinstance(row[4], bytes) or len(row[4]) > MAX_PAGE_BYTES or digest(row[4]) != row[3]:
                raise ContractError("pending integrity failure")
            try:
                body = json.loads(row[4])
                pid, raw = page(self.scope, row[1], row[2], body["following"], body["events"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ContractError("invalid pending state") from exc
            if pid != row[3] or raw != row[4]:
                raise ContractError("pending context mismatch")
        return row

    def state(self):
        _, generation, current, pending_id, pending, last = self._row()
        return {"generation": generation, "cursor": current, "pending_id": pending_id,
                "pending": json.loads(pending) if pending else None, "last_ack": last}

    def stage(self, generation, previous, following, events):
        pid, body = page(self.scope, generation, previous, following, events)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            _, actual, current, pending_id, pending, _ = self._row()
            if actual != generation or current != previous:
                raise ContractError("stale checkpoint")
            if pending_id is not None:
                if pending_id == pid and pending == body:
                    return pid
                raise ContractError("another page is pending")
            self.db.execute("UPDATE checkpoint SET pending_id=?, pending_body=? WHERE singleton=1",
                            (pid, body))
        return pid

    def acknowledge(self, page_id, durability):
        # Only the future trusted sink adapter can assert this level.
        if not isinstance(page_id, str) or not HEX.fullmatch(page_id):
            raise ContractError("invalid receipt ID")
        if durability != "durable":
            raise ContractError("durable acknowledgement required")
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            _, generation, _, pending_id, pending, last = self._row()
            if page_id == last:
                return generation
            if page_id != pending_id or pending is None:
                raise ContractError("receipt does not match pending page")
            following = json.loads(pending)["following"]
            self.db.execute("UPDATE checkpoint SET generation=?,cursor=?,pending_id=NULL,"
                            "pending_body=NULL,last_ack=? WHERE singleton=1",
                            (generation + 1, following, page_id))
        return generation + 1
