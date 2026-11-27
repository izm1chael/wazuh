"""Read-side conservation and native reconciliation reference.

Never writes event indices or calls an engine. Native evidence must come
from a separately qualified, scope-authorized adapter. The default is
unknown; local acceptance alone cannot produce native confirmation.
"""
import sqlite3
from dataclasses import dataclass

from delivery_inbox import DeliveryInbox, validate_events
from ledger import ContractError, HEX, canonical, digest, identifier, scope

MAX_ROWS = 100000
OUTCOMES = frozenset({"native_confirmed", "native_rejected", "unknown"})


@dataclass(frozen=True)
class Observation:
    event_id: str
    payload_sha256: str
    outcome: str
    evidence_id: str | None


def inventory(events):
    validate_events(events)
    return {event["id"]: digest(canonical(event["payload"])) for event in events}


class Reconciliation:
    """Lab evidence ledger, not a native admission or authorization service.

    Only a trusted evidence reader may supply observations. All rows are
    immutable once confirmed/rejected; conflicts require review. A durable
    local inbox or spool cannot be drained/deleted by this class.
    """
    def __init__(self, path, scope_value):
        try:
            self.scope = scope(**scope_value)
        except (TypeError, KeyError) as exc:
            raise ContractError("invalid reconciliation scope") from exc
        self.db = sqlite3.connect(path, timeout=5)
        try:
            self.db.execute("PRAGMA synchronous=FULL")
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute("CREATE TABLE IF NOT EXISTS reconcile_meta (id INTEGER PRIMARY KEY CHECK(id=1), scope BLOB NOT NULL)")
                self.db.execute("INSERT OR IGNORE INTO reconcile_meta VALUES (1,?)", (canonical(self.scope),))
                self.db.execute("""CREATE TABLE IF NOT EXISTS observations (
                    delivery_id TEXT NOT NULL, event_id TEXT NOT NULL,
                    payload_sha TEXT NOT NULL, outcome TEXT NOT NULL, evidence TEXT NOT NULL,
                    PRIMARY KEY(delivery_id,event_id))""")
                self._check()
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def _check(self):
        row = self.db.execute("SELECT scope FROM reconcile_meta WHERE id=1").fetchone()
        if row is None or row[0] != canonical(self.scope):
            raise ContractError("reconciliation scope mismatch")

    def _unit(self, inbox, sequence):
        if type(inbox) is not DeliveryInbox or inbox.scope != self.scope:
            raise ContractError("untrusted or foreign inbox")
        if type(sequence) is not int or not 1 <= sequence < 2 ** 63:
            raise ContractError("invalid inbox sequence")
        rows = inbox.read(after=sequence - 1, limit=1)
        if len(rows) != 1 or rows[0][0] != sequence:
            raise ContractError("unknown retained delivery")
        _, delivery_id, events = rows[0]
        return delivery_id, inventory(events)

    def record(self, inbox, sequence, observations):
        """Check exact retained event identities and payloads before recording.

        Native evidence references are opaque identifiers, not proof of
        authenticity. The caller MUST supply them from a qualified reader.
        This method is intentionally not exposed as a management API.
        """
        delivery, expected = self._unit(inbox, sequence)
        if not isinstance(observations, (list, tuple)) or len(observations) > len(expected):
            raise ContractError("invalid evidence count")
        seen = set()
        for row in observations:
            if not isinstance(row, Observation):
                raise ContractError("invalid observation")
            event = identifier(row.event_id)
            if (event in seen or event not in expected or row.payload_sha256 != expected[event]
                    or row.outcome not in OUTCOMES):
                raise ContractError("evidence mismatch")
            seen.add(event)
            if row.outcome == "unknown":
                if row.evidence_id is not None:
                    raise ContractError("unknown outcome cannot carry confirmation")
            else:
                identifier(row.evidence_id)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self._check()
            count = self.db.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
            for row in observations:
                if row.outcome == "unknown":
                    continue
                prior = self.db.execute(
                    "SELECT payload_sha,outcome,evidence FROM observations WHERE delivery_id=? AND event_id=?",
                    (delivery, row.event_id)).fetchone()
                value = (row.payload_sha256, row.outcome, row.evidence_id)
                if prior is not None:
                    if prior != value:
                        raise ContractError("conflicting native evidence")
                    continue
                if count >= MAX_ROWS:
                    raise ContractError("reconciliation capacity exhausted")
                self.db.execute("INSERT INTO observations VALUES (?,?,?,?,?)",
                                (delivery, row.event_id, *value))
                count += 1

    def summary(self, inbox, sequence):
        delivery, expected = self._unit(inbox, sequence)
        self._check()
        confirmed = rejected = 0
        for event, payload, outcome, evidence in self.db.execute(
                "SELECT event_id,payload_sha,outcome,evidence FROM observations WHERE delivery_id=?",
                (delivery,)):
            if event not in expected or payload != expected[event] or outcome not in OUTCOMES - {"unknown"}:
                raise ContractError("stored evidence mismatch")
            identifier(evidence)
            confirmed += outcome == "native_confirmed"
            rejected += outcome == "native_rejected"
        unknown = len(expected) - confirmed - rejected
        return {"delivery_id": delivery, "retained_events": len(expected),
                "reported_native_confirmed": confirmed, "reported_native_rejected": rejected,
                "unknown": unknown, "coverage": "unknown",
                "native_delivery_qualified": False, "deletion_supported": False}
