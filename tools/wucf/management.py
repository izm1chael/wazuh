"""Local reference management/scheduling store; never registers a live worker."""
import secrets
import sqlite3
from contextlib import contextmanager

from ledger import ContractError, HEX, identifier

MAX_SOURCES = 128
MAX_AUDIT = 4096


def epoch(value):
    if type(value) is not int or not 0 <= value <= 2**53 - 86401:
        raise ContractError("invalid clock")
    return value


def fingerprint(value):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ContractError("invalid fingerprint")
    return value


class Management:
    """Protected local DB per trusted environment, one lab claim at a time.

    Caller is responsible for authentication, file permissions, trusted time,
    worker termination, exact profile admission and external sink fencing.
    Expiry never automatically reassigns work. No secrets or events stored.
    """
    def __init__(self, path, environment):
        self.environment = identifier(environment)
        self.db = sqlite3.connect(path, timeout=5)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute("PRAGMA synchronous=FULL")
            with self.tx():
                self.db.execute("CREATE TABLE IF NOT EXISTS meta (id INTEGER PRIMARY KEY CHECK(id=1), environment TEXT NOT NULL, clock INTEGER NOT NULL)")
                self.db.execute("INSERT OR IGNORE INTO meta VALUES (1,?,0)", (self.environment,))
                self.db.execute("""CREATE TABLE IF NOT EXISTS sources (
                    instance TEXT NOT NULL, dataset TEXT NOT NULL, revision TEXT NOT NULL,
                    interval INTEGER NOT NULL, state TEXT NOT NULL, version INTEGER NOT NULL,
                    due INTEGER NOT NULL, admission TEXT, lease TEXT, expiry INTEGER, lease_actor TEXT,
                    PRIMARY KEY(instance,dataset))""")
                self.db.execute("""CREATE TABLE IF NOT EXISTS audit (
                    seq INTEGER PRIMARY KEY, instance TEXT NOT NULL, dataset TEXT NOT NULL,
                    version INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
                    at INTEGER NOT NULL, evidence TEXT)""")
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    @contextmanager
    def tx(self, now=None):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            if self.db.execute("SELECT name FROM sqlite_master WHERE name='meta'").fetchone():
                meta = self.db.execute("SELECT * FROM meta WHERE id=1").fetchone()
                if meta is None or meta["environment"] != self.environment:
                    raise ContractError("environment mismatch")
                if now is not None:
                    epoch(now)
                    if now < meta["clock"]:
                        raise ContractError("clock regression")
                    self.db.execute("UPDATE meta SET clock=? WHERE id=1", (now,))
            yield

    def _audit(self, row, actor, action, now, evidence=None):
        if self.db.execute("SELECT COUNT(*) FROM audit").fetchone()[0] >= MAX_AUDIT:
            raise ContractError("audit capacity exhausted")
        self.db.execute("INSERT INTO audit(instance,dataset,version,actor,action,at,evidence) VALUES (?,?,?,?,?,?,?)",
                        (row["instance"], row["dataset"], row["version"], identifier(actor), action, now, evidence))

    def _get(self, instance, dataset):
        row = self.db.execute("SELECT * FROM sources WHERE instance=? AND dataset=?",
                              (identifier(instance), identifier(dataset))).fetchone()
        if row is None:
            raise ContractError("unknown source")
        return row

    def _view(self, row):
        return {**{k: row[k] for k in ("instance", "dataset", "revision", "interval", "state", "version", "due")},
                "claim_expiry": row["expiry"]}

    def get(self, instance, dataset):
        with self.tx():
            return self._view(self._get(instance, dataset))

    def register(self, instance, dataset, revision, interval, actor, now):
        identifier(instance)
        identifier(dataset)
        fingerprint(revision)
        if type(interval) is not int or not 60 <= interval <= 86400:
            raise ContractError("invalid interval")
        with self.tx(now):
            if self.db.execute("SELECT COUNT(*) FROM sources").fetchone()[0] >= MAX_SOURCES:
                raise ContractError("source capacity exhausted")
            try:
                self.db.execute("INSERT INTO sources VALUES (?,?,?,?,'draft',0,?,NULL,NULL,NULL,NULL)",
                                (instance, dataset, revision, interval, now))
            except sqlite3.IntegrityError:
                raise ContractError("source already registered") from None
            row = self._get(instance, dataset)
            self._audit(row, actor, "register", now)
            return self._view(row)

    def change(self, instance, dataset, version, action, actor, now, evidence=None):
        """Only trusted lab operator. Admission/recovery digests are attestations."""
        if type(version) is not int or version < 0:
            raise ContractError("invalid version")
        with self.tx(now):
            row = self._get(instance, dataset)
            if row["version"] != version:
                raise ContractError("stale source version")
            state = row["state"]
            admission = row["admission"]
            if row["lease"] is not None:
                raise ContractError("outstanding worker claim")
            if action == "admit_lab" and state == "draft":
                admission = fingerprint(evidence)
                target = "ready"
            elif action == "pause" and state == "ready" and evidence is None:
                target = "paused"
            elif action == "resume_lab" and state == "paused" and admission and evidence is None:
                target = "ready"
            elif action == "reconcile" and state == "review":
                fingerprint(evidence)
                target = "paused"
            elif action == "revoke" and state in {"draft", "ready", "paused"} and evidence is None:
                target = "revoked"
            else:
                raise ContractError("invalid lifecycle transition")
            self.db.execute("UPDATE sources SET state=?,admission=?,version=version+1,due=? WHERE instance=? AND dataset=?",
                            (target, admission, now, instance, dataset))
            updated = self._get(instance, dataset)
            self._audit(updated, actor, action, now, evidence)
            return self._view(updated)

    def claim(self, actor, now, ttl=120):
        """A lab scheduler reservation only, not an execution authorization."""
        identifier(actor)
        if type(ttl) is not int or not 30 <= ttl <= 900:
            raise ContractError("invalid claim lifetime")
        with self.tx(now):
            if self.db.execute("SELECT 1 FROM sources WHERE lease IS NOT NULL").fetchone():
                return None
            row = self.db.execute("SELECT * FROM sources WHERE state='ready' AND admission IS NOT NULL AND due<=? ORDER BY due,instance,dataset LIMIT 1", (now,)).fetchone()
            if row is None:
                return None
            token = secrets.token_hex(32)
            self.db.execute("UPDATE sources SET lease=?,expiry=?,lease_actor=?,version=version+1 WHERE instance=? AND dataset=?",
                            (token, now+ttl, actor, row["instance"], row["dataset"]))
            updated = self._get(row["instance"], row["dataset"])
            self._audit(updated, actor, "claim", now)
            return {**self._view(updated), "lease": token, "expiry": now+ttl,
                    "environment": self.environment, "boundary": "local_spool"}

    def finish(self, instance, dataset, token, actor, now, outcome, boundary):
        """Injected worker outcome, not verified native delivery or a sink fence."""
        fingerprint(token)
        if boundary != "local_spool" or outcome not in {"complete", "idle", "budget_exhausted", "provider_error", "invalid_provider_page", "delivery_unknown", "delivery_unconfirmed"}:
            raise ContractError("invalid outcome")
        with self.tx(now):
            row = self._get(instance, dataset)
            if (row["lease"] != token or row["lease_actor"] != actor
                    or row["expiry"] is None or now >= row["expiry"]):
                raise ContractError("invalid or expired claim")
            # No retry of provider failures without persisted Retry-After evidence.
            target = "ready" if outcome in {"complete", "idle", "budget_exhausted"} else "review"
            delay = 60 if outcome == "budget_exhausted" else row["interval"]
            self.db.execute("UPDATE sources SET state=?,due=?,lease=NULL,expiry=NULL,lease_actor=NULL,version=version+1 WHERE instance=? AND dataset=?",
                            (target, now+delay, instance, dataset))
            updated = self._get(instance, dataset)
            self._audit(updated, actor, outcome, now)
            return self._view(updated)

    def recover_expired(self, instance, dataset, version, actor, now, evidence):
        """Trusted operator attests old worker stopped; never automatic reclaim."""
        if type(version) is not int or version < 0:
            raise ContractError("invalid version")
        fingerprint(evidence)
        with self.tx(now):
            row = self._get(instance, dataset)
            if (row["version"] != version or row["lease"] is None
                    or row["expiry"] is None or now < row["expiry"]):
                raise ContractError("claim not expired or mismatch")
            self.db.execute("UPDATE sources SET state='review',lease=NULL,expiry=NULL,lease_actor=NULL,version=version+1 WHERE instance=? AND dataset=?", (instance,dataset))
            updated = self._get(instance, dataset)
            self._audit(updated, actor, "expired_worker_attestation", now, evidence)
            return self._view(updated)

    def check_claim(self, claim, actor, now):
        """Recheck reservation before lab work; not a fence on an external sink."""
        identifier(actor)
        if not isinstance(claim, dict) or claim.get("environment") != self.environment or claim.get("boundary") != "local_spool":
            raise ContractError("claim scope mismatch")
        token = fingerprint(claim.get("lease"))
        with self.tx(now):
            row = self._get(claim.get("instance"), claim.get("dataset"))
            if (row["lease"] != token or row["lease_actor"] != actor or row["expiry"] is None
                    or now >= row["expiry"] or claim.get("expiry") != row["expiry"]
                    or any(claim.get(k) != v for k, v in self._view(row).items())):
                raise ContractError("invalid or expired claim")
