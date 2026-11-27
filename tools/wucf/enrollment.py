"""Local single-use enrollment/reference identity registry, no listener.

A real TLS termination layer must verify the certificate chain and pass
the authenticated leaf SHA-256 fingerprint. No client-supplied principal
is trusted, no CA issuance or bearer-token-only gateway is implemented.
"""
import secrets
import sqlite3
from dataclasses import dataclass

from ledger import ContractError, HEX, canonical, digest, identifier, scope

MAX_COLLECTORS = 128


def timestamp(value):
    if type(value) is not int or not 0 <= value < 2 ** 53 - 3600:
        raise ContractError("invalid enrollment clock")
    return value


def fingerprint(value):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ContractError("invalid certificate fingerprint")
    return value


@dataclass(frozen=True)
class Identity:
    collector: str
    certificate_sha256: str
    revision: str


class Enrollment:
    def __init__(self, path, scope_value):
        try:
            self.scope = scope(**scope_value)
        except (TypeError, KeyError) as exc:
            raise ContractError("invalid enrollment scope") from exc
        self.db = sqlite3.connect(path, timeout=5)
        try:
            self.db.execute("PRAGMA synchronous=FULL")
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute("CREATE TABLE IF NOT EXISTS enrollment_meta (id INTEGER PRIMARY KEY CHECK(id=1), scope BLOB NOT NULL, clock INTEGER NOT NULL)")
                self.db.execute("INSERT OR IGNORE INTO enrollment_meta VALUES (1,?,0)", (canonical(self.scope),))
                self.db.execute("""CREATE TABLE IF NOT EXISTS collectors (
                    collector TEXT PRIMARY KEY, token_sha TEXT UNIQUE,
                    cert TEXT NOT NULL UNIQUE, expires INTEGER NOT NULL,
                    status TEXT NOT NULL)""")
                self._check(0, advance=False)
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def _check(self, now, advance=True):
        timestamp(now)
        row = self.db.execute("SELECT scope,clock FROM enrollment_meta WHERE id=1").fetchone()
        if row is None or row[0] != canonical(self.scope):
            raise ContractError("enrollment scope mismatch")
        if advance:
            if now < row[1]:
                raise ContractError("enrollment clock regression")
            self.db.execute("UPDATE enrollment_meta SET clock=? WHERE id=1", (now,))

    def issue(self, collector, certificate_sha256, now, ttl=300):
        """Trusted administrator pre-binds expected verified certificate.

        Returns the opaque token once; only its hash is stored. Operator
        authorization, secure delivery and certificate provisioning are external.
        """
        collector = identifier(collector)
        cert = fingerprint(certificate_sha256)
        timestamp(now)
        if type(ttl) is not int or not 30 <= ttl <= 900:
            raise ContractError("invalid enrollment lifetime")
        token = secrets.token_hex(32)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self._check(now)
            if self.db.execute("SELECT COUNT(*) FROM collectors").fetchone()[0] >= MAX_COLLECTORS:
                raise ContractError("collector capacity exhausted")
            try:
                self.db.execute("INSERT INTO collectors VALUES (?,?,?,?,'pending')",
                                (collector, digest(token.encode("ascii")), cert, now + ttl))
            except sqlite3.IntegrityError:
                raise ContractError("collector or certificate already registered") from None
        return token

    def redeem(self, collector, token, verified_certificate_sha256, now):
        collector = identifier(collector)
        cert = fingerprint(verified_certificate_sha256)
        fingerprint(token)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self._check(now)
            row = self.db.execute("SELECT token_sha,cert,expires,status FROM collectors WHERE collector=?",
                                  (collector,)).fetchone()
            if (row is None or row[3] != "pending" or now >= row[2]
                    or row[1] != cert or not secrets.compare_digest(row[0], digest(token.encode("ascii")))):
                raise ContractError("enrollment rejected")
            self.db.execute("UPDATE collectors SET token_sha=NULL,status='active' WHERE collector=?",
                            (collector,))
        return Identity(collector, cert, self.scope["revision"])

    def authorize(self, collector, verified_certificate_sha256, now):
        collector = identifier(collector)
        cert = fingerprint(verified_certificate_sha256)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self._check(now)
            row = self.db.execute("SELECT cert,status FROM collectors WHERE collector=?", (collector,)).fetchone()
            if row != (cert, "active"):
                raise ContractError("collector unauthorized")
        return Identity(collector, cert, self.scope["revision"])

    def revoke(self, collector, now):
        collector = identifier(collector)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self._check(now)
            changed = self.db.execute("UPDATE collectors SET token_sha=NULL,status='revoked' WHERE collector=? AND status!='revoked'",
                                      (collector,)).rowcount
            if changed != 1:
                raise ContractError("collector not revocable")
