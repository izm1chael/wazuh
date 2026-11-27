"""Durable *local lab* ingress spool; never a native WCS acknowledgement.

One protected SQLite file per source/revision; plaintext data, no drain,
production retention, distributed fencing or native confirmation mechanism.
Quota exhaustion blocks collection instead of discarding unprocessed pages.
"""
import json
import sqlite3

from ledger import ContractError, canonical, page, scope
from runtime import Receipt


class LocalSpool:
    def __init__(self, path, scope_value, max_pages=1000, max_bytes=64 * 1024 * 1024):
        try:
            self.scope = scope(**scope_value)
        except (TypeError, KeyError) as exc:
            raise ContractError("invalid spool scope") from exc
        if (type(max_pages) is not int or not 1 <= max_pages <= 10000
                or type(max_bytes) is not int or not 1024 <= max_bytes <= 1024 ** 3):
            raise ContractError("invalid spool quota")
        self.max_pages = max_pages
        self.max_bytes = max_bytes
        self.db = sqlite3.connect(path, timeout=5)
        try:
            self.db.execute("PRAGMA synchronous=FULL")
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute("CREATE TABLE IF NOT EXISTS spool_scope (singleton INTEGER PRIMARY KEY CHECK(singleton=1), scope BLOB NOT NULL)")
                self.db.execute("INSERT OR IGNORE INTO spool_scope VALUES (1,?)", (canonical(self.scope),))
                self.db.execute("""CREATE TABLE IF NOT EXISTS accepted_pages (
                    generation INTEGER PRIMARY KEY, page_id TEXT NOT NULL UNIQUE,
                    body BLOB NOT NULL)""")
                self._check_scope()
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def _check_scope(self):
        row = self.db.execute("SELECT scope FROM spool_scope WHERE singleton=1").fetchone()
        if row is None or row[0] != canonical(self.scope):
            raise ContractError("spool scope mismatch")

    def _validate(self, page_id, body):
        if (not isinstance(body, dict)
                or set(body) != {"scope", "generation", "previous", "following", "events"}
                or body["scope"] != self.scope):
            raise ContractError("spool page scope or shape")
        calculated, raw = page(self.scope, body["generation"], body["previous"],
                               body["following"], body["events"])
        if calculated != page_id:
            raise ContractError("spool page digest mismatch")
        return raw

    def deliver(self, page_id, body):
        """Receipt means committed to this spool only, not native acceptance.

        When explicitly selected in a lab, the runtime ledger can advance
        after local durability. All accepted bytes are retained for future
        reconciliation. Never present this receipt as successful WCS ingest.
        """
        raw = self._validate(page_id, body)
        generation = body["generation"]
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self._check_scope()
            prior = self.db.execute("SELECT page_id,body FROM accepted_pages WHERE generation=?",
                                    (generation,)).fetchone()
            if prior is not None:
                if prior != (page_id, raw):
                    raise ContractError("conflicting spool generation")
                return Receipt(page_id, "durable")
            count, used, last = self.db.execute(
                "SELECT COUNT(*),COALESCE(SUM(LENGTH(body)),0),MAX(generation) FROM accepted_pages"
            ).fetchone()
            if generation != (0 if last is None else last + 1):
                raise ContractError("spool generation gap")
            if last is not None:
                previous_id, previous_raw = self.db.execute(
                    "SELECT page_id,body FROM accepted_pages WHERE generation=?", (last,)
                ).fetchone()
                previous = json.loads(previous_raw)
                if self._validate(previous_id, previous) != previous_raw:
                    raise ContractError("spool integrity failure")
                if previous["following"] != body["previous"]:
                    raise ContractError("spool cursor discontinuity")
            elif body["previous"] is not None:
                raise ContractError("invalid initial spool cursor")
            if count >= self.max_pages or used + len(raw) > self.max_bytes:
                raise ContractError("spool quota exceeded")
            self.db.execute("INSERT INTO accepted_pages VALUES (?,?,?)",
                            (generation, page_id, raw))
        return Receipt(page_id, "durable")

    def read(self, after_generation=-1, limit=10):
        """Read bounded retained evidence; no drain or deletion operation."""
        if (type(after_generation) is not int or not -1 <= after_generation < 2 ** 63
                or type(limit) is not int or not 1 <= limit <= 100):
            raise ContractError("invalid spool read bounds")
        self._check_scope()
        result = []
        for generation, pid, raw in self.db.execute(
                "SELECT generation,page_id,body FROM accepted_pages WHERE generation>? ORDER BY generation LIMIT ?",
                (after_generation, limit)):
            body = json.loads(raw)
            if self._validate(pid, body) != raw or body["generation"] != generation:
                raise ContractError("spool integrity failure")
            result.append((pid, body))
        return result
