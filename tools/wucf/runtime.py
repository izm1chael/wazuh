"""Bounded single-worker collection coordinator; injected provider and sink only.

No network, registration, secret retrieval, distributed lease or native receipt.
The caller must provision a protected ledger and trusted, bounded adapters.
"""
from dataclasses import dataclass
from typing import Protocol

from ledger import ContractError, Ledger, cursor, page


@dataclass(frozen=True)
class Batch:
    following: str | None
    events: list
    more: bool = False


@dataclass(frozen=True)
class Receipt:
    page_id: str
    durability: str
    boundary: str = "unqualified_adapter"


class Provider(Protocol):
    def fetch(self, current: str | None) -> Batch: ...


class Sink(Protocol):
    def deliver(self, page_id: str, body: dict) -> Receipt: ...


@dataclass(frozen=True)
class RunResult:
    status: str
    acknowledged_pages: int
    acknowledged_events: int
    pending: bool
    boundary: str = "unqualified_adapter"


def run(ledger: Ledger, provider: Provider, sink: Sink,
        max_pages: int = 10, *, expected_boundary: str = "unqualified_adapter") -> RunResult:
    """Recover before polling; stop on any ambiguous delivery or adapter error.

    A page budget bounds work, not wall time. Adapters must implement their
    own timeouts, byte bounds, throttling and cancellation. No in-call retries.
    Exceptions are intentionally not exposed in the result.
    """
    if type(max_pages) is not int or not 1 <= max_pages <= 100:
        raise ContractError("invalid page budget")
    if expected_boundary not in {"unqualified_adapter", "local_spool"}:
        raise ContractError("unsupported delivery boundary")
    pages = events = 0
    for _ in range(max_pages):
        state = ledger.state()
        pending = state["pending"]
        recovered = pending is not None
        if not recovered:
            try:
                batch = provider.fetch(state["cursor"])
            except Exception:
                return RunResult("provider_error", pages, events, False, expected_boundary)
            if not isinstance(batch, Batch) or type(batch.more) is not bool:
                return RunResult("invalid_provider_page", pages, events, False, expected_boundary)
            if not isinstance(batch.events, list):
                return RunResult("invalid_provider_page", pages, events, False, expected_boundary)
            if batch.following == state["cursor"]:
                if not batch.events and not batch.more:
                    return RunResult("idle", pages, events, False, expected_boundary)
                return RunResult("invalid_provider_page", pages, events, False, expected_boundary)
            try:
                cursor(batch.following)
                page(ledger.scope, state["generation"], state["cursor"],
                     batch.following, batch.events)
            except ContractError:
                return RunResult("invalid_provider_page", pages, events, False, expected_boundary)
            # Ledger failures are not provider failures; propagate and stop.
            ledger.stage(state["generation"], state["cursor"],
                         batch.following, batch.events)
            state = ledger.state()
            pending = state["pending"]
        pid = state["pending_id"]
        count = len(pending["events"])
        try:
            receipt = sink.deliver(pid, pending)
        except Exception:
            return RunResult("delivery_unknown", pages, events, True, expected_boundary)
        if (not isinstance(receipt, Receipt) or receipt.page_id != pid
                or receipt.durability != "durable" or receipt.boundary != expected_boundary):
            return RunResult("delivery_unconfirmed", pages, events, True, expected_boundary)
        ledger.acknowledge(pid, receipt.durability)
        pages += 1
        events += count
        # Recovered pages have no transient continuation flag. Poll from the
        # acknowledged cursor again (provider must support this).
        if not recovered and not batch.more:
            return RunResult("complete", pages, events, False, expected_boundary)
    return RunResult("budget_exhausted", pages, events, False, expected_boundary)
