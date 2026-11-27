"""Small, advisory health projection; no event payloads, secrets or cursors."""
from datetime import datetime, timezone

from ledger import ContractError
from runtime import RunResult

_STATUSES = {"complete", "idle", "budget_exhausted", "provider_error",
             "invalid_provider_page", "delivery_unknown", "delivery_unconfirmed"}


def project(source, result, observed_at):
    if not isinstance(result, RunResult) or result.status not in _STATUSES:
        raise ContractError("invalid run result")
    if (not isinstance(observed_at, datetime) or observed_at.tzinfo is None
            or observed_at.utcoffset() is None):
        raise ContractError("timezone-aware observation required")
    if (type(result.acknowledged_pages) is not int
            or not 0 <= result.acknowledged_pages <= 100
            or type(result.acknowledged_events) is not int
            or not 0 <= result.acknowledged_events <= 100 * result.acknowledged_pages
            or type(result.pending) is not bool
            or result.pending != (result.status in {"delivery_unknown",
                                                    "delivery_unconfirmed"})):
        raise ContractError("invalid run counters")
    if result.status in {"delivery_unknown", "delivery_unconfirmed"}:
        state = "delivery_blocked"
    elif result.status in {"provider_error", "invalid_provider_page"}:
        state = "collection_error"
    elif result.acknowledged_events:
        state = "events_acknowledged"
    else:
        state = "no_events_observed"
    return {"schema_version": 1, "environment": source.environment,
            "instance": source.instance, "dataset": source.dataset,
            "provider": source.provider, "revision": source.revision,
            "observed_at": observed_at.astimezone(timezone.utc).isoformat(),
            "state": state, "execution_status": result.status,
            "acknowledged_pages": result.acknowledged_pages,
            "acknowledged_events": result.acknowledged_events,
            "pending": result.pending, "coverage": "unknown",
            "native_delivery_qualified": False}
