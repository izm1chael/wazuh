"""Bounded retry delay policy, not a scheduler or persistent lease."""
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import math
import re

from ledger import ContractError


@dataclass(frozen=True)
class Retry:
    disposition: str
    delay_seconds: int | None


def retry(status, attempt, now, retry_after=None):
    """Respect server lower bound; defer rather than truncate long waits.

    Caller supplies consecutive attempt count and aware clock. A scheduler
    must persist next eligibility, apply fairness and jitter across sources.
    """
    if (type(status) is not int or not 100 <= status <= 599
            or type(attempt) is not int or not 1 <= attempt <= 100
            or not isinstance(now, datetime) or now.utcoffset() is None):
        raise ContractError("invalid retry context")
    if status in (401, 403):
        return Retry("credential_or_permission_review", None)
    if status not in (408, 429, 500, 502, 503, 504):
        return Retry("terminal_response", None)
    if attempt > 8:
        return Retry("retry_budget_exhausted", None)
    delay = min(300, 2 ** attempt)
    if retry_after is not None:
        if not isinstance(retry_after, str) or len(retry_after) > 128:
            return Retry("invalid_retry_after", None)
        try:
            if re.fullmatch(r"[0-9]{1,10}", retry_after):
                lower = int(retry_after)
            else:
                date = parsedate_to_datetime(retry_after)
                if date.utcoffset() is None:
                    raise ValueError()
                lower = max(0, math.ceil((date.astimezone(timezone.utc)
                                          - now.astimezone(timezone.utc)).total_seconds()))
        except (ValueError, TypeError, OverflowError, AttributeError):
            return Retry("invalid_retry_after", None)
        delay = max(delay, lower)
    if delay > 86400:
        return Retry("operator_deferred", None)
    return Retry("retry", delay)
