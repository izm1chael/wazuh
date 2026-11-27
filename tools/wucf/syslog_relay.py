"""Offline relay preparation and authenticated handoff; no socket listener."""
import re

from enrollment import Enrollment
from ledger import ContractError, canonical, digest, identifier
from push_gateway import SignedPush, sign

MAX_LINE_BYTES = 8192
MAX_BATCH = 100
PRI = re.compile(r"<([0-9]{1,3})>", re.ASCII)


def prepare_lines(stream_id, first_sequence, lines):
    """One bounded, pre-framed batch from an authorized collector.

    No parsing or canonical WCS fields invented. Device input is raw,
    untrusted data. Stable stream ID and durable sequence allocation must
    be maintained by the collector; do not generate a fresh ID on retry.
    """
    stream_id = identifier(stream_id)
    if (type(first_sequence) is not int or not 0 <= first_sequence < 2 ** 53 - MAX_BATCH
            or not isinstance(lines, list) or not 1 <= len(lines) <= MAX_BATCH):
        raise ContractError("invalid relay batch")
    events = []
    for offset, line in enumerate(lines):
        if not isinstance(line, bytes) or not 1 <= len(line) <= MAX_LINE_BYTES:
            raise ContractError("invalid syslog frame size")
        try:
            message = line.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ContractError("invalid syslog encoding") from exc
        priority = PRI.match(message)
        if (priority is None or int(priority.group(1)) > 191
                or any(ord(c) < 32 and c != "\t" or ord(c) == 127 for c in message)):
            raise ContractError("invalid syslog frame")
        eid = digest(canonical(["syslog_relay", stream_id, first_sequence + offset]))
        events.append({"id": eid, "payload": {"raw_syslog": message}})
    return canonical(events)


class RemoteRelay:
    """Requires identity from a verified external TLS termination layer.

    Pre/post checks detect revocation observed around processing. A racing
    revoke may retain a local unit but cannot cause a native delivery claim.
    The caller must perform atomic authorization/fencing for production.
    """
    def __init__(self, enrollment, push, clock):
        if (type(enrollment) is not Enrollment or type(push) is not SignedPush
                or enrollment.scope != push.inbox.scope):
            raise ContractError("relay scope mismatch")
        self.enrollment, self.push, self.clock = enrollment, push, clock

    def accept(self, verified_certificate, epoch, nonce, signature, body):
        collector = self.push.collector
        self.enrollment.authorize(collector, verified_certificate, self.clock())
        receipt = self.push.accept(epoch, nonce, signature, body)
        self.enrollment.authorize(collector, verified_certificate, self.clock())
        return receipt
