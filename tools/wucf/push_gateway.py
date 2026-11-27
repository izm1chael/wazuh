"""Signed push/remote relay reference contract; no network listener.

The trusted transport authenticates the collector, resolves its scoped key,
and enforces TLS, request limits and quotas before calling accept(). The
local receipt proves only durable local inbox acceptance. HMAC verification
does not replace native RBAC, mTLS enrollment or external network security.
"""
import hashlib
import hmac
import json
import re

from delivery_inbox import DeliveryInbox
from ledger import ContractError, canonical, digest, identifier

MAX_PUSH_BYTES = 1024 * 1024
MAX_CLOCK_SKEW = 300
MAX_PUSH_EVENTS = 100
NONCE = re.compile(r"[A-Za-z0-9_-]{22,128}", re.ASCII)
SIGNATURE = re.compile(r"[a-f0-9]{64}", re.ASCII)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate JSON member")
        result[key] = value
    return result


def envelope(scope_value, collector, epoch, nonce, body):
    if type(epoch) is not int or not 0 <= epoch < 2 ** 53:
        raise ContractError("invalid push timestamp")
    if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
        raise ContractError("invalid push nonce")
    if not isinstance(body, bytes) or not 1 <= len(body) <= MAX_PUSH_BYTES:
        raise ContractError("push byte budget")
    return canonical({"contract": "wucf-signed-push-v1", "scope": scope_value,
                      "collector": identifier(collector), "epoch": epoch,
                      "nonce": nonce, "body_sha256": digest(body)})


def sign(key, scope_value, collector, epoch, nonce, body):
    if not isinstance(key, bytes) or not 32 <= len(key) <= 128:
        raise ContractError("invalid signing key")
    return hmac.new(key, envelope(scope_value, collector, epoch, nonce, body),
                    hashlib.sha256).hexdigest()


class SignedPush:
    def __init__(self, inbox, collector, resolve_key, now):
        if type(inbox) is not DeliveryInbox:
            raise ContractError("local inbox required")
        self.inbox, self.collector = inbox, identifier(collector)
        self.resolve_key, self.now = resolve_key, now

    def accept(self, epoch, nonce, signature, body):
        """Accept exact retry, reject altered nonce reuse and stale signatures.

        Key resolution must bind environment, instance, dataset, revision,
        collector, credential generation and revocation state. No exceptions
        from the resolver are exposed. No secrets stored in the inbox.
        """
        if not isinstance(signature, str) or not SIGNATURE.fullmatch(signature):
            raise ContractError("invalid signature")
        payload = envelope(self.inbox.scope, self.collector, epoch, nonce, body)
        clock = self.now()
        if type(clock) is not int or not 0 <= clock < 2 ** 53 or abs(clock - epoch) > MAX_CLOCK_SKEW:
            raise ContractError("expired push envelope")
        try:
            key = self.resolve_key(dict(self.inbox.scope), self.collector)
            if not isinstance(key, bytes) or not 32 <= len(key) <= 128:
                raise ValueError()
            expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
        except Exception:
            raise ContractError("signing credential unavailable") from None
        if not hmac.compare_digest(signature, expected):
            raise ContractError("signature mismatch")
        try:
            records = json.loads(body.decode("utf-8"), object_pairs_hook=unique_object)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise ContractError("invalid push JSON") from exc
        if not isinstance(records, list) or not 1 <= len(records) <= MAX_PUSH_EVENTS:
            raise ContractError("invalid push batch")
        events = []
        for record in records:
            if (not isinstance(record, dict) or set(record) != {"id", "payload"}
                    or not isinstance(record["payload"], dict)):
                raise ContractError("invalid push record")
            event_id = identifier(record["id"])
            events.append({"id": digest(canonical(["push", self.collector, event_id])),
                           "payload": record["payload"]})
        # Bind raw body and timestamp separately from event payloads. Internal
        # receipt metadata must never be passed to native telemetry.
        delivery = digest(canonical(["push", self.collector, nonce]))
        return self.inbox.accept(delivery, events, identity_digest=digest(payload))
