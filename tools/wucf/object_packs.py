"""Microsoft 365 content feed and CloudTrail S3/SQS reference adapters.

No SDK credentials or listeners. Injected clients must enforce account scope,
timeouts, byte bounds, TLS, approved egress and disabled redirects. Do not
acknowledge a queue receipt before all referenced objects are retained.
"""
import gzip
import io
import json
import re
from datetime import timedelta
from urllib.parse import unquote, unquote_plus, urlencode, urlsplit

from delivery_inbox import DeliveryInbox, MAX_UNIT_BYTES, MAX_UNIT_EVENTS
from graph import iso, stamp
from ledger import ContractError, canonical, digest
from windowed_packs import UUID, safe_url

M365_HOST = "manage.office.com"
CONTENT_TYPES = frozenset({"Audit.AzureActiveDirectory", "Audit.Exchange",
                           "Audit.SharePoint", "Audit.General", "DLP.All"})
MAX_CONTENTS = 100
MAX_COMPRESSED = 8 * 1024 * 1024
ACCOUNT = re.compile(r"[0-9]{12}", re.ASCII)
BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", re.ASCII)


def decode_json(raw, cap=MAX_UNIT_BYTES):
    if not isinstance(raw, bytes) or len(raw) > cap:
        raise ContractError("object byte budget")
    try:
        return json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise ContractError("invalid object JSON") from exc


def checked_text(value, limit):
    if (not isinstance(value, str) or not 1 <= len(value) <= limit
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ContractError("invalid object identity")
    return value


class Microsoft365Feed:
    """List one page, retain every content blob, then return next position.

    Caller persists window and page continuation only after successful return.
    If a process dies first, repeated blobs are idempotent in the inbox.
    No subscription creation; each content type is separately provisioned.
    """
    def __init__(self, tenant, publisher, content_type, transport, inbox):
        if (not all(isinstance(v, str) and UUID.fullmatch(v) for v in (tenant, publisher))
                or content_type not in CONTENT_TYPES or type(inbox) is not DeliveryInbox):
            raise ContractError("invalid M365 profile")
        self.tenant, self.publisher = tenant.lower(), publisher.lower()
        self.content_type, self.transport, self.inbox = content_type, transport, inbox
        self.prefix = f"/api/v1.0/{self.tenant}/activity/feed"
        self.list_path = self.prefix + "/subscriptions/content"

    def content_url(self, uri, content_id):
        checked_text(uri, 3000)
        if any(ord(c) < 33 or ord(c) > 126 for c in uri) or "\\" in uri:
            raise ContractError("invalid content URI")
        try:
            parts = urlsplit(uri)
        except ValueError as exc:
            raise ContractError("invalid content URI") from exc
        expected = self.prefix + "/audit/" + content_id
        if ((parts.scheme, parts.netloc) != ("https", M365_HOST)
                or unquote(parts.path) != expected or parts.fragment
                or "/" in content_id or "\\" in content_id or "%" in content_id):
            raise ContractError("unapproved content URI")
        # Reconstruct only the documented publisher parameter; don't forward
        # arbitrary query or credentials returned by an untrusted response.
        return f"https://{M365_HOST}{parts.path}?{urlencode({'PublisherIdentifier': self.publisher})}"

    def step(self, start, end, continuation=None):
        lower, upper = stamp(start), stamp(end)
        if not lower < upper <= lower + timedelta(hours=24):
            raise ContractError("invalid content availability window")
        if continuation is None:
            query = urlencode({"contentType": self.content_type,
                               "startTime": iso(lower), "endTime": iso(upper),
                               "PublisherIdentifier": self.publisher})
            url = f"https://{M365_HOST}{self.list_path}?{query}"
        else:
            url = safe_url(continuation, M365_HOST, self.list_path)
        # Transport returns body plus the single case-normalized NextPageUri
        # header or None; redirects and duplicate headers must be rejected.
        raw, following = self.transport.list_content(url, max_bytes=MAX_UNIT_BYTES, timeout_seconds=15)
        if following is not None:
            following = safe_url(following, M365_HOST, self.list_path)
            if following == url:
                raise ContractError("non-progressing content listing")
        entries = decode_json(raw)
        if not isinstance(entries, list) or len(entries) > MAX_CONTENTS:
            raise ContractError("content list budget")
        seen = set()
        # Validate all descriptors before any content request.
        descriptors = []
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("contentType") != self.content_type:
                raise ContractError("unexpected content type")
            cid = checked_text(entry.get("contentId"), 512)
            if cid in seen or not lower <= stamp(entry.get("contentCreated")) < upper:
                raise ContractError("invalid content descriptor")
            seen.add(cid)
            descriptors.append((cid, self.content_url(entry.get("contentUri"), cid)))
        receipts = []
        for cid, uri in descriptors:
            records = decode_json(self.transport.get(uri, max_bytes=MAX_UNIT_BYTES, timeout_seconds=15))
            if not isinstance(records, list) or len(records) > MAX_UNIT_EVENTS:
                raise ContractError("content record budget")
            events = []
            for record in records:
                if not isinstance(record, dict):
                    raise ContractError("invalid content record")
                organization = record.get("OrganizationId")
                if not isinstance(organization, str) or organization.lower() != self.tenant:
                    raise ContractError("content tenant mismatch")
                event = checked_text(record.get("Id"), 256)
                events.append({"id": digest(canonical(["m365", self.tenant, event])), "payload": record})
            key = digest(canonical(["m365", self.tenant, self.content_type, cid]))
            receipts.append(self.inbox.accept(key, events))
        return following, tuple(receipts)


def cloudtrail_records(raw, accounts):
    if not isinstance(raw, bytes) or len(raw) > MAX_COMPRESSED:
        raise ContractError("compressed object budget")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            body = stream.read(MAX_UNIT_BYTES + 1)
    except (OSError, EOFError) as exc:
        raise ContractError("invalid CloudTrail compression") from exc
    obj = decode_json(body)
    if (not isinstance(obj, dict) or not isinstance(obj.get("Records"), list)
            or len(obj["Records"]) > MAX_UNIT_EVENTS):
        raise ContractError("invalid CloudTrail record set")
    events = []
    for record in obj["Records"]:
        if not isinstance(record, dict) or record.get("recipientAccountId") not in accounts:
            raise ContractError("CloudTrail account mismatch")
        eid = checked_text(record.get("eventID"), 256)
        events.append({"id": digest(canonical(["cloudtrail", record["recipientAccountId"], eid])),
                       "payload": record})
    return events


class CloudTrailQueue:
    """Direct S3 notification via SQS. No SNS unwrap or destructive auto-DLQ.

    S3 client must use configured bucket and immutable versionId. Unversioned
    objects are deliberately unsupported by this reference: do not fetch the
    current mutable key and pretend it is the notification's exact object.
    """
    def __init__(self, bucket, prefix, accounts, objects, queue, inbox):
        if (not isinstance(bucket, str) or not BUCKET.fullmatch(bucket)
                or not isinstance(prefix, str) or not prefix.startswith("AWSLogs/")
                or not prefix.endswith("/") or len(prefix) > 256
                or not isinstance(accounts, (list, tuple)) or not 1 <= len(accounts) <= 100
                or any(not isinstance(a, str) or not ACCOUNT.fullmatch(a) for a in accounts)
                or type(inbox) is not DeliveryInbox):
            raise ContractError("invalid CloudTrail profile")
        self.bucket, self.prefix, self.accounts = bucket, prefix, frozenset(accounts)
        self.objects, self.queue, self.inbox = objects, queue, inbox

    def process(self, notification, receipt_handle):
        checked_text(receipt_handle, 4096)
        obj = decode_json(notification, 256 * 1024)
        records = obj.get("Records") if isinstance(obj, dict) else None
        if not isinstance(records, list) or not 1 <= len(records) <= 20:
            raise ContractError("invalid S3 notification")
        descriptors = []
        for record in records:
            try:
                if (record["eventSource"] != "aws:s3"
                        or not record["eventName"].startswith("ObjectCreated:")
                        or record["s3"]["bucket"]["name"] != self.bucket):
                    raise ContractError("notification scope mismatch")
                item = record["s3"]["object"]
                key = unquote_plus(checked_text(item["key"], 3072), errors="strict")
                version = checked_text(item["versionId"], 1024)
                if (not key.startswith(self.prefix) or not key.endswith(".json.gz")
                        or any(part in {"", ".", ".."} for part in key.split("/"))
                        or version == "null"):
                    raise ContractError("unsupported CloudTrail object")
                descriptors.append((key, version))
            except (KeyError, TypeError, AttributeError, UnicodeError) as exc:
                raise ContractError("invalid S3 notification") from exc
        receipts = []
        for key, version in descriptors:
            raw = self.objects.get_version(self.bucket, key, version, max_bytes=MAX_COMPRESSED)
            events = cloudtrail_records(raw, self.accounts)
            delivery = digest(canonical(["cloudtrail", self.bucket, key, version]))
            receipts.append(self.inbox.accept(delivery, events))
        # A crash or delete timeout may cause redelivery. All exact objects
        # remain in the inbox and retries are idempotent at this boundary.
        self.queue.delete(receipt_handle)
        return tuple(receipts)
