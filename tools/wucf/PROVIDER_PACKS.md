# Provider and generic collection candidates

All code under tools/wucf is development-only, unregistered. The original
Entra Graph adapters use the checkpoint and local spool protocol. Azure
Activity and Workspace candidates use the same bounded page interface.
M365 and CloudTrail use a separate durable object inbox so queue/delete
acknowledgement is not confused with a poll cursor. Signed push and remote
relay use the same inbox with authenticated envelope identity.

## Provider specifics

* Azure Activity: subscription-scoped REST list API version 2015-04-01,
  inclusive eventTimestamp bounds and exact path continuations. Reference:
  https://learn.microsoft.com/en-us/rest/api/monitor/activity-logs/list
* Google Workspace: Admin SDK Reports activities.list, explicit customer
  and application, pageToken and inclusive timestamp bounds. Reference:
  https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list
* Microsoft 365: content availability windows, NextPageUri listing and
  separately fetched content blobs. Reference:
  https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference
* AWS CloudTrail: direct S3 event notification with immutable versionId,
  account allowlist, bounded gzip expansion, exact local object receipt
  before queue deletion. Reference:
  https://docs.aws.amazon.com/awscloudtrail/latest/userguide/using_processing_lib.html

These are API-shape candidates, not live provider conformance. Inclusive
window boundaries may duplicate records; downstream scoped stable identity
deduplication and delayed-arrival replay must be qualified. Azure/Google/
M365/CloudTrail clients are injected, not production OAuth/SDK adapters.
Large pages/objects, unversioned S3 objects, retention gaps and failed
descriptors fail closed. No automatic discard or destructive DLQ.

M365 listing continuation must be durably committed by a caller only
after every listed blob has been retained; this reference does not yet
supply the persistent listing scheduler, token refresh or subscription
management. CloudTrail requires S3 versioning and configured SQS/SDK
identity, receipt visibility extension, long polling, redrive/DLQ policy
and explicit provider-side permissions. No queue URL supplied by events.

## Generic and community packs

The SDK admits only fixed reviewed profile IDs. Manifests describe
compatibility, version, native content digest, prerequisites and hashed
fixture inventory; arbitrary URLs, scripts, imports and command fields
are rejected. A changed pack requires a new execution revision, not
automatic checkpoint migration. Fixture checks verify bytes, not results.

Signed batches bind trusted source scope, collector, timestamp, nonce
and exact body hash. Nonce conflicts fail closed, exact retries within
the time window are idempotent; signing context is separate from event
payloads. Enrollment tokens are single-use, short-lived and bound to an
out-of-band verified leaf certificate fingerprint. This is not a TLS
listener, a CA, a multi-tenant gateway, or an authorization boundary.
Authenticated TLS termination, credential rotation, encrypted offline
buffering, rate controls, revocation propagation and operator-approved
network deployment are required.

No raw syslog listener, arbitrary REST polling or generic object-store
adapter is enabled. Native Wazuh ingress, WCS mapping, deduplication,
encrypted spool/inbox drain, durable reconciliation and deployment remain
release gates. All health and receipts must label local durability as
local only; never represent it as successful WCS ingestion.
