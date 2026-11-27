# WUCF — Universal Connector Framework (development only)

Parent: izm1chael/wazuh-dashboard-plugins#18. Core trackers #1–#7.
Baseline: core 0a951d08bafdd194af395ca67d923ed706d3df07 (siem/rc2-base);
Dashboard 22901fa354f20616d4bc707003b4b8a115cfb3d9;
Indexer e2871f7d68ee46fef2b01e21d3261dc6ab411489.
No integration with the running stack, no installation or production activation.
These are isolated GPL-compatible development tools, not a shipped service.

## Initial RC2 source audit (exact core blobs)

| Path | Blob | Observation |
|---|---|---|
| api/api/spec/spec.yaml | d6fd7eb7d2978ce09ae3d262b2e873ec4f981b37 | RC2 REST authentication and remote management contract; inspect role and route registration before exposing any management action. |
| wodles/azure/azure-logs.py | b182bf3cd0e883e39c0fd5ce55f5f065b12350f5 | Existing Graph, Log Analytics and Storage entry points; preserve compatibility. |
| wodles/azure/azure_services/graph.py | 2033a36969da859e95c73450da24f53d8e4c7ec4 | Existing Graph collection and pagination URL checks; candidate for reuse after complete review. |
| wodles/azure/azure_utils.py | 0cf89154077b2e1037215d571ce58dce0d9d9dc3 | Unix datagram socket and send_message; socket success is not durable ingestion or WCS indexing acknowledgement. |
| wodles/aws/aws_s3.py | d6cd2941fff8110e8b8cd652808b259b638a2a19 | Existing AWS S3 and SQS dispatch; adapter audit required. |
| wodles/gcloud/gcloud.py | 030dfce358b6780a17e6769bf6726c84b87f09f6 | Existing Pub/Sub and GCS collection entry points. |
| wodles/gcloud/pubsub/subscriber.py | f44d7e5aea28964466aef27baa212dfd1149aba8 | Sends events before acknowledging Pub/Sub messages; durable downstream semantics must be established separately. |
| wodles/utils.py | b598ef717e8998450ea20eca24aa8507492df2d6 | Native queue path definition. |

This is a targeted initial audit, not proof of native end-to-end delivery. The
engine's exact RC2 ingress, supported event metadata, decoder/integration
binding, acknowledgement and security contracts remain a gate. Do not bypass
the engine with direct event-index writes. Reuse provider-specific existing
collectors and native content wherever their semantics permit it.

## Architecture and ownership

* Core: collection execution and native ingress adapter; narrowly scoped
  control API only after existing RBAC integration is validated.
* Dashboard: catalogue, permission-aware setup wizard, test/sample/preview,
  activation, pause, revoke, configuration versioning and health.
* Indexer: only necessary durable management/health storage and native
  authorization; no separate canonical event schema. WCS and native integration
  packages remain authoritative.
* WADE consumes source health and coverage, never secrets; SOC consumes
  findings and scope-authorized investigation data. Neither owns collection.

A packaged connector definition is declarative data, never user-executable
code. Initially use reviewed built-in transport/provider IDs and fixed egress
policies. The environment principal must be derived from authenticated
deployment context, not user-submitted tenant IDs. Secrets are opaque
references, never returned by read APIs or logged. Remote collector enrollment
must be short-lived, scoped and revocable; no default public listener.
Self-hosted and managed deployment use the same contracts with different
secret, scheduling and durable-state backends. Private Wazuh Cloud deployment
requires maintainer review, not merely a local tenant ID field.

## Delivery state machine

A trusted collector reads an approved dataset with bounded work and a durable
cursor. Stage an immutable pending page with event identities and next cursor
before attempting delivery. Retry the same pending page after an ambiguous
outcome. Commit the cursor only after a trusted sink has acknowledged the
exact page at the required durability level. The lab ledger uses an injected
acknowledgement contract; no existing native socket is assumed to satisfy it.
Repeated delivery is possible after failures; do not claim exactly once.
Provider identifiers, ordering, pagination and late arrivals need dedicated
contracts. Do not claim telemetry completeness from a successful empty poll.

Initial local SQLite reference state is for single-worker lab experiments only.
It is not an encrypted tenant store, distributed lease service or deployed
runtime. Production requires trusted provisioning, encrypted buffering, bounded
retention and quotas, fencing, crash recovery and sink idempotency/reconciliation.

## Qualification

Run standalone tests first. Then disposable pinned RC2 full builds and native
ingestion fixtures (including decoder failure, source identity, malformed events
and duplicate delivery), cross-environment RBAC/egress/secret tests, outage and
restart/failover, throughput, quota/fairness, retention, upgrade/rollback,
browser onboarding, accessibility, Docker integration and an upstream review
series. Keep every tracking issue open until its evidence is recorded.
