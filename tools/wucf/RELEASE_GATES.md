# WUCF consolidated acceptance ledger

Parent dashboard #18; core #1–#7, dashboard #19–#21. All acceptance
issues remain open. Personal forks only; no upstream submission or
production activation. This file is a qualification plan, not a pass receipt.

| Track | Reference implementation | Remaining mandatory gate |
|---|---|---|
| WUCF-01 | Pinned source audit; scope, catalogue, SDK, execution plan | Exact native RC2 engine/decoder/WCS integration and supported deployment architecture |
| WUCF-02 | Ledger, management scheduler, worker, local spool, object inbox | Persistent provider cursor/queue workers, hard deadlines, durable cooldown, fairness and cross-worker fencing; encrypted state, recovery and retention |
| WUCF-03 | Fixed-host Microsoft TLS/OAuth, mounted lab secret, profile allowlist, signed push and enrollment | Authenticated principal and role enforcement; all provider credentials, rotation/revocation, external egress/network controls, encrypted buffering and cross-tenant tests |
| WUCF-04 | Native ingress gate and local reconciliation ledger | Actual supported engine ingress, native decoder/WCS binding, durable evidence reader, event conservation and deduplication; no direct event-index writes |
| WUCF-05 | Unmounted Dashboard catalogue/setup and health panel | Native manager control API with RBAC; server-backed catalogue, write-only secret entry, connection tests/sample mapping and lifecycle; OSD browser/a11y |
| WUCF-06 | Advisory health, persisted lab observations and local reconciliation | One scope/revision-bound API contract for poll and object/push delivery, health persistence, event timestamp lag/parse/coverage and WADE publication |
| WUCF-07 | Six starter dataset adapters | Real provider clients, per-provider permissions, pagination/retention/cooldown, secure scheduling, live sample fixtures and native decoder proof |
| WUCF-08 | Signed push, enrollment, approved REST, immutable object and syslog relay references | Actual authenticated mTLS gateway, outbound relay service, encrypted offline buffering, device provisioning, provider transports and revocation/fault/load tests |
| WUCF-09 | Declarative reviewed SDK, upgrade guard and fixture digest verification | Versioned package inventory, real fixtures and admission receipts, docs generation, community review, expanded connector packs |
| WUCF-10 | Offline test receipt runner and test plan | Full pinned RC2 Docker build, local E2E/RBAC/isolation/fault/load tests, migration and restore, supported forward-port and upstream review series |

## Operator local validation

Check out the current draft commit from each personal fork. Run:
```sh
# From the core checkout root; put the receipt outside the checkout.
python3 tools/wucf/qualify.py > /tmp/wucf-offline-receipt.json
```
Review the receipt and stderr. A passing offline test receipt is not a
native or release qualification. The runner checks an unchanged Git head
and clean WUCF subtree, inventories source bytes and records test output
digest; it does not isolate malicious repository code. Use a disposable,
network-disabled container/VM with no credentials or production mounts.

Dashboard: run the native main plugin Jest suites for wucf-model and
wucf-health-model, lint, actual EUI/OSD 3.6.0 build and browser tests. The
two health model source blobs were strict-compiled and six standalone
Node assertions passed in one continuation session (model
bd248dfb72e68cd68f35c09dc9b5aebecb172a28, health model
3a278d4b1650ca1d8b58cb1a753188b03c8bbc54). That was not Jest or EUI
build execution. Verify all current combined core tests afresh.
 
## Release rule

No activation, native success/coverage claim, destructive retention or
upstream PR until the relevant gates pass. All local spool and inbox
receipts must remain explicitly local. Provider data and real credentials
must never be placed into unencrypted reference stores. Cloud SaaS
qualification requires maintainer review of managed infrastructure.
