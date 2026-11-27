# Local connector management and execution gate

Implemented in management.py, execution_plan.py and lab_worker.py; no service registration.
The worker is an explicit invocation using a trusted injected provider. Never use real
credentials or production events in the plaintext lab databases.

## Contract
- Scope-bound source registration, immutable configuration fingerprint, draft by default.
- Lab admission, pause, resume, review/reconcile and terminal revocation, with expected
  lifecycle version and transactional attributed audit.
- One outstanding reservation per environment database; oldest due eligible source
  wins. Persisted due time, bounded lifetime and worker/token checks; expired claim
  blocks further claims until operator attests that the old worker has stopped.
- Plan fingerprint covers provider configuration fingerprint, credential generation,
  content revision, scope, interval and the fixed local-spool boundary.
- Explicit worker checks claim before and after provider/spool work, and before
  completion. Real local ledger and spool compose with the existing coordinator.
- On spool quota failure, pending page stays retained; review required. On expiry
  or ambiguous completion, claim remains outstanding for manual reconciliation.

## Reproduce
From the exact checkout, in tools/wucf:
    python3 -m unittest -v test_management test_execution_plan test_lab_worker

16 tests passed on Python 3.13.5 with real SQLite databases and a mocked provider.
Exact committed blobs matched for the three implementation/test pairs and existing
ledger, spool and runtime dependencies. The full repository suite was not run.

## Limits and next gates
No authenticated API, vault implementation, provider-specific worker factory,
native ingress, dashboard registration, background worker or SaaS deployment.
Caller supplies trusted identity, evidence, clock, protected file paths and provider
binding. An execution-plan digest is not proof of actual credential generation,
content installation or source authorization. No automatic revision migration;
registering a different revision at the same source is rejected.
The worker does not implement hard cancellation, distributed leases or atomic
external fencing; duplicate invocation with a shared claim is outside the
single trusted worker contract. Expiry does not terminate a running process.
The lab uses one reservation per environment database, not a global quota.
A 128-source lifetime limit and 4096-entry audit capacity fail closed; audit
exhaustion can block recovery and requires a designed production retention path.
No automatic retries on provider failure because the present runtime does not
preserve the provider's Retry-After evidence. Native WCS acceptance, encrypted
buffering, authenticated role isolation, credential rotation, receipt reconciliation,
bounded retry, crash/kill and load tests remain mandatory before activation.
