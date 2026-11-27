# WUCF qualification and handoff (development, not release)

## Standalone tests

From the exact core draft checkout:

```bash
cd tools/wucf
python3 -m compileall -q .
python3 -m unittest discover -s . -p 'test_*.py' -v
```

The original nine ledger tests were previously executed against their exact
blobs; all subsequent tests need fresh execution at the combined head.
These tests are local/fake-transport only. They use no real credentials.

For the Dashboard companion draft, use the pinned OpenSearch Dashboards
3.6.0/Wazuh 5.0 RC2 development environment and run the main plugin's Jest
suite targeting wucf-model.test.ts, lint, full plugin build, browser and
accessibility tests. Verify the EUI component under the actual platform,
not just a standalone TypeScript compiler.

## Gates that must remain closed

* Runtime: persistent scheduling and fairness, multi-worker leases with
  end-to-end fencing, bounded wall-clock cancellation, persisted retry
  classification and cooldown, resource quotas and safe recovery.
* Credentials: actual authenticated principal; tenant/account binding and
  secret generation/rotation; secure references and encrypted storage and
  buffering. Provisioning must bind source revision to provider account,
  trusted endpoint/profile version, initial/backfill policy, credential
  reference version and chosen delivery boundary. A caller cannot switch
  the boundary for an existing checkpoint. Lab prototypes do not enforce
  the full provisioning contract.
* Ingress: local spool receipt means local durable acceptance only, not WCS
  or native indexing. Prove supported engine ingress and downstream
  acknowledgement or reconciliation; no direct write to event indices.
  Implement encrypted spool drain, bounded retention, backpressure,
  reconciliation and deduplication by scoped event identity before enabling.
* Provider: Entra sign-ins and directory audits require real permission,
  filter, window completeness, late arrivals, token expiry and pagination
  fixtures. Graph fixed-host TLS candidate does not acquire OAuth tokens or
  implement hard total deadlines; injected resolver and token source must
  be deployment-controlled. Other catalogue datasets are metadata only.
  No real M365, Azure Activity, AWS or Google Workspace adapter yet.
* Onboarding: authenticated manager/API and Dashboard registration; test,
  sample, WCS preview, configuration revisions, pause/resume/revoke,
  write-only secret entry, health persistence and per-source read isolation.
* Generic connectors, remote gateway, SDK, deployment/upgrade/rollback and
  managed Wazuh Cloud review remain separate acceptance work.

Do not merge, deploy or submit upstream on the strength of these prototypes.
No production changes were made. Keep all issues open until evidence.
