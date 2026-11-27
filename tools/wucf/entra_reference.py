"""Compose the Entra reference adapters without service or activation registration."""
from dataclasses import dataclass, replace

from catalogue import Source, provision
from graph import GraphProvider, iso, stamp
from graph_transport import GraphHTTPS
from ledger import ContractError, canonical, digest
from microsoft_transport import MicrosoftTokenSupplier, UUID
from runtime import run


@dataclass(frozen=True)
class EntraProfile:
    source: Source
    tenant_id: str
    client_id: str
    initial: str
    lag_seconds: int


def prepare(environment, instance, configuration):
    """Trusted provisioning only; no authentication performed here.

    Native content version, credential generation and effective grants still
    require a separate deployment admission and rotation policy.
    """
    keys = {"dataset", "credential_ref", "interval_seconds", "tenant_id",
            "client_id", "initial", "lag_seconds"}
    if not isinstance(configuration, dict) or set(configuration) != keys:
        raise ContractError("invalid Entra configuration")
    dataset = configuration["dataset"]
    if dataset not in ("signins", "directory_audit"):
        raise ContractError("unsupported Entra dataset")
    tenant = configuration["tenant_id"]
    client = configuration["client_id"]
    if not all(isinstance(v, str) and UUID.fullmatch(v) for v in (tenant, client)):
        raise ContractError("invalid Microsoft identity configuration")
    lag = configuration["lag_seconds"]
    if type(lag) is not int or not 60 <= lag <= 86400:
        raise ContractError("invalid lag")
    initial = iso(stamp(configuration["initial"]))
    source = provision(environment, instance, {
        "provider": "entra", "dataset": dataset,
        "credential_ref": configuration["credential_ref"],
        "interval_seconds": configuration["interval_seconds"],
    })
    revision = digest(canonical({
        "contract": "entra-reference-v1", "source_revision": source.revision,
        "tenant_id": tenant.lower(), "client_id": client.lower(),
        "initial": initial, "lag_seconds": lag,
    }))
    return EntraProfile(replace(source, revision=revision), tenant.lower(),
                        client.lower(), initial, lag)


def run_reference(profile, ledger, resolve_secret, resolve_graph, now, sink,
                  max_pages=10):
    """Explicit lab invocation. No scheduler, durable native sink or auth included.

    resolve_secret receives environment, instance, credential reference and
    exact configuration fingerprint. The caller must enforce all of those
    dimensions, not simply look up a globally named secret. The Graph resolver
    must be bounded by the caller. Sink receipts remain injected assertions.
    """
    if not isinstance(profile, EntraProfile) or profile.source.provider != "entra":
        raise ContractError("invalid Entra profile")
    source = profile.source
    checked = prepare(source.environment, source.instance, {
        "dataset": source.dataset, "credential_ref": source.credential_ref,
        "interval_seconds": source.interval_seconds,
        "tenant_id": profile.tenant_id, "client_id": profile.client_id,
        "initial": profile.initial, "lag_seconds": profile.lag_seconds,
    })
    if checked != profile or ledger.scope != source.ledger_scope():
        raise ContractError("profile and ledger scope mismatch")
    token = MicrosoftTokenSupplier(profile.tenant_id, profile.client_id,
        lambda: resolve_secret(source.environment, source.instance,
                               source.credential_ref, source.revision))
    transport = GraphHTTPS(source.dataset, resolve_graph, token)
    provider = GraphProvider(source.dataset, profile.initial, transport, now,
                             lag_seconds=profile.lag_seconds)
    return run(ledger, provider, sink, max_pages=max_pages)
