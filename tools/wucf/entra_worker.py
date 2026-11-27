"""Bind the Entra reference profile to the managed local-spool worker."""
from entra_reference import EntraProfile, prepare as prepare_profile
from execution_plan import validate
from graph import GraphProvider
from graph_transport import GraphHTTPS
from ledger import ContractError
from microsoft_transport import MicrosoftTokenSupplier
from mounted_secret import MountedSecret


def provider_factory(profile, reader, resolve_graph, now):
    """Build an exact-plan provider factory, without reading a secret yet.

    Trusted provisioning supplies the account, resolver, clock and mounted grant.
    No native delivery, activation API or background scheduling is introduced.
    """
    if not isinstance(profile, EntraProfile) or type(reader) is not MountedSecret:
        raise ContractError('invalid Entra worker configuration')
    source = profile.source
    checked = prepare_profile(source.environment, source.instance, {
        'dataset': source.dataset, 'credential_ref': source.credential_ref,
        'interval_seconds': source.interval_seconds, 'tenant_id': profile.tenant_id,
        'client_id': profile.client_id, 'initial': profile.initial,
        'lag_seconds': profile.lag_seconds,
    })
    if checked != profile:
        raise ContractError('invalid Entra profile fingerprint')

    def build(plan):
        plan = validate(plan)
        if (plan.environment, plan.instance, plan.dataset, plan.provider_revision, plan.interval) != (
                source.environment, source.instance, source.dataset, source.revision, source.interval_seconds):
            raise ContractError('provider plan mismatch')
        # Reader independently checks the exact plan and reference on each fetch.
        token = MicrosoftTokenSupplier(profile.tenant_id, profile.client_id,
                                       lambda: reader.resolve(plan, source.credential_ref))
        transport = GraphHTTPS(source.dataset, resolve_graph, token)
        return GraphProvider(source.dataset, profile.initial, transport, now,
                             lag_seconds=profile.lag_seconds)

    return build
