"""Immutable lab execution plan; binds source identity to exact delivery semantics."""
from dataclasses import dataclass

from ledger import ContractError, canonical, digest, identifier, scope
from management import fingerprint


@dataclass(frozen=True)
class ExecutionPlan:
    environment: str
    instance: str
    dataset: str
    provider_revision: str
    credential_generation: str
    content_revision: str
    interval: int
    revision: str
    boundary: str = "local_spool"

    def ledger_scope(self):
        return scope(self.environment, self.instance, self.dataset, self.revision)


def prepare(environment, instance, dataset, provider_revision,
            credential_generation, content_revision, interval):
    """All inputs come from trusted provisioning; digests are not attestations.

    A changed credential generation or content revision produces a new plan.
    No automatic cursor migration, secret material or native approval here.
    """
    for value in (environment, instance, dataset, credential_generation):
        identifier(value)
    fingerprint(provider_revision)
    fingerprint(content_revision)
    if type(interval) is not int or not 60 <= interval <= 86400:
        raise ContractError("invalid interval")
    body = {"contract": "wucf-local-spool-v1", "environment": environment,
            "instance": instance, "dataset": dataset, "provider_revision": provider_revision,
            "credential_generation": credential_generation, "content_revision": content_revision,
            "interval": interval, "boundary": "local_spool"}
    return ExecutionPlan(environment, instance, dataset, provider_revision,
                         credential_generation, content_revision, interval, digest(canonical(body)))


def validate(plan):
    if not isinstance(plan, ExecutionPlan):
        raise ContractError("invalid execution plan")
    expected = prepare(plan.environment, plan.instance, plan.dataset, plan.provider_revision,
                       plan.credential_generation, plan.content_revision, plan.interval)
    if plan != expected:
        raise ContractError("execution plan mismatch")
    return expected


def register(management, plan, actor, now):
    plan = validate(plan)
    if management.environment != plan.environment:
        raise ContractError("management scope mismatch")
    return management.register(plan.instance, plan.dataset, plan.revision, plan.interval, actor, now)


def bind_claim(plan, claim, ledger, spool):
    """Validate exact identities before constructing provider or resolving secrets.

    This is not proof of current lease ownership or external fencing. The
    trusted caller must separately validate the live claim and ensure the old
    worker cannot continue before reconciliation. No network or writes here.
    """
    plan = validate(plan)
    expected = {"environment": plan.environment, "instance": plan.instance,
                "dataset": plan.dataset, "revision": plan.revision, "interval": plan.interval,
                "boundary": plan.boundary, "state": "ready"}
    if not isinstance(claim, dict) or any(claim.get(k) != v for k, v in expected.items()):
        raise ContractError("claim scope mismatch")
    fingerprint(claim.get("lease"))
    if (type(claim.get("version")) is not int or claim["version"] < 1
            or type(claim.get("expiry")) is not int or claim["expiry"] != claim.get("claim_expiry")):
        raise ContractError("invalid claim metadata")
    if ledger.scope != plan.ledger_scope() or spool.scope != plan.ledger_scope():
        raise ContractError("delivery state scope mismatch")
    return plan.ledger_scope()
