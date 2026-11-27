"""Reviewed built-in dataset catalogue; metadata only, not enabled adapters."""
from dataclasses import dataclass
from types import MappingProxyType

from ledger import ContractError, canonical, digest, identifier, scope


@dataclass(frozen=True)
class Dataset:
    provider: str
    dataset: str
    label: str
    credential_kind: str
    permissions: tuple[str, ...]
    native_candidate: str


_DATASETS = (
    Dataset("entra", "signins", "Entra sign-ins", "oauth_client",
            ("AuditLog.Read.All",), "azure"),
    Dataset("entra", "directory_audit", "Entra directory audit", "oauth_client",
            ("AuditLog.Read.All",), "azure"),
    Dataset("m365", "audit", "Microsoft 365 audit", "oauth_client",
            ("ActivityFeed.Read",), "review_required"),
    Dataset("azure", "activity", "Azure Activity", "oauth_client",
            ("Monitoring Reader (scope review required)",), "azure"),
    Dataset("aws", "cloudtrail", "AWS CloudTrail", "aws_role",
            ("s3:GetObject", "sqs:ReceiveMessage", "sqs:DeleteMessage"),
            "aws"),
    Dataset("google_workspace", "audit", "Google Workspace audit",
            "google_delegated",
            ("https://www.googleapis.com/auth/admin.reports.audit.readonly",),
            "review_required"),
)
CATALOGUE = MappingProxyType({(d.provider, d.dataset): d for d in _DATASETS})


@dataclass(frozen=True)
class Source:
    environment: str
    instance: str
    provider: str
    dataset: str
    credential_ref: str
    interval_seconds: int
    revision: str

    def ledger_scope(self):
        return scope(self.environment, self.instance, self.dataset, self.revision)


def provision(environment, instance, configuration):
    """Environment comes from trusted deployment provisioning, never a request.

    References are opaque identifiers, not credentials. This is validation,
    not an authorization or secret resolver. Catalogue permissions are starter
    guidance; provider-specific least-privilege verification remains required.
    """
    identifier(environment)
    identifier(instance)
    keys = {"provider", "dataset", "credential_ref", "interval_seconds"}
    if not isinstance(configuration, dict) or set(configuration) != keys:
        raise ContractError("unsupported configuration fields")
    provider = identifier(configuration["provider"])
    dataset = identifier(configuration["dataset"])
    if (provider, dataset) not in CATALOGUE:
        raise ContractError("unknown built-in dataset")
    reference = identifier(configuration["credential_ref"])
    interval = configuration["interval_seconds"]
    if type(interval) is not int or not 60 <= interval <= 86400:
        raise ContractError("invalid polling interval")
    revision = digest(canonical({"version": 1, "environment": environment,
                                 "instance": instance, **configuration}))
    return Source(environment, instance, provider, dataset, reference,
                  interval, revision)


def public_metadata(source):
    """Read-side representation deliberately omits the credential reference."""
    dataset = CATALOGUE[(source.provider, source.dataset)]
    return {"environment": source.environment, "instance": source.instance,
            "provider": source.provider, "dataset": source.dataset,
            "label": dataset.label, "revision": source.revision,
            "interval_seconds": source.interval_seconds,
            "qualification": "not_qualified", "activation_supported": False}
