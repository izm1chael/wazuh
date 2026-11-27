"""Declarative connector pack SDK: reviewed built-ins only, no dynamic imports.

Manifest data describes prerequisites and fixture contracts, not executable
code. Transport endpoints and native content are bound by the reviewed
adapter/provisioning layer. A manifest alone never authorizes activation.
"""
import json
import re
from dataclasses import dataclass
from types import MappingProxyType

from ledger import ContractError, canonical, digest, identifier

MAX_MANIFEST_BYTES = 32768
MAX_FIXTURE_BYTES = 1024 * 1024
VERSION = re.compile(r"(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})", re.ASCII)
REVISION = re.compile(r"[a-f0-9]{64}", re.ASCII)
PROFILES = MappingProxyType({
    "entra_signins": ("entra", "signins", "oauth_client", "local_spool"),
    "entra_directory_audit": ("entra", "directory_audit", "oauth_client", "local_spool"),
    "azure_activity": ("azure", "activity", "oauth_client", "local_spool"),
    "workspace_reports": ("google_workspace", "audit", "google_delegated", "local_spool"),
    "m365_feed": ("m365", "audit", "oauth_client", "local_inbox"),
    "aws_cloudtrail": ("aws", "cloudtrail", "aws_role", "local_inbox"),
    "signed_push": ("generic", "signed_push", "scoped_signing_key", "local_inbox"),
    "remote_relay": ("generic", "remote_relay", "certificate_and_signing_key", "local_inbox"),
})
KINDS = frozenset({"sample", "negative", "restart", "scope", "limit"})


@dataclass(frozen=True)
class Manifest:
    pack_id: str
    version: str
    profile: str
    provider: str
    dataset: str
    credential_kind: str
    boundary: str
    content_revision: str
    permissions: tuple[str, ...]
    fixtures: tuple[tuple[str, str, str], ...]
    revision: str


def text(value, limit):
    if (not isinstance(value, str) or not 1 <= len(value) <= limit
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ContractError("invalid manifest text")
    return value


def sha(value):
    if not isinstance(value, str) or not REVISION.fullmatch(value):
        raise ContractError("invalid manifest digest")
    return value


def version(value):
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        raise ContractError("invalid semantic version")
    return tuple(int(n) for n in value.split("."))


def validate(value):
    keys = {"schema_version", "pack_id", "version", "profile", "content_revision",
            "permissions", "fixtures", "compatibility"}
    if not isinstance(value, dict) or set(value) != keys:
        raise ContractError("invalid manifest shape")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ContractError("unsupported manifest schema")
    if value["compatibility"] != "wazuh-5.0.0-rc2-reference":
        raise ContractError("unsupported compatibility target")
    pack = identifier(value["pack_id"])
    version(value["version"])
    profile = identifier(value["profile"])
    if profile not in PROFILES:
        raise ContractError("unreviewed adapter profile")
    content = sha(value["content_revision"])
    permissions = value["permissions"]
    if not isinstance(permissions, list) or not 1 <= len(permissions) <= 64:
        raise ContractError("invalid prerequisites")
    permissions = tuple(text(permission, 256) for permission in permissions)
    if len(set(permissions)) != len(permissions):
        raise ContractError("duplicate prerequisites")
    fixtures = value["fixtures"]
    if not isinstance(fixtures, list) or not 1 <= len(fixtures) <= 64:
        raise ContractError("invalid fixtures")
    parsed = []
    seen = set()
    kinds = set()
    for fixture in fixtures:
        if not isinstance(fixture, dict) or set(fixture) != {"id", "kind", "sha256"}:
            raise ContractError("invalid fixture declaration")
        fid = identifier(fixture["id"])
        kind = identifier(fixture["kind"])
        if fid in seen or kind not in KINDS:
            raise ContractError("invalid fixture identity or kind")
        seen.add(fid)
        kinds.add(kind)
        parsed.append((fid, kind, sha(fixture["sha256"])))
    if kinds != KINDS:
        raise ContractError("incomplete required fixture coverage")
    raw = canonical(value)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ContractError("manifest byte budget")
    return Manifest(pack, value["version"], profile, *PROFILES[profile], content,
                    permissions, tuple(parsed), digest(raw))


def load(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_MANIFEST_BYTES:
        raise ContractError("manifest byte budget")
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ContractError("duplicate manifest member")
            out[key] = value
        return out
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ContractError("invalid manifest JSON") from exc
    return validate(value)


def check_upgrade(old, new):
    """No in-place checkpoint reuse. Return explicit reviewed transition need."""
    if not isinstance(old, Manifest) or not isinstance(new, Manifest):
        raise ContractError("validated manifests required")
    if old.pack_id != new.pack_id or old.profile != new.profile:
        raise ContractError("incompatible pack identity")
    if old.revision == new.revision:
        return "unchanged"
    if version(new.version) <= version(old.version):
        raise ContractError("non-increasing pack version")
    return "new_execution_revision_required"


def verify_fixtures(manifest, blobs):
    """Verify fixture inventory and exact bytes, not fixture test outcomes."""
    if not isinstance(manifest, Manifest) or not isinstance(blobs, dict):
        raise ContractError("invalid fixture inventory")
    expected = {fid: checksum for fid, _, checksum in manifest.fixtures}
    if set(blobs) != set(expected):
        raise ContractError("fixture inventory mismatch")
    for fid, raw in blobs.items():
        if not isinstance(raw, bytes) or len(raw) > MAX_FIXTURE_BYTES or digest(raw) != expected[fid]:
            raise ContractError("fixture integrity or size mismatch")
    return manifest.revision


def describe(manifest):
    """Machine-readable documentation; all activation status is explicit."""
    if not isinstance(manifest, Manifest):
        raise ContractError("validated manifest required")
    return {"pack_id": manifest.pack_id, "version": manifest.version,
            "provider": manifest.provider, "dataset": manifest.dataset,
            "credential_kind": manifest.credential_kind,
            "candidate_permissions": list(manifest.permissions),
            "delivery_boundary": manifest.boundary,
            "revision": manifest.revision, "native_delivery_qualified": False,
            "activation_supported": False}
