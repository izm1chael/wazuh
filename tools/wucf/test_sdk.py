import unittest

from ledger import ContractError, canonical, digest
from sdk import check_upgrade, describe, load, validate, verify_fixtures


class SdkTests(unittest.TestCase):
    def setUp(self):
        kinds = ["sample", "negative", "restart", "scope", "limit"]
        self.blobs = {kind: canonical({"kind": kind}) for kind in kinds}
        self.raw = {"schema_version": 1, "pack_id": "example", "version": "1.0.0",
                    "profile": "entra_signins", "content_revision": "a" * 64,
                    "permissions": ["AuditLog.Read.All"],
                    "compatibility": "wazuh-5.0.0-rc2-reference",
                    "fixtures": [{"id": kind, "kind": kind, "sha256": digest(self.blobs[kind])}
                                 for kind in kinds]}

    def test_strict_manifest_and_fixture_hashes(self):
        manifest = load(canonical(self.raw))
        self.assertEqual(manifest, validate(self.raw))
        self.assertEqual(verify_fixtures(manifest, self.blobs), manifest.revision)
        self.assertFalse(describe(manifest)["activation_supported"])
        with self.assertRaises(ContractError):
            verify_fixtures(manifest, {**self.blobs, "sample": b"changed"})

    def test_no_executable_or_arbitrary_transport(self):
        for bad in ({"url": "https://example.com"}, {"script": "x"},
                    {"profile": "my_custom_http"}, {"schema_version": True},
                    {"fixtures": self.raw["fixtures"][:-1]}):
            with self.assertRaises(ContractError):
                validate({**self.raw, **bad})

    def test_upgrade_requires_new_revision(self):
        old = validate(self.raw)
        new = validate({**self.raw, "version": "1.1.0"})
        self.assertEqual(check_upgrade(old, old), "unchanged")
        self.assertEqual(check_upgrade(old, new), "new_execution_revision_required")
        with self.assertRaises(ContractError):
            check_upgrade(new, old)
        with self.assertRaises(ContractError):
            check_upgrade(old, validate({**self.raw, "profile": "aws_cloudtrail", "version": "2.0.0"}))

    def test_duplicate_json_member(self):
        with self.assertRaises(ContractError):
            load(b'{"schema_version":1,"schema_version":1}')
