import unittest
from unittest.mock import Mock, patch

from entra_reference import prepare, run_reference
from ledger import ContractError

CONFIG = {"dataset": "signins", "credential_ref": "credential-a",
          "interval_seconds": 300, "tenant_id": "11111111-1111-1111-1111-111111111111",
          "client_id": "22222222-2222-2222-2222-222222222222",
          "initial": "2026-11-01T00:00:00Z", "lag_seconds": 600}


class EntraReferenceTests(unittest.TestCase):
    def test_collection_identity_changes_revision(self):
        original = prepare("env-a", "source-a", CONFIG)
        for key, value in (("tenant_id", "33333333-3333-3333-3333-333333333333"),
                           ("client_id", "33333333-3333-3333-3333-333333333333"),
                           ("dataset", "directory_audit"), ("credential_ref", "credential-b"),
                           ("interval_seconds", 600), ("lag_seconds", 900),
                           ("initial", "2026-11-02T00:00:00Z")):
            with self.subTest(key=key):
                changed = prepare("env-a", "source-a", {**CONFIG, key: value})
                self.assertNotEqual(original.source.revision, changed.source.revision)
        self.assertNotEqual(original.source.revision,
                            prepare("env-b", "source-a", CONFIG).source.revision)
        self.assertEqual(original, prepare("env-a", "source-a",
                         {**CONFIG, "initial": "2026-11-01T01:00:00+01:00"}))

    def test_extra_fields_and_unsupported_dataset_rejected(self):
        for changes in ({"environment": "forged"}, {"client_secret": "dummy"},
                        {"dataset": "users"}, {"tenant_id": "common"},
                        {"lag_seconds": True}, {"initial": "2026-11-01"}):
            with self.subTest(changes=changes), self.assertRaises(ContractError):
                prepare("env-a", "source-a", {**CONFIG, **changes})

    def test_mismatched_ledger_rejected_before_secret_or_transport(self):
        profile = prepare("env-a", "source-a", CONFIG)
        other = prepare("env-b", "source-a", CONFIG)
        ledger = Mock(scope=other.source.ledger_scope())
        secret = Mock()
        resolve = Mock()
        with self.assertRaises(ContractError):
            run_reference(profile, ledger, secret, resolve, Mock(), Mock())
        secret.assert_not_called()
        resolve.assert_not_called()

    @patch("entra_reference.run")
    @patch("entra_reference.GraphProvider")
    @patch("entra_reference.GraphHTTPS")
    @patch("entra_reference.MicrosoftTokenSupplier")
    def test_composition_uses_exact_scope_and_dataset(self, token, https, provider, run):
        profile = prepare("env-a", "source-a", CONFIG)
        ledger = Mock(scope=profile.source.ledger_scope())
        secret = Mock(return_value="dummy")
        resolve, clock, sink = Mock(), Mock(), Mock()
        result = run_reference(profile, ledger, secret, resolve, clock, sink, 2)
        self.assertIs(result, run.return_value)
        secret.assert_not_called()
        tenant, client, supplier = token.call_args.args
        self.assertEqual((tenant, client), (profile.tenant_id, profile.client_id))
        self.assertEqual(supplier(), "dummy")
        secret.assert_called_once_with("env-a", "source-a", "credential-a",
                                       profile.source.revision)
        https.assert_called_once_with("signins", resolve, token.return_value)
        provider.assert_called_once_with("signins", profile.initial, https.return_value,
                                         clock, lag_seconds=600)
        run.assert_called_once_with(ledger, provider.return_value, sink, max_pages=2)


if __name__ == "__main__":
    unittest.main()
