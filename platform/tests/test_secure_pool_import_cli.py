import argparse
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "secure_pool_import", ROOT / "scripts" / "secure_pool_import.py"
)
assert SPEC is not None and SPEC.loader is not None
secure_pool_import = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = secure_pool_import
SPEC.loader.exec_module(secure_pool_import)


class SecurePoolImportCliTests(unittest.TestCase):
    @staticmethod
    def _args(**overrides: str) -> argparse.Namespace:
        values = {
            "pool_type": "card",
            "input_file": str((ROOT / "input.json").resolve()),
            "tenant_id": "tenant-1",
            "vault_address": "https://vault.example.test",
            "token_file": str((ROOT / "vault.token").resolve()),
            "receipt_output": str((ROOT / "receipt.json").resolve()),
            "audience": "email-platform:pool-import:production",
            "ca_file": None,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_card_parser_derives_last4_and_never_emits_pan_in_manifest(self) -> None:
        manifest, secret = secure_pool_import._card_record({
            "provider_ref": "provider-card-1",
            "pool_key": "checkout-cn",
            "region": "cn-east",
            "brand": "Visa",
            "pan": "4111 1111 1111 1111",
            "expiry_month": 12,
            "expiry_year": 2030,
        })
        self.assertEqual(manifest["last4"], "1111")
        self.assertNotIn("pan", manifest)
        self.assertEqual(secret["pan"], "4111111111111111")

    def test_card_parser_rejects_all_security_code_aliases(self) -> None:
        base = {
            "provider_ref": "provider-card-1",
            "brand": "Visa",
            "pan": "4111111111111111",
        }
        for name in ("cvv", "cvc", "cid", "security_code", "card_verification_value"):
            with self.subTest(name=name), self.assertRaises(
                secure_pool_import.ImportFailure
            ):
                secure_pool_import._card_record({**base, name: "123"})

    def test_parsers_reject_implicit_scalar_coercion(self) -> None:
        with self.assertRaises(secure_pool_import.ImportFailure):
            secure_pool_import._card_record({
                "provider_ref": "provider-card-1",
                "brand": "Visa",
                "pan": 4111111111111111,
            })
        with self.assertRaises(secure_pool_import.ImportFailure):
            secure_pool_import._card_record({
                "provider_ref": "provider-card-1",
                "brand": "Visa",
                "pan": "4111111111111111",
                "expiry_month": True,
                "expiry_year": 2030,
            })
        with self.assertRaises(secure_pool_import.ImportFailure):
            secure_pool_import._mailbox_record({
                "email_masked": "m***@example.test",
                "connector_type": 7,
                "secret": {"password": "private-password"},
            })

    def test_mailbox_parser_keeps_credentials_out_of_manifest(self) -> None:
        manifest, secret = secure_pool_import._mailbox_record({
            "email_masked": "M***@example.test",
            "connector_type": "http",
            "task_type": "mail_code",
            "secret": {"username": "private", "password": "private-password"},
        })
        self.assertEqual(manifest["email_masked"], "m***@example.test")
        self.assertNotIn("secret", manifest)
        self.assertEqual(secret["password"], "private-password")

    def test_vault_address_requires_https_origin(self) -> None:
        with self.assertRaises(secure_pool_import.ImportFailure):
            secure_pool_import.VaultClient("http://vault.example.test", "token", ca_file=None)
        with self.assertRaises(secure_pool_import.ImportFailure):
            secure_pool_import.VaultClient(
                "https://vault.example.test/path", "token", ca_file=None
            )

    def test_run_rejects_unusable_receipt_binding_before_reading_secrets(self) -> None:
        for field, value in (("tenant_id", " tenant-1"), ("audience", "")):
            with self.subTest(field=field), self.assertRaises(
                secure_pool_import.ImportFailure
            ):
                secure_pool_import.run(self._args(**{field: value}))

    def test_run_requires_ca_path_to_be_distinct_from_secret_inputs(self) -> None:
        token_file = str((ROOT / "vault.token").resolve())
        with self.assertRaises(secure_pool_import.ImportFailure):
            secure_pool_import.run(
                self._args(token_file=token_file, ca_file=token_file)
            )

    def test_run_requires_precreated_receipt_directory(self) -> None:
        output = ROOT / "missing-secure-import-output-directory" / "receipt.json"
        with self.assertRaises(secure_pool_import.ImportFailure):
            secure_pool_import.run(
                self._args(receipt_output=str(output.resolve()))
            )


if __name__ == "__main__":
    unittest.main()
