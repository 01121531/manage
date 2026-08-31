import argparse
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.secure_pool_import_recovery import assess_execution_directory


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
            "execution_directory": str((ROOT / "secure-import-execution").resolve()),
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

    def test_mailbox_parser_rejects_pseudo_masked_addresses(self) -> None:
        for email_masked in (
            "alice@example.test*",
            "alice*@example.test",
            "ab***@example.test",
            "***@example.test",
            "a***@example.test/credential",
        ):
            with self.subTest(email_masked=email_masked), self.assertRaises(
                secure_pool_import.ImportFailure
            ):
                secure_pool_import._mailbox_record({
                    "email_masked": email_masked,
                    "connector_type": "http",
                    "task_type": "mail_code",
                    "secret": {"password": "private-password"},
                })

    def test_vault_address_requires_https_origin(self) -> None:
        with self.assertRaises(secure_pool_import.ImportFailure):
            secure_pool_import.VaultClient("http://vault.example.test", "token", ca_file=None)
        with self.assertRaises(secure_pool_import.ImportFailure):
            secure_pool_import.VaultClient(
                "https://vault.example.test/path", "token", ca_file=None
            )

    def test_vault_write_requires_exact_version_one_acknowledgement(self) -> None:
        client = secure_pool_import.VaultClient(
            "https://vault.example.test", "token", ca_file=None
        )
        secret_ref = "vault://secret/cards/imports/example/0"
        with patch.object(client, "post", return_value={"data": {"version": 1}}):
            client.write_secret(secret_ref, {"pan": "4111111111111111"})
        for response in (
            {},
            {"data": {}},
            {"data": {"version": True}},
            {"data": {"version": 2}},
        ):
            with self.subTest(response=response), patch.object(
                client, "post", return_value=response
            ), self.assertRaises(secure_pool_import.ImportFailure):
                client.write_secret(secret_ref, {"pan": "4111111111111111"})

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

    def test_generated_bundle_declares_version_and_exact_pool_type(self) -> None:
        class FakeVaultClient:
            def __init__(self, *_args: object, **_kwargs: object) -> None:
                pass

            def write_secret(self, _secret_ref: str, _secret: dict[str, object]) -> None:
                pass

            def sign(self, _pool_type: str, _payload: bytes) -> str:
                return "vault:v1:test-signature"

        records = {
            "card": [{
                "provider_ref": "provider-card-1",
                "pool_key": "checkout-cn",
                "region": "cn-east",
                "brand": "Visa",
                "pan": "4111111111111111",
            }],
            "mailbox": [{
                "email_masked": "m***@example.test",
                "connector_type": "http",
                "task_type": "mail_code",
                "secret": {"username": "private", "password": "private-password"},
            }],
        }
        for pool_type, source_records in records.items():
            with self.subTest(pool_type=pool_type), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                input_file = root / "input.json"
                token_file = root / "vault.token"
                receipt_output = root / "receipt.json"
                execution_directory = root / "execution"
                input_file.write_text(json.dumps(source_records), encoding="utf-8")
                token_file.write_text("test-vault-token", encoding="utf-8")
                with patch.object(secure_pool_import, "VaultClient", FakeVaultClient):
                    secure_pool_import.run(self._args(
                        pool_type=pool_type,
                        input_file=str(input_file.resolve()),
                        token_file=str(token_file.resolve()),
                        receipt_output=str(receipt_output.resolve()),
                        execution_directory=str(execution_directory.resolve()),
                    ))
                bundle = json.loads(receipt_output.read_text(encoding="utf-8"))
                self.assertEqual(set(bundle), {
                    "schema_version", "pool_type", "submission_key",
                    "receipt_token", "items",
                })
                self.assertEqual(bundle["schema_version"], 2)
                self.assertEqual(bundle["pool_type"], pool_type)
                self.assertRegex(
                    bundle["submission_key"],
                    r"^spi:[0-9a-f-]{36}$",
                )
                self.assertNotIn("test-vault-token", receipt_output.read_text())

    def test_execution_plan_and_attempt_precede_each_vault_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_file = root / "input.json"
            token_file = root / "vault.token"
            receipt_output = root / "receipt.json"
            execution_directory = root / "execution"
            input_file.write_text(json.dumps([
                {
                    "email_masked": "a***@example.test",
                    "connector_type": "http",
                    "secret": {"password": "first-private-password"},
                },
                {
                    "email_masked": "b***@example.test",
                    "connector_type": "http",
                    "secret": {"password": "second-private-password"},
                },
            ]), encoding="utf-8")
            token_file.write_text("test-vault-token", encoding="utf-8")

            class OrderedVaultClient:
                writes = 0

                def __init__(self, *_args: object, **_kwargs: object) -> None:
                    pass

                def write_secret(self, _secret_ref: str, _secret: dict[str, object]) -> None:
                    index = self.writes
                    self.assert_execution_state(index)
                    type(self).writes += 1

                @staticmethod
                def assert_execution_state(index: int) -> None:
                    self.assertTrue((execution_directory / "plan.json").is_file())
                    self.assertTrue(
                        (execution_directory / f"write-{index:03d}.intent.json").is_file()
                    )
                    if index:
                        self.assertTrue(
                            (execution_directory / f"write-{index - 1:03d}.confirmed.json").is_file()
                        )

                def sign(self, _pool_type: str, _payload: bytes) -> str:
                    return "vault:v1:test-signature"

            with patch.object(secure_pool_import, "VaultClient", OrderedVaultClient):
                secure_pool_import.run(self._args(
                    pool_type="mailbox",
                    input_file=str(input_file.resolve()),
                    token_file=str(token_file.resolve()),
                    receipt_output=str(receipt_output.resolve()),
                    execution_directory=str(execution_directory.resolve()),
                ))

            self.assertEqual(OrderedVaultClient.writes, 2)
            self.assertTrue((execution_directory / "write-001.confirmed.json").is_file())
            self.assertTrue((execution_directory / "complete.json").is_file())
            recovery = assess_execution_directory(
                execution_directory, receipt_output
            )
            self.assertEqual(recovery["status"], "completed")
            execution_text = "".join(
                path.read_text(encoding="ascii")
                for path in execution_directory.iterdir()
            )
            self.assertNotIn("first-private-password", execution_text)
            self.assertNotIn("second-private-password", execution_text)
            self.assertNotIn("test-vault-token", execution_text)

    def test_crash_after_vault_attempt_is_classified_commit_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_file = root / "input.json"
            token_file = root / "vault.token"
            receipt_output = root / "receipt.json"
            execution_directory = root / "execution"
            input_file.write_text(json.dumps([{
                "provider_ref": "provider-card-1",
                "brand": "Visa",
                "pan": "4111111111111111",
            }]), encoding="utf-8")
            token_file.write_text("test-vault-token", encoding="utf-8")

            class InterruptedVaultClient:
                def __init__(self, *_args: object, **_kwargs: object) -> None:
                    pass

                def write_secret(self, _secret_ref: str, _secret: dict[str, object]) -> None:
                    raise KeyboardInterrupt

                def sign(self, _pool_type: str, _payload: bytes) -> str:
                    raise AssertionError("sign must not run after an unknown Vault write")

            with patch.object(secure_pool_import, "VaultClient", InterruptedVaultClient):
                with self.assertRaises(KeyboardInterrupt):
                    secure_pool_import.run(self._args(
                        input_file=str(input_file.resolve()),
                        token_file=str(token_file.resolve()),
                        receipt_output=str(receipt_output.resolve()),
                        execution_directory=str(execution_directory.resolve()),
                    ))

            self.assertTrue((execution_directory / "plan.json").is_file())
            self.assertTrue(
                (execution_directory / "write-000.intent.json").is_file()
            )
            self.assertFalse((execution_directory / "write-000.confirmed.json").exists())
            recovery = assess_execution_directory(
                execution_directory, receipt_output
            )
            self.assertEqual(recovery["status"], "commit_unknown")
            self.assertEqual(recovery["phase"], "vault_write_commit_unknown")
            self.assertEqual(recovery["unknown_index"], 0)
            self.assertFalse(receipt_output.exists())
            execution_text = "".join(
                path.read_text(encoding="ascii")
                for path in execution_directory.iterdir()
            )
            self.assertNotIn("4111111111111111", execution_text)


if __name__ == "__main__":
    unittest.main()
