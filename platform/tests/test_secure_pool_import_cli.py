import argparse
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from scripts.secure_pool_import_recovery import assess_execution_directory


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "secure_pool_import", ROOT / "scripts" / "secure_pool_import.py"
)
assert SPEC is not None and SPEC.loader is not None
secure_pool_import = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = secure_pool_import
SPEC.loader.exec_module(secure_pool_import)
READ_PLATFORM_ACCESS_TOKEN = secure_pool_import._read_platform_access_token
PRIVATE_FILE_PERMISSION_FINGERPRINT = (
    secure_pool_import._private_file_permission_fingerprint
)


class SecurePoolImportCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.receipt_id = str(uuid4())

        def issue_context(
            _client: object,
            pool_type: str,
            digest: str,
            item_count: int,
        ) -> object:
            context = secure_pool_import.PoolImportContext(
                schema_version=1,
                context_token="c" * 43,
                receipt_id=self.receipt_id,
                tenant_id="tenant-1",
                audience="email-platform:pool-import:production",
                pool_type=pool_type,
                ordered_manifest_digest=digest,
                item_count=item_count,
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            )
            self.issued_context = context
            return context

        def renew_context(_client: object, context_token: str) -> object:
            self.assertEqual(context_token, self.issued_context.context_token)
            return replace(
                self.issued_context,
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            )

        self.platform_context_patch = patch.object(
            secure_pool_import.PlatformClient,
            "issue_context",
            new=issue_context,
        )
        self.platform_token_patch = patch.object(
            secure_pool_import,
            "_read_platform_access_token",
            return_value="platform-access-token",
        )
        self.platform_renewal_patch = patch.object(
            secure_pool_import.PlatformClient,
            "renew_context",
            new=renew_context,
        )
        self.vault_approle_patch = patch.object(
            secure_pool_import,
            "_read_vault_approle_token",
            return_value="test-vault-token",
        )
        self.private_permissions_patch = patch.object(
            secure_pool_import,
            "_private_file_permission_fingerprint",
            return_value="test-private-permissions",
        )
        self.platform_context_patch.start()
        self.platform_token_patch.start()
        self.platform_renewal_patch.start()
        self.vault_approle_patch.start()
        self.private_permissions_patch.start()

    def tearDown(self) -> None:
        self.private_permissions_patch.stop()
        self.vault_approle_patch.stop()
        self.platform_renewal_patch.stop()
        self.platform_token_patch.stop()
        self.platform_context_patch.stop()

    @staticmethod
    def _args(**overrides: str) -> argparse.Namespace:
        values = {
            "pool_type": "card",
            "input_file": str((ROOT / "input.json").resolve()),
            "reissue_from": None,
            "platform_address": "https://platform.example.test",
            "platform_token_file": str((ROOT / "platform.token").resolve()),
            "expected_tenant_id": "tenant-1",
            "expected_audience": "email-platform:pool-import:production",
            "vault_address": "https://vault.example.test",
            "approle_role_id_file": str((ROOT / "vault.role-id").resolve()),
            "approle_secret_id_file": str((ROOT / "vault.secret-id").resolve()),
            "receipt_output": str((ROOT / "receipt.json").resolve()),
            "execution_directory": str((ROOT / "secure-import-execution").resolve()),
            "ca_file": None,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    @staticmethod
    def _parser_arguments(*credentials: str) -> list[str]:
        return [
            "card",
            "--input-file", str((ROOT / "input.json").resolve()),
            "--platform-address", "https://platform.example.test",
            "--platform-token-file", str((ROOT / "platform.token").resolve()),
            "--expected-tenant-id", "tenant-1",
            "--expected-audience", "email-platform:pool-import:production",
            "--vault-address", "https://vault.example.test",
            *credentials,
            "--receipt-output", str((ROOT / "receipt.json").resolve()),
            "--execution-directory", str((ROOT / "execution").resolve()),
        ]

    def test_parser_requires_separate_approle_files_and_retires_token_file(self) -> None:
        parsed = secure_pool_import.build_parser().parse_args(
            self._parser_arguments(
                "--approle-role-id-file", str((ROOT / "vault.role-id").resolve()),
                "--approle-secret-id-file", str((ROOT / "vault.secret-id").resolve()),
            )
        )
        self.assertIsNone(getattr(parsed, "token_file", None))
        self.assertEqual(parsed.approle_role_id_file, str((ROOT / "vault.role-id").resolve()))
        with self.assertRaises(SystemExit):
            secure_pool_import.build_parser().parse_args(
                self._parser_arguments(
                    "--approle-role-id-file", str((ROOT / "vault.role-id").resolve()),
                    "--approle-secret-id-file", str((ROOT / "vault.secret-id").resolve()),
                    "--token-file", str((ROOT / "vault.token").resolve()),
                )
            )

    @staticmethod
    def _approle_response(**auth_overrides: object) -> bytes:
        auth = {
            "client_token": "vault-service-token",
            "policies": ["email-platform-card-importer"],
            "token_policies": ["email-platform-card-importer"],
            "identity_policies": [],
            "lease_duration": 900,
            "token_type": "service",
            "orphan": True,
            "num_uses": 0,
            "metadata": {"role_name": "email-platform-card-importer"},
        }
        auth.update(auth_overrides)
        return json.dumps({"auth": auth}).encode("utf-8")

    @staticmethod
    def _approle_opener(
        response_body: bytes,
        captured: dict[str, object],
        *,
        revoke_status: int = 204,
        revoke_body: bytes = b"",
    ) -> object:
        class FakeResponse:
            def __init__(self, body: bytes, status: int) -> None:
                self.body = body
                self.status = status

            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, *_args: object) -> None:
                pass

            def read(self, _limit: int) -> bytes:
                return self.body

            def getcode(self) -> int:
                return self.status

        class FakeOpener:
            def open(self, request: object, timeout: int) -> FakeResponse:
                if request.full_url.endswith("/v1/auth/approle/login"):
                    captured["request"] = request
                    captured["timeout"] = timeout
                    return FakeResponse(response_body, 200)
                captured["revocation_request"] = request
                captured["revocation_timeout"] = timeout
                return FakeResponse(revoke_body, revoke_status)

        return FakeOpener()

    def test_approle_exchange_posts_credentials_and_keeps_token_in_memory(self) -> None:
        captured: dict[str, object] = {}
        opener = self._approle_opener(self._approle_response(), captured)
        with patch.object(secure_pool_import.urllib.request, "build_opener", return_value=opener):
            token = secure_pool_import._exchange_approle_token(
                "https://vault.example.test",
                role_id="role-id-value",
                secret_id="single-use-secret-id",
                expected_role="email-platform-card-importer",
                expected_policy="email-platform-card-importer",
                tls_context=None,
            )

        self.assertEqual(token, "vault-service-token")
        request = captured["request"]
        self.assertEqual(request.full_url, "https://vault.example.test/v1/auth/approle/login")
        self.assertEqual(request.method, "POST")
        self.assertEqual(captured["timeout"], 20)
        self.assertEqual(
            json.loads(request.data),
            {"role_id": "role-id-value", "secret_id": "single-use-secret-id"},
        )
        self.assertNotIn("x-vault-token", {name.lower() for name, _ in request.header_items()})

    def test_approle_exchange_rejects_identity_or_lease_drift_without_secret_leak(self) -> None:
        invalid_responses = (
            {"policies": ["email-platform-mailbox-importer"]},
            {"token_policies": ["email-platform-card-importer", "default"]},
            {"identity_policies": ["unexpected-identity-policy"]},
            {"lease_duration": 901},
            {"token_type": "batch"},
            {"orphan": False},
            {"num_uses": 1},
            {"metadata": {"role_name": "email-platform-mailbox-importer"}},
        )
        for overrides in invalid_responses:
            with self.subTest(overrides=overrides):
                opener = self._approle_opener(self._approle_response(**overrides), {})
                with patch.object(
                    secure_pool_import.urllib.request,
                    "build_opener",
                    return_value=opener,
                ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
                    secure_pool_import._exchange_approle_token(
                        "https://vault.example.test",
                        role_id="sensitive-role-id",
                        secret_id="sensitive-secret-id",
                        expected_role="email-platform-card-importer",
                        expected_policy="email-platform-card-importer",
                        tls_context=None,
                    )
                message = str(raised.exception)
                self.assertEqual(message, "Vault AppRole response is invalid")
                self.assertNotIn("sensitive-role-id", message)
                self.assertNotIn("sensitive-secret-id", message)
                self.assertNotIn("vault-service-token", message)

    def test_approle_identity_drift_revokes_an_issued_safe_token(self) -> None:
        captured: dict[str, object] = {}
        opener = self._approle_opener(
            self._approle_response(
                policies=["email-platform-mailbox-importer"],
            ),
            captured,
        )
        with patch.object(
            secure_pool_import.urllib.request,
            "build_opener",
            return_value=opener,
        ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
            secure_pool_import._exchange_approle_token(
                "https://vault.example.test",
                role_id="sensitive-role-id",
                secret_id="sensitive-secret-id",
                expected_role="email-platform-card-importer",
                expected_policy="email-platform-card-importer",
                tls_context=None,
            )

        self.assertEqual(str(raised.exception), "Vault AppRole response is invalid")
        request = captured["revocation_request"]
        self.assertEqual(
            request.full_url,
            "https://vault.example.test/v1/auth/token/revoke-self",
        )
        self.assertEqual(request.method, "POST")
        self.assertEqual(captured["revocation_timeout"], 20)
        self.assertEqual(request.get_header("X-vault-token"), "vault-service-token")

    def test_approle_validation_error_stays_primary_when_revoke_is_unconfirmed(
        self,
    ) -> None:
        captured: dict[str, object] = {}
        opener = self._approle_opener(
            self._approle_response(token_type="batch"),
            captured,
            revoke_status=500,
        )
        with patch.object(
            secure_pool_import.urllib.request,
            "build_opener",
            return_value=opener,
        ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
            secure_pool_import._exchange_approle_token(
                "https://vault.example.test",
                role_id="sensitive-role-id",
                secret_id="sensitive-secret-id",
                expected_role="email-platform-card-importer",
                expected_policy="email-platform-card-importer",
                tls_context=None,
            )

        self.assertEqual(str(raised.exception), "Vault AppRole response is invalid")
        self.assertEqual(
            raised.exception.__notes__,
            [secure_pool_import._REVOCATION_FAILURE_NOTE],
        )
        self.assertNotIn("vault-service-token", str(raised.exception))
        self.assertIn("revocation_request", captured)

    def test_approle_never_sends_an_invalid_token_as_a_revocation_header(self) -> None:
        for invalid_token in ("unsafe token", "\ud800", "\x00", "non-ascii-é"):
            with self.subTest(invalid_token=ascii(invalid_token)):
                captured: dict[str, object] = {}
                opener = self._approle_opener(
                    self._approle_response(client_token=invalid_token),
                    captured,
                )
                with patch.object(
                    secure_pool_import.urllib.request,
                    "build_opener",
                    return_value=opener,
                ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
                    secure_pool_import._exchange_approle_token(
                        "https://vault.example.test",
                        role_id="sensitive-role-id",
                        secret_id="sensitive-secret-id",
                        expected_role="email-platform-card-importer",
                        expected_policy="email-platform-card-importer",
                        tls_context=None,
                    )

                self.assertEqual(
                    str(raised.exception),
                    "Vault AppRole response is invalid",
                )
                self.assertNotIn("revocation_request", captured)

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

    def test_duplicate_card_provider_refs_fail_before_platform_or_vault_use(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_file = root / "input.json"
            receipt_output = root / "receipt.json"
            execution_directory = root / "execution"
            input_file.write_text(
                json.dumps(
                    [
                        {
                            "provider_ref": "provider-duplicate",
                            "brand": "Visa",
                            "pan": "4111111111111111",
                        },
                        {
                            "provider_ref": "provider-duplicate",
                            "brand": "Mastercard",
                            "pan": "5555555555554444",
                        },
                    ]
                ),
                encoding="utf-8",
            )

            with patch.object(
                secure_pool_import,
                "_read_platform_access_token",
                side_effect=AssertionError("platform token must not be read"),
            ) as read_platform_token, patch.object(
                secure_pool_import,
                "VaultClient",
                side_effect=AssertionError("Vault client must not be created"),
            ), self.assertRaisesRegex(
                secure_pool_import.ImportFailure,
                "^Card input contains duplicate provider references$",
            ):
                secure_pool_import.run(
                    self._args(
                        input_file=str(input_file.resolve()),
                        receipt_output=str(receipt_output.resolve()),
                        execution_directory=str(execution_directory.resolve()),
                    )
                )

            read_platform_token.assert_not_called()
            self.assertFalse(receipt_output.exists())
            self.assertFalse(execution_directory.exists())

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
            secure_pool_import.VaultClient(
                "http://vault.example.test", "token", tls_context=None
            )
        with self.assertRaises(secure_pool_import.ImportFailure):
            secure_pool_import.VaultClient(
                "https://vault.example.test/path", "token", tls_context=None
            )

    def test_malformed_origins_use_fixed_secret_free_errors(self) -> None:
        cases = (
            (
                secure_pool_import._vault_origin,
                "https://[private-vault-origin-detail",
                "Vault address must be an HTTPS origin",
            ),
            (
                secure_pool_import._platform_origin,
                "https://platform.example.test:private-port-detail",
                "Platform address must be an HTTPS origin",
            ),
            (
                secure_pool_import._platform_origin,
                "https://:443",
                "Platform address must be an HTTPS origin",
            ),
            (
                secure_pool_import._platform_origin,
                "https://platform.example.test:0",
                "Platform address must be an HTTPS origin",
            ),
            (
                secure_pool_import._platform_origin,
                "\thttps://platform.example.test ",
                "Platform address must be an HTTPS origin",
            ),
        )
        for validator, value, expected in cases:
            with self.subTest(value=value):
                with self.assertRaises(secure_pool_import.ImportFailure) as raised:
                    validator(value)
                self.assertEqual(str(raised.exception), expected)
                self.assertNotIn("private", str(raised.exception))

    def test_vault_write_requires_exact_version_one_acknowledgement(self) -> None:
        client = secure_pool_import.VaultClient(
            "https://vault.example.test", "token", tls_context=None
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

    def test_vault_token_self_revocation_requires_empty_204_and_clears_memory(self) -> None:
        captured: dict[str, object] = {}

        class FakeResponse:
            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, *_args: object) -> None:
                pass

            @staticmethod
            def getcode() -> int:
                return 204

            @staticmethod
            def read(_limit: int) -> bytes:
                return b""

        class FakeOpener:
            @staticmethod
            def open(request: object, timeout: int) -> FakeResponse:
                captured["request"] = request
                captured["timeout"] = timeout
                return FakeResponse()

        client = secure_pool_import.VaultClient(
            "https://vault.example.test", "short-lived-token", tls_context=None
        )
        client.opener = FakeOpener()
        client.revoke_self()

        request = captured["request"]
        self.assertEqual(
            request.full_url,
            "https://vault.example.test/v1/auth/token/revoke-self",
        )
        self.assertEqual(request.method, "POST")
        self.assertEqual(captured["timeout"], 20)
        self.assertEqual(request.get_header("X-vault-token"), "short-lived-token")
        self.assertEqual(client.token, "")

    def test_vault_token_self_revocation_is_a_noop_without_an_issued_token(
        self,
    ) -> None:
        class RejectingOpener:
            @staticmethod
            def open(*_args: object, **_kwargs: object) -> object:
                raise AssertionError("empty token must not reach the network")

        client = secure_pool_import.VaultClient(
            "https://vault.example.test", "", tls_context=None
        )
        client.opener = RejectingOpener()

        client.revoke_self()

        self.assertEqual(client.token, "")

    def test_vault_token_self_revocation_rejects_ambiguous_acknowledgement(self) -> None:
        class FakeResponse:
            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, *_args: object) -> None:
                pass

            @staticmethod
            def getcode() -> int:
                return 200

            @staticmethod
            def read(_limit: int) -> bytes:
                return b"{}"

        class FakeOpener:
            @staticmethod
            def open(_request: object, timeout: int) -> FakeResponse:
                return FakeResponse()

        client = secure_pool_import.VaultClient(
            "https://vault.example.test", "short-lived-token", tls_context=None
        )
        client.opener = FakeOpener()
        with self.assertRaises(secure_pool_import.ImportFailure) as raised:
            client.revoke_self()
        self.assertEqual(
            str(raised.exception),
            "Vault token revocation acknowledgement is invalid",
        )
        self.assertEqual(client.token, "")

    def test_revocation_still_runs_when_intent_evidence_cannot_be_written(self) -> None:
        class FakeVaultClient:
            revocations = 0

            def revoke_self(self) -> None:
                type(self).revocations += 1

        with patch.object(
            secure_pool_import,
            "build_execution_event",
            return_value={},
        ), patch.object(
            secure_pool_import,
            "_write_execution_record",
            side_effect=secure_pool_import.ImportFailure(
                "Execution record publication failed"
            ),
        ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
            secure_pool_import._revoke_import_token(
                FakeVaultClient(),
                execution_directory=ROOT,
                plan={},
            )

        self.assertEqual(FakeVaultClient.revocations, 1)
        self.assertEqual(
            str(raised.exception),
            "Vault token revocation evidence is unconfirmed",
        )

    def test_context_mismatch_fails_before_vault_token_or_execution_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_file = root / "input.json"
            platform_token_file = root / "platform.token"
            vault_token_file = root / "vault.token"
            receipt_output = root / "receipt.json"
            execution_directory = root / "execution"
            input_file.write_text(json.dumps([{
                "provider_ref": "provider-card-1",
                "brand": "Visa",
                "pan": "4111111111111111",
            }]), encoding="utf-8")
            platform_token_file.write_text("platform-access-token", encoding="utf-8")
            vault_token_file.write_text("vault-token-must-not-be-read", encoding="utf-8")
            receipt_id = str(uuid4())
            valid = secure_pool_import.PoolImportContext(
                schema_version=1,
                context_token="c" * 43,
                receipt_id=receipt_id,
                tenant_id="tenant-1",
                audience="email-platform:pool-import:production",
                pool_type="card",
                ordered_manifest_digest=secure_pool_import.pool_import_digest(
                    "card",
                    [{
                        "provider_ref": "provider-card-1",
                        "pool_key": "legacy-unclassified",
                        "region": "legacy-unclassified",
                        "brand": "Visa",
                        "last4": "1111",
                        "expiry_month": None,
                        "expiry_year": None,
                    }],
                ),
                item_count=1,
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            )
            mismatches = (
                replace(valid, tenant_id="tenant-2"),
                replace(valid, audience="email-platform:pool-import:staging"),
                replace(valid, pool_type="mailbox"),
                replace(valid, ordered_manifest_digest="0" * 64),
                replace(valid, item_count=2),
            )
            for context in mismatches:
                with self.subTest(context=context), patch.object(
                    secure_pool_import.PlatformClient,
                    "issue_context",
                    return_value=context,
                ), patch.object(
                    secure_pool_import,
                    "_read_vault_approle_token",
                    side_effect=AssertionError("Vault AppRole files must not be read"),
                ), patch.object(
                    secure_pool_import,
                    "VaultClient",
                    side_effect=AssertionError("Vault client must not be created"),
                ), self.assertRaises(secure_pool_import.ImportFailure):
                    secure_pool_import.run(self._args(
                        input_file=str(input_file.resolve()),
                        platform_token_file=str(platform_token_file.resolve()),
                        approle_secret_id_file=str(vault_token_file.resolve()),
                        receipt_output=str(receipt_output.resolve()),
                        execution_directory=str(execution_directory.resolve()),
                    ))
                self.assertFalse(execution_directory.exists())
                self.assertFalse(receipt_output.exists())

    def test_raw_pool_input_hardlink_fails_before_remote_or_local_mutation(self) -> None:
        records = {
            "card": [{
                "provider_ref": "provider-card-1",
                "brand": "Visa",
                "pan": "4111111111111111",
            }],
            "mailbox": [{
                "email_masked": "m***@example.test",
                "connector_type": "http",
                "secret": {"password": "private-password"},
            }],
        }
        for pool_type, source_records in records.items():
            with self.subTest(pool_type=pool_type), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                input_file = root / "input.json"
                input_alias = root / "retained-input.json"
                receipt_output = root / "receipt.json"
                execution_directory = root / "execution"
                input_file.write_text(json.dumps(source_records), encoding="utf-8")
                try:
                    os.link(input_file, input_alias)
                except OSError as error:
                    self.skipTest(f"hard links unavailable: {error}")

                with patch.object(
                    secure_pool_import.PlatformClient,
                    "issue_context",
                    side_effect=AssertionError("Platform must not be called"),
                ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
                    secure_pool_import.run(self._args(
                        pool_type=pool_type,
                        input_file=str(input_file.resolve()),
                        receipt_output=str(receipt_output.resolve()),
                        execution_directory=str(execution_directory.resolve()),
                    ))

                self.assertEqual(
                    str(raised.exception),
                    "Input file is unavailable or invalid",
                )
                self.assertFalse(execution_directory.exists())
                self.assertFalse(receipt_output.exists())

    def test_platform_token_hardlink_fails_before_remote_or_local_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_file = root / "input.json"
            platform_token_file = root / "platform.token"
            platform_token_alias = root / "retained-platform.token"
            receipt_output = root / "receipt.json"
            execution_directory = root / "execution"
            input_file.write_text(json.dumps([{
                "provider_ref": "provider-card-1",
                "brand": "Visa",
                "pan": "4111111111111111",
            }]), encoding="utf-8")
            platform_token_file.write_text("platform-access-token", encoding="utf-8")
            try:
                os.link(platform_token_file, platform_token_alias)
            except OSError as error:
                self.skipTest(f"hard links unavailable: {error}")

            with patch.object(
                secure_pool_import,
                "_read_platform_access_token",
                new=READ_PLATFORM_ACCESS_TOKEN,
            ), patch.object(
                secure_pool_import.PlatformClient,
                "issue_context",
                side_effect=AssertionError("Platform must not be called"),
            ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
                secure_pool_import.run(self._args(
                    input_file=str(input_file.resolve()),
                    platform_token_file=str(platform_token_file.resolve()),
                    receipt_output=str(receipt_output.resolve()),
                    execution_directory=str(execution_directory.resolve()),
                ))

            self.assertEqual(
                str(raised.exception),
                "Platform access token file is unavailable",
            )
            self.assertFalse(execution_directory.exists())
            self.assertFalse(receipt_output.exists())

    def test_raw_input_link_or_reparse_path_fails_before_remote_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_file = root / "input.json"
            receipt_output = root / "receipt.json"
            execution_directory = root / "execution"
            input_file.write_text(json.dumps([{
                "provider_ref": "provider-card-1",
                "brand": "Visa",
                "pan": "4111111111111111",
            }]), encoding="utf-8")

            with patch.object(
                secure_pool_import,
                "has_link_or_reparse_ancestor",
                return_value=True,
                create=True,
            ), patch.object(
                secure_pool_import.PlatformClient,
                "issue_context",
                side_effect=secure_pool_import.ImportFailure("later stage reached"),
            ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
                secure_pool_import.run(self._args(
                    input_file=str(input_file.resolve()),
                    receipt_output=str(receipt_output.resolve()),
                    execution_directory=str(execution_directory.resolve()),
                ))

            self.assertEqual(
                str(raised.exception),
                "Input file is unavailable or invalid",
            )
            self.assertFalse(execution_directory.exists())
            self.assertFalse(receipt_output.exists())

    def test_platform_token_link_or_reparse_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "platform.token"
            path.write_text("platform-access-token", encoding="utf-8")
            with patch.object(
                secure_pool_import,
                "has_link_or_reparse_ancestor",
                return_value=True,
                create=True,
            ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
                READ_PLATFORM_ACCESS_TOKEN(path)

            self.assertEqual(
                str(raised.exception),
                "Platform access token file is unavailable",
            )

    def test_platform_token_path_alias_drift_after_read_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "platform.token"
            path.write_text("platform-access-token", encoding="utf-8")
            with patch.object(
                secure_pool_import,
                "has_link_or_reparse_ancestor",
                side_effect=(False, True),
            ) as aliases, self.assertRaises(
                secure_pool_import.ImportFailure
            ) as raised:
                READ_PLATFORM_ACCESS_TOKEN(path)

            self.assertEqual(aliases.call_count, 2)
            self.assertEqual(
                str(raised.exception),
                "Platform access token file is unavailable",
            )

    def test_approle_link_or_reparse_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "role-id"
            path.write_text("private-role-id", encoding="utf-8")
            with patch.object(
                secure_pool_import,
                "has_link_or_reparse_ancestor",
                return_value=True,
                create=True,
            ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
                secure_pool_import._read_approle_value(path)

            self.assertEqual(
                str(raised.exception),
                "Vault AppRole credential file is unavailable",
            )

    def test_raw_input_permission_failure_precedes_remote_or_local_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_file = root / "input.json"
            receipt_output = root / "receipt.json"
            execution_directory = root / "execution"
            input_file.write_text(json.dumps([{
                "provider_ref": "provider-card-1",
                "brand": "Visa",
                "pan": "4111111111111111",
            }]), encoding="utf-8")

            with patch.object(
                secure_pool_import,
                "_private_file_permission_fingerprint",
                side_effect=OSError,
                create=True,
            ) as permissions, patch.object(
                secure_pool_import.PlatformClient,
                "issue_context",
                side_effect=AssertionError("Platform must not be called"),
            ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
                secure_pool_import.run(self._args(
                    input_file=str(input_file.resolve()),
                    receipt_output=str(receipt_output.resolve()),
                    execution_directory=str(execution_directory.resolve()),
                ))

            self.assertEqual(
                str(raised.exception),
                "Input file is unavailable or invalid",
            )
            self.assertEqual(permissions.call_count, 1)
            self.assertFalse(execution_directory.exists())
            self.assertFalse(receipt_output.exists())

    def test_platform_token_permission_failure_precedes_remote_or_local_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_file = root / "input.json"
            platform_token_file = root / "platform.token"
            receipt_output = root / "receipt.json"
            execution_directory = root / "execution"
            input_file.write_text(json.dumps([{
                "provider_ref": "provider-card-1",
                "brand": "Visa",
                "pan": "4111111111111111",
            }]), encoding="utf-8")
            platform_token_file.write_text("platform-access-token", encoding="utf-8")

            with patch.object(
                secure_pool_import,
                "_private_file_permission_fingerprint",
                side_effect=("private", "private", OSError()),
                create=True,
            ) as permissions, patch.object(
                secure_pool_import,
                "_read_platform_access_token",
                new=READ_PLATFORM_ACCESS_TOKEN,
            ), patch.object(
                secure_pool_import.PlatformClient,
                "issue_context",
                side_effect=AssertionError("Platform must not be called"),
            ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
                secure_pool_import.run(self._args(
                    input_file=str(input_file.resolve()),
                    platform_token_file=str(platform_token_file.resolve()),
                    receipt_output=str(receipt_output.resolve()),
                    execution_directory=str(execution_directory.resolve()),
                ))

            self.assertEqual(
                str(raised.exception),
                "Platform access token file is unavailable",
            )
            self.assertEqual(permissions.call_count, 3)
            self.assertFalse(execution_directory.exists())
            self.assertFalse(receipt_output.exists())

    def test_posix_platform_token_rejects_group_or_other_permissions(self) -> None:
        def metadata(mode: int) -> os.stat_result:
            return os.stat_result((stat.S_IFREG | mode, 0, 0, 1, 0, 0, 21, 0, 0, 0))

        for mode in (0o640, 0o604, 0o644):
            with self.subTest(mode=oct(mode)):
                with patch.object(
                    secure_pool_import.os,
                    "name",
                    "posix",
                ), patch.object(
                    secure_pool_import,
                    "has_link_or_reparse_ancestor",
                    return_value=False,
                ), patch.object(
                    secure_pool_import,
                    "read_stable_runtime_bytes_with_metadata",
                    return_value=(b"platform-access-token", metadata(mode)),
                ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
                    READ_PLATFORM_ACCESS_TOKEN(Path("/private/platform.token"))

                self.assertEqual(
                    str(raised.exception),
                    "Platform access token file is unavailable",
                )

        with patch.object(
            secure_pool_import.os,
            "name",
            "posix",
        ), patch.object(
            secure_pool_import,
            "has_link_or_reparse_ancestor",
            return_value=False,
        ), patch.object(
            secure_pool_import,
            "read_stable_runtime_bytes_with_metadata",
            return_value=(b"platform-access-token", metadata(0o600)),
        ):
            self.assertEqual(
                READ_PLATFORM_ACCESS_TOKEN(Path("/private/platform.token")),
                "platform-access-token",
            )

    def test_approle_permission_failure_precedes_credential_use(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "role-id"
            path.write_text("private-role-id", encoding="utf-8")
            with patch.object(
                secure_pool_import,
                "_private_file_permission_fingerprint",
                side_effect=OSError,
                create=True,
            ) as permissions, self.assertRaises(
                secure_pool_import.ImportFailure
            ) as raised:
                secure_pool_import._read_approle_value(path)

            self.assertEqual(
                str(raised.exception),
                "Vault AppRole credential file is unavailable",
            )
            self.assertEqual(permissions.call_count, 1)

    def test_windows_private_permission_adapter_is_handle_bound_and_redacted(
        self,
    ) -> None:
        metadata = object()
        fingerprint = object()
        with patch.object(
            secure_pool_import.os,
            "name",
            "nt",
        ), patch.object(
            secure_pool_import,
            "validate_private_file_permissions",
            return_value=fingerprint,
        ) as validate:
            self.assertIs(
                PRIVATE_FILE_PERMISSION_FINGERPRINT(17, metadata),
                fingerprint,
            )
        validate.assert_called_once_with(17, metadata)

        with patch.object(
            secure_pool_import.os,
            "name",
            "nt",
        ), patch.object(
            secure_pool_import,
            "validate_private_file_permissions",
            side_effect=secure_pool_import.BackupCryptoError(
                "private ACL detail"
            ),
        ), self.assertRaises(OSError) as raised:
            PRIVATE_FILE_PERMISSION_FINGERPRINT(17, metadata)
        self.assertNotIn("private ACL detail", str(raised.exception))

    def test_run_requires_ca_path_to_be_distinct_from_secret_inputs(self) -> None:
        role_id_file = str((ROOT / "vault.role-id").resolve())
        with self.assertRaises(secure_pool_import.ImportFailure):
            secure_pool_import.run(
                self._args(
                    approle_role_id_file=role_id_file,
                    ca_file=role_id_file,
                )
            )

    def test_raw_import_path_resolution_failure_is_fixed_and_precedes_remote_use(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            arguments = self._args(
                input_file=str(root / "input.json"),
                platform_token_file=str(root / "platform.token"),
                approle_role_id_file=str(root / "role-id"),
                approle_secret_id_file=str(root / "secret-id"),
                receipt_output=str(root / "receipt.json"),
                execution_directory=str(root / "execution"),
            )
            with patch.object(
                Path,
                "resolve",
                side_effect=RuntimeError("private raw path detail"),
            ), patch.object(
                secure_pool_import.PlatformClient,
                "issue_context",
                side_effect=AssertionError("Platform must not be called"),
            ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
                secure_pool_import.run(arguments)

            self.assertEqual(
                str(raised.exception),
                "Input, AppRole, platform token, CA, and receipt output paths "
                "must be separate",
            )
            self.assertNotIn("private raw path detail", str(raised.exception))
            self.assertFalse((root / "execution").exists())
            self.assertFalse((root / "receipt.json").exists())

    def test_raw_import_validates_origins_before_ca_or_private_input(self) -> None:
        cases = (
            (
                {"platform_address": "http://private-platform-origin-detail"},
                "Platform address must be an HTTPS origin",
            ),
            (
                {"vault_address": "https://vault.example.test:private-port-detail"},
                "Vault address must be an HTTPS origin",
            ),
        )
        for overrides, expected in cases:
            with self.subTest(overrides=overrides), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                arguments = self._args(
                    input_file=str(root / "input.json"),
                    platform_token_file=str(root / "platform.token"),
                    approle_role_id_file=str(root / "role-id"),
                    approle_secret_id_file=str(root / "secret-id"),
                    receipt_output=str(root / "receipt.json"),
                    execution_directory=str(root / "execution"),
                    **overrides,
                )
                with patch.object(
                    secure_pool_import,
                    "_create_tls_context",
                    side_effect=AssertionError("CA must not be loaded"),
                ), patch.object(
                    secure_pool_import,
                    "_read_json",
                    side_effect=AssertionError("Private input must not be read"),
                ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
                    secure_pool_import.run(arguments)

                self.assertEqual(str(raised.exception), expected)
                self.assertNotIn("private", str(raised.exception))
                self.assertFalse((root / "execution").exists())
                self.assertFalse((root / "receipt.json").exists())

    def test_raw_import_rejects_shared_security_origin_before_private_use(self) -> None:
        cases = (
            (
                "https://shared-origin.example.test",
                "https://shared-origin.example.test",
            ),
            (
                "https://SHARED-ORIGIN.example.test/",
                "https://shared-origin.example.test:443",
            ),
            (
                "https://shared-origin.example.test.",
                "https://SHARED-ORIGIN.example.test:443/",
            ),
            (
                "https://b\u00fccher.example.test",
                "https://xn--bcher-kva.example.test:443/",
            ),
        )
        for platform_address, vault_address in cases:
            with self.subTest(
                platform_address=platform_address,
                vault_address=vault_address,
            ), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                arguments = self._args(
                    input_file=str(root / "input.json"),
                    platform_address=platform_address,
                    platform_token_file=str(root / "platform.token"),
                    vault_address=vault_address,
                    approle_role_id_file=str(root / "role-id"),
                    approle_secret_id_file=str(root / "secret-id"),
                    receipt_output=str(root / "receipt.json"),
                    execution_directory=str(root / "execution"),
                )
                with patch.object(
                    secure_pool_import,
                    "_create_tls_context",
                    side_effect=AssertionError("CA must not be loaded"),
                ), patch.object(
                    secure_pool_import,
                    "_read_json",
                    side_effect=AssertionError("Private input must not be read"),
                ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
                    secure_pool_import.run(arguments)

                self.assertEqual(
                    str(raised.exception),
                    "Platform and Vault addresses must use separate HTTPS origins",
                )
                self.assertFalse((root / "execution").exists())
                self.assertFalse((root / "receipt.json").exists())

    def test_different_effective_ports_remain_separate_security_origins(self) -> None:
        secure_pool_import._require_separate_security_origins(
            "https://shared-host.example.test:8443",
            "https://shared-host.example.test:443",
        )

    def test_custom_ca_link_alias_fails_before_private_or_remote_use(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_file = root / "input.json"
            ca_file = root / "ca.pem"
            input_file.write_text(
                json.dumps([{
                    "provider_ref": "provider-ca-alias",
                    "brand": "Visa",
                    "pan": "4111111111111111",
                }]),
                encoding="utf-8",
            )
            ca_file.write_text("private trust path detail", encoding="ascii")
            original_read_json = secure_pool_import._read_json
            input_reads = 0

            def observed_read_json(*args: object, **kwargs: object) -> object:
                nonlocal input_reads
                input_reads += 1
                return original_read_json(*args, **kwargs)

            default_context = secure_pool_import.ssl.create_default_context()
            with patch.object(
                secure_pool_import,
                "has_link_or_reparse_ancestor",
                side_effect=lambda path: Path(path) == ca_file,
            ), patch.object(
                secure_pool_import,
                "_read_json",
                new=observed_read_json,
            ), patch.object(
                secure_pool_import.ssl,
                "create_default_context",
                return_value=default_context,
            ), patch.object(
                secure_pool_import.PlatformClient,
                "issue_context",
                side_effect=secure_pool_import.ImportFailure("remote use reached"),
            ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
                secure_pool_import.run(self._args(
                    input_file=str(input_file.resolve()),
                    ca_file=str(ca_file.resolve()),
                    receipt_output=str((root / "receipt.json").resolve()),
                    execution_directory=str((root / "execution").resolve()),
                ))

            self.assertEqual(str(raised.exception), "CA file is unavailable or invalid")
            self.assertNotIn("private trust path detail", str(raised.exception))
            self.assertEqual(input_reads, 0)
            self.assertFalse((root / "execution").exists())
            self.assertFalse((root / "receipt.json").exists())

    def test_custom_ca_path_drift_after_read_fails_before_remote_use(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_file = root / "input.json"
            ca_file = root / "ca.pem"
            input_file.write_text(
                json.dumps([{
                    "provider_ref": "provider-ca-drift",
                    "brand": "Visa",
                    "pan": "4111111111111111",
                }]),
                encoding="utf-8",
            )
            ca_file.write_text("stable ca snapshot", encoding="ascii")
            ca_checks = 0

            def path_alias_observed(path: Path) -> bool:
                nonlocal ca_checks
                if Path(path) != ca_file:
                    return False
                ca_checks += 1
                return ca_checks == 2

            default_context = secure_pool_import.ssl.create_default_context()
            with patch.object(
                secure_pool_import,
                "has_link_or_reparse_ancestor",
                side_effect=path_alias_observed,
            ), patch.object(
                secure_pool_import.ssl,
                "create_default_context",
                return_value=default_context,
            ), patch.object(
                secure_pool_import.PlatformClient,
                "issue_context",
                side_effect=secure_pool_import.ImportFailure("remote use reached"),
            ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
                secure_pool_import.run(self._args(
                    input_file=str(input_file.resolve()),
                    ca_file=str(ca_file.resolve()),
                    receipt_output=str((root / "receipt.json").resolve()),
                    execution_directory=str((root / "execution").resolve()),
                ))

            self.assertEqual(str(raised.exception), "CA file is unavailable or invalid")
            self.assertEqual(ca_checks, 2)
            self.assertFalse((root / "execution").exists())
            self.assertFalse((root / "receipt.json").exists())

    def test_custom_ca_is_loaded_from_one_stable_in_memory_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            ca_file = Path(temp_dir) / "ca.pem"
            ca_file.write_text("reviewed ca snapshot", encoding="ascii")
            tls_context = object()
            with patch.object(
                secure_pool_import.ssl,
                "create_default_context",
                return_value=tls_context,
            ) as create_context:
                result = secure_pool_import._create_tls_context(ca_file)

            self.assertIs(result, tls_context)
            create_context.assert_called_once_with(cadata="reviewed ca snapshot")

    def test_invalid_custom_ca_has_one_fixed_public_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            ca_file = Path(temp_dir) / "ca.pem"
            ca_file.write_text("private invalid CA detail", encoding="ascii")

            with self.assertRaises(secure_pool_import.ImportFailure) as raised:
                secure_pool_import._create_tls_context(ca_file)

            self.assertEqual(str(raised.exception), "CA file is unavailable or invalid")
            self.assertNotIn("private invalid CA detail", str(raised.exception))

    def test_custom_ca_hardlink_alias_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            ca_file = root / "ca.pem"
            ca_alias = root / "ca-alias.pem"
            ca_file.write_text("reviewed ca snapshot", encoding="ascii")
            os.link(ca_file, ca_alias)

            with self.assertRaises(secure_pool_import.ImportFailure) as raised:
                secure_pool_import._create_tls_context(ca_file)

            self.assertEqual(str(raised.exception), "CA file is unavailable or invalid")

    def test_one_tls_context_is_reused_for_platform_vault_and_approle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_file = root / "input.json"
            ca_file = root / "ca.pem"
            receipt_output = root / "receipt.json"
            execution_directory = root / "execution"
            input_file.write_text(
                json.dumps([{
                    "provider_ref": "provider-ca-context",
                    "brand": "Visa",
                    "pan": "4111111111111111",
                }]),
                encoding="utf-8",
            )
            ca_file.write_text("reviewed ca snapshot", encoding="ascii")
            tls_context = object()
            observed_contexts: list[object] = []

            def capture_platform_context(
                _client: object,
                _addr: str,
                _access_token: str,
                *,
                tls_context: object,
            ) -> None:
                observed_contexts.append(tls_context)

            class FakeVaultClient:
                def __init__(
                    self,
                    _addr: str,
                    token: str,
                    *,
                    tls_context: object,
                ) -> None:
                    self.token = token
                    observed_contexts.append(tls_context)

                def write_secret(
                    self,
                    _secret_ref: str,
                    _secret: dict[str, object],
                ) -> None:
                    pass

                def sign(self, _pool_type: str, _payload: bytes) -> str:
                    return "vault:v1:test-signature"

                def revoke_self(self) -> None:
                    self.token = ""

            def read_approle(*_args: object, **kwargs: object) -> str:
                observed_contexts.append(kwargs["tls_context"])
                return "test-vault-token"

            with patch.object(
                secure_pool_import,
                "_create_tls_context",
                return_value=tls_context,
            ) as create_context, patch.object(
                secure_pool_import.PlatformClient,
                "__init__",
                new=capture_platform_context,
            ), patch.object(
                secure_pool_import,
                "VaultClient",
                FakeVaultClient,
            ), patch.object(
                secure_pool_import,
                "_read_vault_approle_token",
                new=read_approle,
            ):
                secure_pool_import.run(self._args(
                    input_file=str(input_file.resolve()),
                    ca_file=str(ca_file.resolve()),
                    receipt_output=str(receipt_output.resolve()),
                    execution_directory=str(execution_directory.resolve()),
                ))

            create_context.assert_called_once_with(ca_file)
            self.assertEqual(observed_contexts, [tls_context, tls_context, tls_context])

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

            def revoke_self(self) -> None:
                pass

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
                        approle_secret_id_file=str(token_file.resolve()),
                        receipt_output=str(receipt_output.resolve()),
                        execution_directory=str(execution_directory.resolve()),
                    ))
                bundle = json.loads(receipt_output.read_text(encoding="utf-8"))
                self.assertEqual(set(bundle), {
                    "schema_version", "pool_type", "submission_key",
                    "context_token", "receipt_token", "items",
                })
                self.assertEqual(bundle["schema_version"], 3)
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

                def revoke_self(self) -> None:
                    pass

            with patch.object(secure_pool_import, "VaultClient", OrderedVaultClient):
                secure_pool_import.run(self._args(
                    pool_type="mailbox",
                    input_file=str(input_file.resolve()),
                    approle_secret_id_file=str(token_file.resolve()),
                    receipt_output=str(receipt_output.resolve()),
                    execution_directory=str(execution_directory.resolve()),
                ))

            self.assertEqual(OrderedVaultClient.writes, 2)
            self.assertTrue((execution_directory / "write-001.confirmed.json").is_file())
            self.assertTrue((execution_directory / "complete.json").is_file())
            self.assertTrue((execution_directory / "token-revoke.intent.json").is_file())
            self.assertTrue((execution_directory / "token-revoke.confirmed.json").is_file())
            recovery = assess_execution_directory(
                execution_directory, receipt_output
            )
            self.assertEqual(recovery["status"], "completed")
            self.assertEqual(recovery["token_revocation"], "confirmed")
            execution_text = "".join(
                path.read_text(encoding="ascii")
                for path in execution_directory.iterdir()
            )
            self.assertNotIn("first-private-password", execution_text)
            self.assertNotIn("second-private-password", execution_text)
            self.assertNotIn("test-vault-token", execution_text)

            (execution_directory / "token-revoke.confirmed.json").unlink()
            unconfirmed = assess_execution_directory(
                execution_directory, receipt_output
            )
            self.assertEqual(unconfirmed["status"], "completed")
            self.assertEqual(unconfirmed["token_revocation"], "unconfirmed")

    def test_context_is_renewed_after_all_writes_before_transit_sign(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_file = root / "input.json"
            token_file = root / "vault.token"
            receipt_output = root / "receipt.json"
            execution_directory = root / "execution"
            input_file.write_text(json.dumps([{
                "provider_ref": "provider-renew-order",
                "brand": "Visa",
                "pan": "4111111111111111",
            }]), encoding="utf-8")
            token_file.write_text("test-vault-token", encoding="utf-8")
            order: list[str] = []

            class OrderedVaultClient:
                def __init__(self, *_args: object, **_kwargs: object) -> None:
                    order.append("client")

                def write_secret(self, _secret_ref: str, _secret: dict[str, object]) -> None:
                    order.append("write")

                def sign(self, _pool_type: str, _payload: bytes) -> str:
                    order.append("sign")
                    return "vault:v1:test-signature"

                def revoke_self(self) -> None:
                    order.append("revoke")

            def renew_context(client: object, context_token: str) -> object:
                del client
                order.append("renew")
                self.assertEqual(context_token, "c" * 43)
                return secure_pool_import.PoolImportContext(
                    schema_version=1,
                    context_token=context_token,
                    receipt_id=self.receipt_id,
                    tenant_id="tenant-1",
                    audience="email-platform:pool-import:production",
                    pool_type="card",
                    ordered_manifest_digest=secure_pool_import.pool_import_digest(
                        "card",
                        [{
                            "provider_ref": "provider-renew-order",
                            "pool_key": "legacy-unclassified",
                            "region": "legacy-unclassified",
                            "brand": "Visa",
                            "last4": "1111",
                            "expiry_month": None,
                            "expiry_year": None,
                        }],
                    ),
                    item_count=1,
                    expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
                )

            def read_approle_token(*_args: object, **_kwargs: object) -> str:
                self.assertTrue((execution_directory / "plan.json").is_file())
                order.append("approle")
                return "test-vault-token"

            with patch.object(
                secure_pool_import.PlatformClient,
                "renew_context",
                new=renew_context,
                create=True,
            ), patch.object(
                secure_pool_import,
                "_read_vault_approle_token",
                new=read_approle_token,
                create=True,
            ), patch.object(secure_pool_import, "VaultClient", OrderedVaultClient):
                secure_pool_import.run(self._args(
                    input_file=str(input_file.resolve()),
                    approle_secret_id_file=str(token_file.resolve()),
                    receipt_output=str(receipt_output.resolve()),
                    execution_directory=str(execution_directory.resolve()),
                ))

            self.assertEqual(
                order,
                ["client", "approle", "write", "renew", "sign", "revoke"],
            )

    def test_approle_failure_after_client_setup_has_no_empty_token_revocation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_file = root / "input.json"
            receipt_output = root / "receipt.json"
            execution_directory = root / "execution"
            input_file.write_text(json.dumps([{
                "provider_ref": "provider-client-before-approle",
                "brand": "Visa",
                "pan": "4111111111111111",
            }]), encoding="utf-8")
            order: list[str] = []

            class EmptyVaultClient:
                revocations = 0

                def __init__(self, _addr: str, token: str, **_kwargs: object) -> None:
                    order.append("client")
                    self.token = token

                def revoke_self(self) -> None:
                    type(self).revocations += 1

            def fail_approle(*_args: object, **_kwargs: object) -> str:
                order.append("approle")
                raise secure_pool_import.ImportFailure(
                    "Vault AppRole authentication failed"
                )

            with patch.object(
                secure_pool_import,
                "_read_vault_approle_token",
                new=fail_approle,
            ), patch.object(
                secure_pool_import,
                "VaultClient",
                EmptyVaultClient,
            ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
                secure_pool_import.run(self._args(
                    input_file=str(input_file.resolve()),
                    receipt_output=str(receipt_output.resolve()),
                    execution_directory=str(execution_directory.resolve()),
                ))

            self.assertEqual(
                str(raised.exception),
                "Vault AppRole authentication failed",
            )
            self.assertEqual(order, ["client", "approle"])
            self.assertEqual(EmptyVaultClient.revocations, 0)
            self.assertTrue((execution_directory / "plan.json").is_file())
            self.assertFalse(
                (execution_directory / "token-revoke.intent.json").exists()
            )
            self.assertFalse(
                (execution_directory / "token-revoke.confirmed.json").exists()
            )
            self.assertFalse(receipt_output.exists())

    def test_completed_bundle_can_be_reissued_without_raw_input_or_kv_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_file = root / "input.json"
            token_file = root / "vault.token"
            original_bundle = root / "receipt-original.json"
            fresh_bundle = root / "receipt-fresh.json"
            execution_directory = root / "execution"
            input_file.write_text(json.dumps([{
                "provider_ref": "provider-reissue",
                "brand": "Visa",
                "pan": "4111111111111111",
            }]), encoding="utf-8")
            token_file.write_text("test-vault-token", encoding="utf-8")

            class InitialVaultClient:
                def __init__(self, *_args: object, **_kwargs: object) -> None:
                    pass

                def write_secret(self, _secret_ref: str, _secret: dict[str, object]) -> None:
                    pass

                def sign(self, _pool_type: str, _payload: bytes) -> str:
                    return "vault:v1:original-signature"

                def revoke_self(self) -> None:
                    pass

            with patch.object(secure_pool_import, "VaultClient", InitialVaultClient):
                secure_pool_import.run(self._args(
                    input_file=str(input_file.resolve()),
                    approle_secret_id_file=str(token_file.resolve()),
                    receipt_output=str(original_bundle.resolve()),
                    execution_directory=str(execution_directory.resolve()),
                ))
            execution_snapshot = {
                path.name: path.read_bytes() for path in execution_directory.iterdir()
            }
            input_file.unlink()

            class ReissueVaultClient:
                writes = 0

                def __init__(self, *_args: object, **_kwargs: object) -> None:
                    reissue_order.append("client")

                def write_secret(self, _secret_ref: str, _secret: dict[str, object]) -> None:
                    type(self).writes += 1
                    raise AssertionError("KV write must not run during receipt reissue")

                def sign(self, _pool_type: str, _payload: bytes) -> str:
                    reissue_order.append("sign")
                    return "vault:v1:fresh-signature"

                def revoke_self(self) -> None:
                    reissue_order.append("revoke")

            reissue_order: list[str] = []

            def read_reissue_approle(*_args: object, **_kwargs: object) -> str:
                reissue_order.append("approle")
                return "test-vault-token"

            with patch.object(
                secure_pool_import,
                "_read_vault_approle_token",
                new=read_reissue_approle,
            ), patch.object(secure_pool_import, "VaultClient", ReissueVaultClient):
                result = secure_pool_import.reissue_completed(self._args(
                    input_file=None,
                    reissue_from=str(original_bundle.resolve()),
                    approle_secret_id_file=str(token_file.resolve()),
                    receipt_output=str(fresh_bundle.resolve()),
                    execution_directory=str(execution_directory.resolve()),
                ))

            self.assertEqual(result, (self.receipt_id, 1))
            self.assertEqual(ReissueVaultClient.writes, 0)
            self.assertEqual(
                reissue_order,
                ["client", "approle", "sign", "revoke"],
            )
            original = json.loads(original_bundle.read_text(encoding="utf-8"))
            fresh = json.loads(fresh_bundle.read_text(encoding="utf-8"))
            for key in ("pool_type", "submission_key", "context_token", "items"):
                self.assertEqual(fresh[key], original[key])
            self.assertNotEqual(fresh["receipt_token"], original["receipt_token"])
            self.assertEqual(
                {path.name: path.read_bytes() for path in execution_directory.iterdir()},
                execution_snapshot,
            )

            failed_bundle = root / "receipt-failed.json"

            class FailingReissueVaultClient:
                revocations = 0

                def __init__(self, *_args: object, **_kwargs: object) -> None:
                    pass

                def sign(self, _pool_type: str, _payload: bytes) -> str:
                    raise secure_pool_import.ImportFailure("Transit signing failed")

                def revoke_self(self) -> None:
                    type(self).revocations += 1
                    raise secure_pool_import.ImportFailure(
                        "private revocation transport detail"
                    )

            with patch.object(
                secure_pool_import, "VaultClient", FailingReissueVaultClient
            ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
                secure_pool_import.reissue_completed(self._args(
                    input_file=None,
                    reissue_from=str(original_bundle.resolve()),
                    approle_secret_id_file=str(token_file.resolve()),
                    receipt_output=str(failed_bundle.resolve()),
                    execution_directory=str(execution_directory.resolve()),
                ))
            self.assertEqual(str(raised.exception), "Transit signing failed")
            self.assertEqual(
                raised.exception.__notes__,
                [secure_pool_import._REVOCATION_FAILURE_NOTE],
            )
            self.assertNotIn(
                "private revocation transport detail",
                str(raised.exception),
            )
            self.assertEqual(FailingReissueVaultClient.revocations, 1)
            self.assertFalse(failed_bundle.exists())
            self.assertEqual(
                {path.name: path.read_bytes() for path in execution_directory.iterdir()},
                execution_snapshot,
            )

    def test_reissue_path_resolution_failure_is_fixed_and_precedes_assessment(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            arguments = self._args(
                input_file=None,
                reissue_from=str(root / "receipt-original.json"),
                platform_token_file=str(root / "platform.token"),
                approle_role_id_file=str(root / "role-id"),
                approle_secret_id_file=str(root / "secret-id"),
                receipt_output=str(root / "receipt-fresh.json"),
                execution_directory=str(root / "execution"),
            )
            with patch.object(
                Path,
                "resolve",
                side_effect=OSError("private reissue path detail"),
            ), patch.object(
                secure_pool_import,
                "assess_execution_directory",
                side_effect=AssertionError("Assessment must not run"),
            ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
                secure_pool_import.reissue_completed(arguments)

            self.assertEqual(
                str(raised.exception),
                "Bundle, AppRole, platform token, CA, execution, and output paths "
                "must be separate",
            )
            self.assertNotIn("private reissue path detail", str(raised.exception))
            self.assertFalse((root / "receipt-fresh.json").exists())

    def test_reissue_validates_origins_before_ca_or_execution_assessment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            arguments = self._args(
                input_file=None,
                reissue_from=str(root / "receipt-original.json"),
                platform_address="https://[private-platform-origin-detail",
                platform_token_file=str(root / "platform.token"),
                approle_role_id_file=str(root / "role-id"),
                approle_secret_id_file=str(root / "secret-id"),
                receipt_output=str(root / "receipt-fresh.json"),
                execution_directory=str(root / "execution"),
            )
            with patch.object(
                secure_pool_import,
                "_create_tls_context",
                side_effect=AssertionError("CA must not be loaded"),
            ), patch.object(
                secure_pool_import,
                "assess_execution_directory",
                side_effect=AssertionError("Execution must not be assessed"),
            ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
                secure_pool_import.reissue_completed(arguments)

            self.assertEqual(
                str(raised.exception),
                "Platform address must be an HTTPS origin",
            )
            self.assertNotIn("private", str(raised.exception))
            self.assertFalse((root / "receipt-fresh.json").exists())

    def test_reissue_rejects_shared_security_origin_before_assessment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            arguments = self._args(
                input_file=None,
                reissue_from=str(root / "receipt-original.json"),
                platform_address="https://SHARED-ORIGIN.example.test",
                platform_token_file=str(root / "platform.token"),
                vault_address="https://shared-origin.example.test:443/",
                approle_role_id_file=str(root / "role-id"),
                approle_secret_id_file=str(root / "secret-id"),
                receipt_output=str(root / "receipt-fresh.json"),
                execution_directory=str(root / "execution"),
            )
            with patch.object(
                secure_pool_import,
                "_create_tls_context",
                side_effect=AssertionError("CA must not be loaded"),
            ), patch.object(
                secure_pool_import,
                "assess_execution_directory",
                side_effect=AssertionError("Execution must not be assessed"),
            ), self.assertRaises(secure_pool_import.ImportFailure) as raised:
                secure_pool_import.reissue_completed(arguments)

            self.assertEqual(
                str(raised.exception),
                "Platform and Vault addresses must use separate HTTPS origins",
            )
            self.assertFalse((root / "receipt-fresh.json").exists())

    def test_reissue_refuses_incomplete_execution_before_reading_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_file = root / "input.json"
            token_file = root / "vault.token"
            absent_bundle = root / "receipt-missing.json"
            fresh_bundle = root / "receipt-fresh.json"
            execution_directory = root / "execution"
            input_file.write_text(json.dumps([{
                "provider_ref": "provider-incomplete",
                "brand": "Visa",
                "pan": "4111111111111111",
            }]), encoding="utf-8")
            token_file.write_text("test-vault-token", encoding="utf-8")

            class InterruptedVaultClient:
                revocations = 0

                def __init__(self, *_args: object, **_kwargs: object) -> None:
                    pass

                def write_secret(self, _secret_ref: str, _secret: dict[str, object]) -> None:
                    raise KeyboardInterrupt

                def sign(self, _pool_type: str, _payload: bytes) -> str:
                    raise AssertionError("sign must not run")

                def revoke_self(self) -> None:
                    type(self).revocations += 1

            with patch.object(secure_pool_import, "VaultClient", InterruptedVaultClient):
                with self.assertRaises(KeyboardInterrupt):
                    secure_pool_import.run(self._args(
                        input_file=str(input_file.resolve()),
                        approle_secret_id_file=str(token_file.resolve()),
                        receipt_output=str(absent_bundle.resolve()),
                        execution_directory=str(execution_directory.resolve()),
                    ))

            self.assertEqual(InterruptedVaultClient.revocations, 1)

            with patch.object(
                secure_pool_import,
                "_read_platform_access_token",
                side_effect=AssertionError("Platform token must not be read"),
            ), patch.object(
                secure_pool_import,
                "_read_vault_approle_token",
                side_effect=AssertionError("Vault AppRole files must not be read"),
            ), self.assertRaises(secure_pool_import.ImportFailure):
                secure_pool_import.reissue_completed(self._args(
                    input_file=None,
                    reissue_from=str(absent_bundle.resolve()),
                    approle_secret_id_file=str(token_file.resolve()),
                    receipt_output=str(fresh_bundle.resolve()),
                    execution_directory=str(execution_directory.resolve()),
                ))
            self.assertFalse(fresh_bundle.exists())

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
                revocations = 0

                def __init__(self, *_args: object, **_kwargs: object) -> None:
                    pass

                def write_secret(self, _secret_ref: str, _secret: dict[str, object]) -> None:
                    raise KeyboardInterrupt

                def sign(self, _pool_type: str, _payload: bytes) -> str:
                    raise AssertionError("sign must not run after an unknown Vault write")

                def revoke_self(self) -> None:
                    type(self).revocations += 1

            with patch.object(secure_pool_import, "VaultClient", InterruptedVaultClient):
                with self.assertRaises(KeyboardInterrupt):
                    secure_pool_import.run(self._args(
                        input_file=str(input_file.resolve()),
                        approle_secret_id_file=str(token_file.resolve()),
                        receipt_output=str(receipt_output.resolve()),
                        execution_directory=str(execution_directory.resolve()),
                    ))

            self.assertEqual(InterruptedVaultClient.revocations, 1)

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
            self.assertEqual(recovery["token_revocation"], "confirmed")
            self.assertFalse(receipt_output.exists())
            execution_text = "".join(
                path.read_text(encoding="ascii")
                for path in execution_directory.iterdir()
            )
            self.assertNotIn("4111111111111111", execution_text)


if __name__ == "__main__":
    unittest.main()
