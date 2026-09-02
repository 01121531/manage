import base64
import io
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from uuid import uuid4

from platform.pool_imports import (
    PoolImportReceiptBindingMismatch,
    PoolImportReceiptExpired,
    PoolImportReceiptInvalid,
    VaultTransitPoolImportReceiptVerifier,
    canonical_receipt_claims,
    encode_receipt_token,
    pool_import_digest,
    pool_import_receipt_verifier_from_settings,
    pool_import_submission_key,
    pool_secret_ref,
)


NOW = datetime(2026, 8, 31, 8, 0, tzinfo=timezone.utc)


class _Response:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit: int) -> bytes:
        return self.payload[:limit]


class PoolImportReceiptTests(unittest.TestCase):
    def claims(self, **changes: object) -> dict[str, object]:
        values: dict[str, object] = {
            "schema_version": 1,
            "audience": "email-platform:pool-import:test",
            "receipt_id": str(uuid4()),
            "tenant_id": "tenant-a",
            "pool_type": "card",
            "ordered_manifest_digest": "a" * 64,
            "item_count": 2,
            "issued_at": int(NOW.timestamp()) - 10,
            "expires_at": int(NOW.timestamp()) + 290,
            "key_version": 3,
        }
        values.update(changes)
        return values

    def verifier(self, *, valid: bool = True) -> VaultTransitPoolImportReceiptVerifier:
        def opener(request, *, timeout: int):
            self.assertEqual(timeout, 3)
            self.assertTrue(request.full_url.endswith(
                "/v1/transit/verify/email-platform-card-import-receipt"
            ))
            body = json.loads(request.data)
            signed_input = base64.b64decode(body["input"])
            self.assertTrue(signed_input.startswith(
                b"email-platform/pool-import-receipt/v1\0"
            ))
            self.assertEqual(body["signature"], "vault:v3:c2lnbmF0dXJl")
            return _Response(json.dumps({"data": {"valid": valid}}).encode())

        return VaultTransitPoolImportReceiptVerifier(
            "https://vault.example.test",
            audience="email-platform:pool-import:test",
            token="test-vault-token",
            timeout=3,
            opener=opener,
            clock=lambda: NOW,
        )

    def token(self, claims: dict[str, object]) -> str:
        return encode_receipt_token(
            canonical_receipt_claims(claims),
            "vault:v3:c2lnbmF0dXJl",
        )

    def test_verifies_canonical_bound_receipt(self) -> None:
        claims = self.claims()
        result = self.verifier().verify(
            self.token(claims),
            tenant_id="tenant-a",
            pool_type="card",
            ordered_manifest_digest="a" * 64,
            item_count=2,
        )
        self.assertEqual(result.receipt_id, claims["receipt_id"])
        self.assertEqual(result.key_version, 3)

    def test_verifier_requires_a_vault_origin(self) -> None:
        with self.assertRaises(ValueError):
            VaultTransitPoolImportReceiptVerifier(
                "https://vault.example.test/proxy",
                audience="email-platform:pool-import:test",
                token="test-vault-token",
            )

    def test_verifier_rejects_malformed_origin_before_token_file_read(self) -> None:
        cases = (
            "https://:8200",
            "https://vault.example.test:0",
            "https://vault.example.test:65536",
            "https://vault.example.test:private-port-detail",
            " https://vault.example.test",
            "https://vault.example.test\t",
            "https://[private-vault-origin-detail",
        )
        token = self.token(self.claims())
        token_file = str((Path.cwd() / "private-vault-token").resolve())
        for address in cases:
            with self.subTest(address=address):
                with mock.patch(
                    "platform.pool_imports.read_stable_runtime_bytes_with_metadata",
                    side_effect=AssertionError("Vault token file must not be read"),
                ), self.assertRaises(ValueError) as raised:
                    verifier = VaultTransitPoolImportReceiptVerifier(
                        address,
                        audience="email-platform:pool-import:test",
                        token_file=token_file,
                        clock=lambda: NOW,
                    )
                    verifier.verify(
                        token,
                        tenant_id="tenant-a",
                        pool_type="card",
                        ordered_manifest_digest="a" * 64,
                        item_count=2,
                    )

                self.assertEqual(str(raised.exception), "Vault address is invalid")

    def test_verifier_requires_https_unless_local_http_is_explicit(self) -> None:
        with self.assertRaises(ValueError) as raised:
            VaultTransitPoolImportReceiptVerifier(
                "http://vault:8200",
                audience="email-platform:pool-import:test",
                token="test-vault-token",
            )
        self.assertEqual(str(raised.exception), "Vault address must use HTTPS")

        local = VaultTransitPoolImportReceiptVerifier(
            "http://vault:8200",
            audience="email-platform:pool-import:test",
            token="test-vault-token",
            allow_http=True,
        )
        self.assertEqual(local.addr, "http://vault:8200")

    def test_settings_factory_scopes_http_exception_to_local_environment(self) -> None:
        def settings(environment: str) -> SimpleNamespace:
            return SimpleNamespace(
                environment=environment,
                vault_addr="http://vault:8200",
                vault_token="test-vault-token",
                vault_token_file=None,
                vault_namespace=None,
                vault_timeout_seconds=3,
                pool_import_receipt_audience="email-platform:pool-import:test",
            )

        with self.assertRaises(ValueError) as raised:
            pool_import_receipt_verifier_from_settings(settings("production"))
        self.assertEqual(str(raised.exception), "Vault address must use HTTPS")

        local = pool_import_receipt_verifier_from_settings(settings("test"))
        self.assertIsInstance(local, VaultTransitPoolImportReceiptVerifier)
        self.assertEqual(local.addr, "http://vault:8200")

    def test_rejects_invalid_signature_expiry_and_binding_without_token_leak(self) -> None:
        token = self.token(self.claims())
        with self.assertRaises(PoolImportReceiptInvalid) as invalid:
            self.verifier(valid=False).verify(
                token,
                tenant_id="tenant-a",
                pool_type="card",
                ordered_manifest_digest="a" * 64,
                item_count=2,
            )
        self.assertNotIn(token, str(invalid.exception))

        expired = self.token(self.claims(expires_at=int(NOW.timestamp())))
        with self.assertRaises(PoolImportReceiptExpired):
            self.verifier().verify(
                expired,
                tenant_id="tenant-a",
                pool_type="card",
                ordered_manifest_digest="a" * 64,
                item_count=2,
            )

        with self.assertRaises(PoolImportReceiptBindingMismatch):
            self.verifier().verify(
                token,
                tenant_id="tenant-b",
                pool_type="card",
                ordered_manifest_digest="a" * 64,
                item_count=2,
            )

    def test_rejects_noncanonical_duplicate_or_extra_claims(self) -> None:
        claims = self.claims(extra="not-allowed")
        with self.assertRaises(PoolImportReceiptInvalid):
            canonical_receipt_claims(claims)

        canonical = canonical_receipt_claims(self.claims())
        noncanonical = json.dumps(json.loads(canonical), indent=2).encode()
        token = encode_receipt_token(noncanonical, "vault:v3:c2lnbmF0dXJl")
        with self.assertRaises(PoolImportReceiptInvalid):
            self.verifier().verify(
                token,
                tenant_id="tenant-a",
                pool_type="card",
                ordered_manifest_digest="a" * 64,
                item_count=2,
            )

    def test_manifest_digest_preserves_order_and_refs_are_server_derived(self) -> None:
        left = [{"provider_ref": "one", "last4": "1111"}, {"provider_ref": "two", "last4": "2222"}]
        right = list(reversed(left))
        self.assertNotEqual(pool_import_digest("card", left), pool_import_digest("card", right))
        receipt_id = str(uuid4())
        self.assertEqual(
            pool_import_submission_key(receipt_id),
            f"spi:{receipt_id}",
        )
        card_ref = pool_secret_ref(
            "card", tenant_id="tenant-a", receipt_id=receipt_id, index=0
        )
        mailbox_ref = pool_secret_ref(
            "mailbox", tenant_id="tenant-a", receipt_id=receipt_id, index=0
        )
        self.assertRegex(
            card_ref,
            rf"^vault://secret/cards/imports/[0-9a-f]{{24}}/{receipt_id}/000$",
        )
        self.assertRegex(
            mailbox_ref,
            rf"^vault://secret/mailboxes/imports/[0-9a-f]{{24}}/{receipt_id}/000$",
        )


if __name__ == "__main__":
    unittest.main()
