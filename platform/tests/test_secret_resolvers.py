import json
from pathlib import Path
import tempfile
import unittest
from email.message import Message
from types import SimpleNamespace
from unittest import mock

from platform.config import Settings
from platform.secrets import (
    SchemeSecretResolver,
    SecretResolverUnavailable,
    VaultSecretResolver,
    JsonEnvironmentSecretResolver,
    secret_resolver_from_settings,
)


class FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self.body = json.dumps(payload).encode("utf-8")
        self.headers = Message()
        self.headers["Content-Type"] = "application/json"

    def read(self) -> bytes:
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class RecordingOpener:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload
        self.requests = []

    def __call__(self, request, timeout: int):
        self.requests.append((request, timeout))
        return FakeResponse(self.payload)


class SecretResolverTests(unittest.TestCase):
    def test_vault_resolver_reads_kv_v2_without_token_in_url(self) -> None:
        opener = RecordingOpener(
            {"data": {"data": {"pan": "4111111111111111", "cvv": "123"}}}
        )
        resolver = VaultSecretResolver(
            "https://vault.example",
            "vault-token-secret",
            namespace="team/platform",
            timeout=7,
            opener=opener,
        )

        value = resolver.resolve("vault://secret/cards/card-1")

        self.assertEqual(value["pan"], "4111111111111111")
        request, timeout = opener.requests[0]
        self.assertEqual(timeout, 7)
        self.assertEqual(
            request.full_url, "https://vault.example/v1/secret/data/cards/card-1"
        )
        self.assertEqual(request.headers["X-vault-token"], "vault-token-secret")
        self.assertEqual(request.headers["X-vault-namespace"], "team/platform")
        self.assertNotIn("vault-token-secret", request.full_url)
        self.assertNotIn("vault-token-secret", repr(resolver))

    def test_vault_ref_rejects_path_traversal_and_empty_segments(self) -> None:
        opener = RecordingOpener({"data": {"data": {"value": "unused"}}})
        resolver = VaultSecretResolver(
            "https://vault.example",
            "vault-token-secret",
            opener=opener,
        )

        for secret_ref in (
            "vault://secret/cards/../mailboxes/mail-1",
            "vault://secret/cards/./card-1",
            "vault://secret/cards//card-1",
            "vault://secret/cards/",
        ):
            with self.subTest(secret_ref=secret_ref):
                with self.assertRaises(SecretResolverUnavailable):
                    resolver.resolve(secret_ref)
        self.assertEqual(opener.requests, [])

    def test_production_disables_environment_secret_references(self) -> None:
        resolver = secret_resolver_from_settings(
            SimpleNamespace(
                environment="production",
                vault_addr=None,
                vault_token=None,
                vault_token_file=None,
            )
        )
        with mock.patch.dict("os.environ", {"SHOULD_NOT_BE_READ": "secret"}):
            with self.assertRaisesRegex(
                SecretResolverUnavailable, "disabled in production"
            ):
                resolver.resolve("env://SHOULD_NOT_BE_READ")

    def test_vault_token_file_rotation_is_used_by_the_next_resolve(self) -> None:
        opener = RecordingOpener({"data": {"data": {"value": "ok"}}})
        with tempfile.TemporaryDirectory() as directory:
            token_file = Path(directory) / "token"
            token_file.write_text("first-short-lived-token\n", encoding="utf-8")
            resolver = VaultSecretResolver(
                "https://vault.example",
                token_file=str(token_file.resolve()),
                opener=opener,
            )

            resolver.resolve("vault://secret/cards/card-1")
            rotated_file = Path(directory) / "token.next"
            rotated_file.write_text("rotated-short-lived-token\n", encoding="utf-8")
            rotated_file.replace(token_file)
            resolver.resolve("vault://secret/cards/card-1")

        self.assertEqual(
            [request.headers["X-vault-token"] for request, _ in opener.requests],
            ["first-short-lived-token", "rotated-short-lived-token"],
        )
        self.assertNotIn("rotated-short-lived-token", repr(resolver))

    def test_vault_token_file_rejects_relative_and_oversized_input(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be absolute"):
            VaultSecretResolver(
                "https://vault.example",
                token_file="relative/token",
            )

        with tempfile.TemporaryDirectory() as directory:
            token_file = Path(directory) / "token"
            token_file.write_text("s" * 4097, encoding="utf-8")
            resolver = VaultSecretResolver(
                "https://vault.example",
                token_file=str(token_file.resolve()),
                opener=RecordingOpener({"data": {"data": {"value": "unused"}}}),
            )
            with self.assertRaises(SecretResolverUnavailable) as raised:
                resolver.resolve("vault://secret/cards/card-1")

        self.assertEqual(str(raised.exception), "Vault token file is unavailable")
        self.assertNotIn("s" * 20, str(raised.exception))

    def test_production_requires_token_file_and_safe_container_path(self) -> None:
        base = {
            "environment": "production",
            "database_url": "sqlite+pysqlite:///:memory:",
            "vault_addr": "https://vault.example",
        }
        with self.assertRaisesRegex(RuntimeError, "required outside development/test"):
            secret_resolver_from_settings(
                Settings(**base, vault_token="environment-token")
            )
        with self.assertRaisesRegex(RuntimeError, "must be under /run/secrets"):
            secret_resolver_from_settings(
                Settings(**base, vault_token_file="/tmp/vault-token")
            )
        resolver = secret_resolver_from_settings(
            Settings(**base, vault_token_file="/run/secrets/email-platform/token")
        )
        self.assertIsInstance(resolver, SchemeSecretResolver)

    def test_vault_configuration_rejects_ambiguous_token_sources(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "exactly one"):
            secret_resolver_from_settings(
                Settings(
                    environment="test",
                    database_url="sqlite+pysqlite:///:memory:",
                    vault_addr="https://vault.example",
                    vault_token="environment-token",
                    vault_token_file=str((Path.cwd() / "token").resolve()),
                )
            )

    def test_vault_refs_fail_closed_without_vault_configuration(self) -> None:
        resolver = secret_resolver_from_settings(
            Settings(
                environment="test",
                database_url="sqlite+pysqlite:///:memory:",
                jwt_hmac_secret="secret-test-hmac-secret-that-is-not-production",
            )
        )
        with self.assertRaises(SecretResolverUnavailable):
            resolver.resolve("vault://secret/cards/card-1")

    def test_vault_configuration_requires_token(self) -> None:
        with self.assertRaises(RuntimeError):
            secret_resolver_from_settings(
                Settings(
                    environment="test",
                    database_url="sqlite+pysqlite:///:memory:",
                    jwt_hmac_secret="secret-test-hmac-secret-that-is-not-production",
                    vault_addr="https://vault.example",
                )
            )

    def test_scheme_resolver_keeps_env_fallback_when_vault_is_configured(self) -> None:
        resolver = SchemeSecretResolver(
            env=JsonEnvironmentSecretResolver(),
            vault=VaultSecretResolver(
                "http://vault:8200",
                "vault-token-secret",
                opener=RecordingOpener({"data": {"data": {"token": "vault-value"}}}),
            ),
        )
        with mock.patch.dict("os.environ", {"LOCAL_JSON": '{"token":"env-value"}'}):
            self.assertEqual(resolver.resolve("env://LOCAL_JSON")["token"], "env-value")


if __name__ == "__main__":
    unittest.main()
