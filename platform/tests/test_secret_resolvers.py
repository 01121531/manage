import json
import unittest
from email.message import Message
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
