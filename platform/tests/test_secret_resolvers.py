import json
import os
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


_MAX_TEST_VAULT_RESPONSE_BYTES = 64 * 1024


def padded_json_bytes(payload: dict[str, object], size: int) -> bytes:
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(encoded) > size:
        raise ValueError("payload exceeds requested size")
    return encoded + (b" " * (size - len(encoded)))


class RawResponse:
    def __init__(
        self,
        body: bytes,
        *,
        content_type: str = "application/json",
    ) -> None:
        self.body = body
        self.read_sizes: list[int] = []
        self.headers = Message()
        self.headers["Content-Type"] = content_type

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return self.body if size < 0 else self.body[:size]

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self.body = json.dumps(payload).encode("utf-8")
        self.headers = Message()
        self.headers["Content-Type"] = "application/json"

    def read(self, size: int = -1) -> bytes:
        return self.body if size < 0 else self.body[:size]

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

    def test_vault_kv_json_boundary_is_bounded_for_v1_and_v2(self) -> None:
        cases = (
            ({"data": {"value": "kv-v1"}}, "kv-v1"),
            ({"data": {"data": {"value": "kv-v2"}}}, "kv-v2"),
        )
        for payload, expected in cases:
            with self.subTest(payload=payload):
                response = RawResponse(
                    padded_json_bytes(payload, _MAX_TEST_VAULT_RESPONSE_BYTES)
                )
                resolver = VaultSecretResolver(
                    "https://vault.example",
                    "vault-token-secret",
                    opener=lambda *_args, **_kwargs: response,
                )

                value = resolver.resolve("vault://secret/cards/card-1")

                self.assertEqual(value["value"], expected)
                self.assertEqual(
                    response.read_sizes,
                    [_MAX_TEST_VAULT_RESPONSE_BYTES + 1],
                )

    def test_vault_kv_json_rejects_oversized_v1_and_v2(self) -> None:
        payloads = (
            {"data": {"value": "kv-v1"}},
            {"data": {"data": {"value": "kv-v2"}}},
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                response = RawResponse(
                    padded_json_bytes(payload, _MAX_TEST_VAULT_RESPONSE_BYTES + 1)
                )
                resolver = VaultSecretResolver(
                    "https://vault.example",
                    "vault-token-secret",
                    opener=lambda *_args, **_kwargs: response,
                )

                with self.assertRaises(SecretResolverUnavailable) as raised:
                    resolver.resolve("vault://secret/cards/card-1")

                self.assertEqual(str(raised.exception), "Vault returned invalid JSON")
                self.assertIsNone(raised.exception.__cause__)

    def test_vault_kv_json_rejects_duplicate_data_keys_at_every_depth(self) -> None:
        bodies = (
            b'{"data":{"value":"safe"},"data":{"value":"safe"}}',
            b'{"data":{"data":{"value":"safe"},"data":{"value":"safe"}}}',
        )
        for body in bodies:
            with self.subTest(body=body):
                response = RawResponse(body)
                resolver = VaultSecretResolver(
                    "https://vault.example",
                    "vault-token-secret",
                    opener=lambda *_args, **_kwargs: response,
                )

                with self.assertRaises(SecretResolverUnavailable) as raised:
                    resolver.resolve("vault://secret/cards/card-1")

                self.assertEqual(str(raised.exception), "Vault returned invalid JSON")
                self.assertIsNone(raised.exception.__cause__)

    def test_vault_kv_json_requires_utf8_regardless_of_response_charset(self) -> None:
        bodies = (
            b'{"data":{"value":"\xff"}}',
            b'{"data":{"data":{"value":"\xff"}}}',
        )
        for body in bodies:
            with self.subTest(body=body):
                response = RawResponse(
                    body,
                    content_type="application/json; charset=iso-8859-1",
                )
                resolver = VaultSecretResolver(
                    "https://vault.example",
                    "vault-token-secret",
                    opener=lambda *_args, **_kwargs: response,
                )

                with self.assertRaises(SecretResolverUnavailable) as raised:
                    resolver.resolve("vault://secret/cards/card-1")

                self.assertEqual(str(raised.exception), "Vault returned invalid JSON")
                self.assertIsNone(raised.exception.__cause__)

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
        with mock.patch.object(VaultSecretResolver, "validate_token_source"):
            resolver = secret_resolver_from_settings(
                SimpleNamespace(
                    environment="production",
                    vault_addr="https://vault.example",
                    vault_token=None,
                    vault_token_file="/run/secrets/email-platform/token",
                )
            )
        with mock.patch.dict("os.environ", {"SHOULD_NOT_BE_READ": "secret"}):
            with self.assertRaisesRegex(
                SecretResolverUnavailable, "disabled in production"
            ):
                resolver.resolve("env://SHOULD_NOT_BE_READ")

    def test_managed_environment_requires_vault_address(self) -> None:
        for environment in ("production", "staging"):
            for vault_addr in (None, "", "   "):
                with self.subTest(
                    environment=environment,
                    vault_addr=vault_addr,
                ):
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "^PLATFORM_VAULT_ADDR is required outside development/test$",
                    ):
                        secret_resolver_from_settings(
                            SimpleNamespace(
                                environment=environment,
                                vault_addr=vault_addr,
                                vault_token=None,
                                vault_token_file=None,
                            )
                        )

    def test_local_environment_can_start_without_vault_address(self) -> None:
        for environment in ("development", "test"):
            with self.subTest(environment=environment):
                resolver = secret_resolver_from_settings(
                    SimpleNamespace(
                        environment=environment,
                        vault_addr=None,
                        vault_token=None,
                        vault_token_file=None,
                    )
                )
                self.assertIsInstance(resolver, SchemeSecretResolver)
                self.assertIsNone(resolver.vault)
                self.assertTrue(resolver.allow_env)

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

            self.assertIsNone(resolver.validate_token_source())
            self.assertEqual(opener.requests, [])
            rotated_file = Path(directory) / "token.next"
            rotated_file.write_text("rotated-short-lived-token\n", encoding="utf-8")
            rotated_file.replace(token_file)
            resolver.resolve("vault://secret/cards/card-1")

            second_rotation = Path(directory) / "token.second"
            second_rotation.write_text("second-rotated-token\n", encoding="utf-8")
            second_rotation.replace(token_file)
            resolver.resolve("vault://secret/cards/card-1")

        self.assertEqual(
            [request.headers["X-vault-token"] for request, _ in opener.requests],
            ["rotated-short-lived-token", "second-rotated-token"],
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

    def test_vault_token_preflight_fails_closed_without_network(self) -> None:
        opener = RecordingOpener({"data": {"data": {"value": "unused"}}})
        with tempfile.TemporaryDirectory() as directory:
            token_file = Path(directory) / "missing-token"
            resolver = VaultSecretResolver(
                "https://vault.example",
                token_file=str(token_file.resolve()),
                opener=opener,
            )

            with self.assertRaises(SecretResolverUnavailable) as raised:
                resolver.validate_token_source()

        self.assertEqual(str(raised.exception), "Vault token file is unavailable")
        self.assertNotIn(str(token_file), str(raised.exception))
        self.assertEqual(opener.requests, [])

    def test_vault_token_preflight_does_not_cache_a_valid_file(self) -> None:
        opener = RecordingOpener({"data": {"data": {"value": "unused"}}})
        with tempfile.TemporaryDirectory() as directory:
            token_file = Path(directory) / "token"
            token_file.write_text("valid-at-startup\n", encoding="utf-8")
            resolver = VaultSecretResolver(
                "https://vault.example",
                token_file=str(token_file.resolve()),
                opener=opener,
            )
            resolver.validate_token_source()
            invalid_file = Path(directory) / "token.invalid"
            invalid_file.write_text("invalid token\n", encoding="utf-8")
            invalid_file.replace(token_file)

            with self.assertRaises(SecretResolverUnavailable) as raised:
                resolver.resolve("vault://secret/cards/card-1")

        self.assertEqual(str(raised.exception), "Vault token file is unavailable")
        self.assertEqual(opener.requests, [])

    def test_vault_token_preflight_rejects_unsafe_file_shapes(self) -> None:
        opener = RecordingOpener({"data": {"data": {"value": "unused"}}})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = {
                "empty": b"",
                "whitespace": b"   \n",
                "embedded-whitespace": b"unsafe token",
                "invalid-utf8": b"\xff\xfe",
                "oversized": b"s" * 4097,
            }
            for name, contents in cases.items():
                with self.subTest(name=name):
                    token_file = root / name
                    token_file.write_bytes(contents)
                    resolver = VaultSecretResolver(
                        "https://vault.example",
                        token_file=str(token_file.resolve()),
                        opener=opener,
                    )
                    with self.assertRaises(SecretResolverUnavailable) as raised:
                        resolver.validate_token_source()
                    self.assertEqual(
                        str(raised.exception), "Vault token file is unavailable"
                    )
                    self.assertIsNone(raised.exception.__cause__)
                    self.assertNotIn(str(token_file), str(raised.exception))

            directory_resolver = VaultSecretResolver(
                "https://vault.example",
                token_file=str(root.resolve()),
                opener=opener,
            )
            with self.assertRaises(SecretResolverUnavailable) as raised:
                directory_resolver.validate_token_source()
            self.assertEqual(
                str(raised.exception), "Vault token file is unavailable"
            )
            self.assertIsNone(raised.exception.__cause__)

            exact_limit = root / "exact-limit"
            exact_limit.write_bytes(b"v" * 4096)
            exact_resolver = VaultSecretResolver(
                "https://vault.example",
                token_file=str(exact_limit.resolve()),
                opener=opener,
            )
            self.assertIsNone(exact_resolver.validate_token_source())

        self.assertEqual(opener.requests, [])

    @unittest.skipIf(os.name == "nt", "POSIX symlink support is required")
    def test_vault_token_preflight_supports_stable_projected_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text("valid-token", encoding="utf-8")
            token_file = root / "token"
            token_file.symlink_to(target)
            resolver = VaultSecretResolver(
                "https://vault.example",
                token_file=str(token_file.absolute()),
            )

            self.assertIsNone(resolver.validate_token_source())

    @unittest.skipIf(os.name == "nt", "POSIX mode bits are required")
    def test_vault_token_preflight_rejects_group_or_world_writable_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            token_file = Path(directory) / "token"
            token_file.write_text("valid-token", encoding="utf-8")
            for mode in (0o620, 0o602):
                with self.subTest(mode=oct(mode)):
                    token_file.chmod(mode)
                    resolver = VaultSecretResolver(
                        "https://vault.example",
                        token_file=str(token_file.resolve()),
                    )
                    with self.assertRaises(SecretResolverUnavailable) as raised:
                        resolver.validate_token_source()
                    self.assertEqual(
                        str(raised.exception), "Vault token file is unavailable"
                    )
                    self.assertIsNone(raised.exception.__cause__)

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
        with mock.patch.object(
            VaultSecretResolver, "validate_token_source"
        ) as validate_token_source:
            resolver = secret_resolver_from_settings(
                Settings(**base, vault_token_file="/run/secrets/email-platform/token")
            )
        self.assertIsInstance(resolver, SchemeSecretResolver)
        validate_token_source.assert_called_once_with()

    def test_production_rejects_plaintext_vault_transport(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "VAULT_ADDR must use HTTPS"):
            secret_resolver_from_settings(
                Settings(
                    environment="production",
                    database_url="sqlite+pysqlite:///:memory:",
                    vault_addr="http://vault:8200",
                    vault_token_file="/run/secrets/email-platform/token",
                )
            )

        resolver = secret_resolver_from_settings(
            Settings(
                environment="test",
                database_url="sqlite+pysqlite:///:memory:",
                vault_addr="http://vault:8200",
                vault_token="local-test-token",
            )
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
