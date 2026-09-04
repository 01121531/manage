from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from platform.config import Settings
from platform.sub2_admin import sub2_admin_from_settings


class ResolverThatMustStayLazy:
    def __init__(self) -> None:
        self.refs: list[str] = []

    def resolve(self, secret_ref: str):
        self.refs.append(secret_ref)
        raise AssertionError("factory must not resolve the Sub2 admin API key")


class Sub2AdminFactoryTests(unittest.TestCase):
    def test_all_admin_settings_empty_disables_adapter(self) -> None:
        resolver = ResolverThatMustStayLazy()

        configured = sub2_admin_from_settings(Settings(), resolver)

        self.assertIsNone(configured)
        self.assertEqual(resolver.refs, [])

    def test_partial_admin_configuration_fails_closed(self) -> None:
        cases = (
            {"sub2_admin_base_url": "https://sub2.example/api/v1/admin"},
            {"sub2_admin_api_key_ref": "vault://secret/sub2/admin"},
            {"sub2_admin_proxy_id": 1},
            {"sub2_admin_model_mapping_file": "mapping.json"},
        )
        for values in cases:
            with self.subTest(values=values), self.assertRaisesRegex(
                RuntimeError, "configuration is incomplete"
            ):
                sub2_admin_from_settings(Settings(**values), ResolverThatMustStayLazy())

    def test_production_requires_vault_api_key_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            origins = Path(directory) / "allowed-origins"
            origins.write_text("https://sub2.example\n", encoding="utf-8")
            mapping = Path(directory) / "model-mapping.json"
            mapping.write_text('{"gpt-5.6":"gpt-5.6"}\n', encoding="utf-8")
            settings = Settings(
                environment="production",
                sub2_admin_base_url="https://sub2.example/api/v1/admin",
                sub2_admin_api_key_ref="env://SUB2_ADMIN_KEY",
                sub2_admin_model_mapping_file=str(mapping),
                sub2_allowed_origins_file=str(origins),
            )

            with self.assertRaisesRegex(RuntimeError, "must use vault://"):
                sub2_admin_from_settings(settings, ResolverThatMustStayLazy())

    def test_factory_reuses_policy_and_transport_settings_without_resolving_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            origins = Path(directory) / "allowed-origins"
            origins.write_text("https://sub2.example\n", encoding="utf-8")
            mapping = Path(directory) / "model-mapping.json"
            mapping.write_text('{"gpt-5.6":"gpt-5.6"}\n', encoding="utf-8")
            settings = Settings(
                environment="production",
                sub2_admin_base_url="https://sub2.example/api/v1/admin",
                sub2_admin_api_key_ref="vault://secret/sub2/admin",
                sub2_admin_proxy_id=7,
                sub2_admin_model_mapping_file=str(mapping),
                sub2_allowed_origins_file=str(origins),
                sub2_timeout_seconds=19,
                sub2_policy_version="sub2-official-v1",
                sub2_group_id=52,
                sub2_concurrency=11,
            )
            resolver = ResolverThatMustStayLazy()

            configured = sub2_admin_from_settings(settings, resolver)

            self.assertIsNotNone(configured)
            adapter, policy = configured
            self.assertEqual(adapter.base_url, "https://sub2.example/api/v1/admin")
            self.assertEqual(adapter.admin_api_key_ref, "vault://secret/sub2/admin")
            self.assertEqual(adapter.timeout, 19)
            self.assertIs(adapter.secret_resolver, resolver)
            self.assertEqual(policy.version, "sub2-official-v1")
            self.assertEqual(policy.proxy_id, 7)
            self.assertEqual(policy.group_ids, (52,))
            self.assertEqual(policy.concurrency, 11)
            self.assertEqual(policy.model_mapping, {"gpt-5.6": "gpt-5.6"})
            self.assertEqual(resolver.refs, [])

    def test_factory_rejects_duplicate_model_mapping_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            origins = Path(directory) / "allowed-origins"
            origins.write_text("https://sub2.example\n", encoding="utf-8")
            mapping = Path(directory) / "model-mapping.json"
            mapping.write_text(
                '{"gpt-5.6":"first","gpt-5.6":"second"}\n',
                encoding="utf-8",
            )
            settings = Settings(
                sub2_admin_base_url="https://sub2.example/api/v1/admin",
                sub2_admin_api_key_ref="env://SUB2_ADMIN_KEY",
                sub2_admin_model_mapping_file=str(mapping),
                sub2_allowed_origins_file=str(origins),
            )

            with self.assertRaisesRegex(RuntimeError, "policy is unavailable"):
                sub2_admin_from_settings(settings, ResolverThatMustStayLazy())


if __name__ == "__main__":
    unittest.main()
