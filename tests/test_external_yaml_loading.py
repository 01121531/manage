from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import yaml

from scripts import external_json
from scripts import external_yaml
from scripts import rollback_release
from scripts import target_platform_inventory
from scripts import vault_token_sinks
from scripts import verify_chapter13_defaults
from scripts import verify_compose_env
from scripts import verify_ci_workflow
from scripts import verify_container_hardening
from scripts import verify_container_logging
from scripts import verify_container_supply_chain
from scripts import verify_deploy_release
from scripts import verify_edge_assets
from scripts import verify_internal_tls
from scripts import verify_kubernetes_portability
from scripts import verify_monitoring_assets
from scripts import verify_release_workflow
from scripts import verify_rollback_assets
from scripts import verify_rolling_release
from scripts import verify_runtime_secrets
from scripts import verify_security_workflow
from scripts import verify_service_boundaries
from scripts import verify_vault_isolation


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
DEV_COMPOSE = ROOT / "docker-compose.dev.yml"
MAX_YAML_BYTES = 64 * 1024


class _LoaderCalled(RuntimeError):
    pass


class ExternalYamlLoadingTests(unittest.TestCase):
    def test_loader_accepts_exact_limit_and_rejects_oversize(self) -> None:
        prefix = b"root:\n  child: value\n#"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "asset.yml"
            path.write_bytes(prefix + b"x" * (MAX_YAML_BYTES - len(prefix)))
            self.assertEqual(
                external_yaml.load_unique_yaml(path),
                {"root": {"child": "value"}},
            )

            path.write_bytes(prefix + b"x" * (MAX_YAML_BYTES + 1 - len(prefix)))
            with self.assertRaises(OSError):
                external_yaml.load_unique_yaml(path)

    def test_loader_rejects_duplicate_keys_at_every_depth(self) -> None:
        values = (
            "services: {}\nservices: {}\n",
            "services:\n  api:\n    image: first\n    image: first\n",
        )
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(yaml.YAMLError):
                    external_yaml.parse_unique_yaml(value)

    def test_loader_rejects_link_or_reparse_before_open(self) -> None:
        path = Path("docker-compose.yml")
        with mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            return_value=True,
        ), mock.patch.object(external_json.os, "open") as open_file:
            with self.assertRaises(OSError):
                external_yaml.load_unique_yaml(path)
        open_file.assert_not_called()

    def test_loader_rejects_open_file_shape_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "asset.yml"
            path.write_text("services: {}\n", encoding="utf-8")
            real_fstat = os.fstat
            calls = 0

            def drifting_fstat(descriptor: int):
                nonlocal calls
                calls += 1
                metadata = real_fstat(descriptor)
                if calls == 2:
                    return SimpleNamespace(
                        st_mode=metadata.st_mode,
                        st_dev=metadata.st_dev,
                        st_ino=metadata.st_ino,
                        st_nlink=metadata.st_nlink,
                        st_size=metadata.st_size + 1,
                        st_mtime_ns=metadata.st_mtime_ns,
                        st_ctime_ns=metadata.st_ctime_ns,
                        st_file_attributes=getattr(
                            metadata, "st_file_attributes", 0
                        ),
                    )
                return metadata

            with mock.patch("os.fstat", side_effect=drifting_fstat):
                with self.assertRaises(OSError):
                    external_yaml.load_unique_yaml(path)
            self.assertEqual(calls, 2)

    def test_loader_rejects_invalid_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "asset.yml"
            path.write_bytes(b"services: \xff\n")
            with self.assertRaises(UnicodeError):
                external_yaml.load_unique_yaml(path)

    def test_all_production_compose_consumers_use_the_shared_file_boundary(self) -> None:
        consumers = (
            (
                vault_token_sinks,
                "load_unique_yaml",
                lambda: vault_token_sinks._validate_compose_contract(COMPOSE),
            ),
            (
                verify_compose_env,
                "read_stable_yaml_text",
                verify_compose_env.verification_errors,
            ),
            (
                verify_container_hardening,
                "load_unique_yaml",
                verify_container_hardening.main,
            ),
            (
                verify_container_logging,
                "load_unique_yaml",
                verify_container_logging.load_compose,
            ),
            (
                verify_deploy_release,
                "read_stable_yaml_text",
                verify_deploy_release.main,
            ),
            (
                verify_edge_assets,
                "load_unique_yaml",
                verify_edge_assets.load_assets,
            ),
            (
                verify_internal_tls,
                "load_unique_yaml",
                verify_internal_tls.load_assets,
            ),
            (
                verify_kubernetes_portability,
                "load_unique_yaml",
                lambda: verify_kubernetes_portability.deployment_alignment_errors([]),
            ),
            (
                verify_monitoring_assets,
                "load_unique_yaml",
                lambda: verify_monitoring_assets._load_document(COMPOSE),
            ),
            (
                verify_rollback_assets,
                "read_stable_yaml_text",
                verify_rollback_assets.main,
            ),
            (
                verify_runtime_secrets,
                "load_unique_yaml",
                verify_runtime_secrets.verification_errors,
            ),
            (
                verify_service_boundaries,
                "load_unique_yaml",
                verify_service_boundaries.main,
            ),
            (
                verify_vault_isolation,
                "load_unique_yaml",
                verify_vault_isolation.load_assets,
            ),
        )

        for module, loader_name, invoke in consumers:
            with self.subTest(module=module.__name__), mock.patch.object(
                module,
                loader_name,
                side_effect=_LoaderCalled,
            ) as loader:
                try:
                    invoke()
                except _LoaderCalled:
                    pass
                loader.assert_called()

    def test_text_injection_contracts_reject_duplicate_compose_keys(self) -> None:
        compose_text = COMPOSE.read_text(encoding="utf-8")
        duplicate = "services: {}\n" + compose_text
        dev_compose_text = DEV_COMPOSE.read_text(encoding="utf-8")

        cases = (
            (
                "compose-env",
                lambda: verify_compose_env.verification_errors(
                    compose_text=duplicate
                ),
            ),
            (
                "deploy-release",
                lambda: verify_deploy_release.deployment_asset_errors(
                    duplicate,
                    dev_compose_text,
                    verify_deploy_release.ENV_EXAMPLE.read_text(encoding="utf-8"),
                    verify_deploy_release.DEV_ENV_EXAMPLE.read_text(
                        encoding="utf-8"
                    ),
                    verify_deploy_release.DEPLOY_SCRIPT.read_text(encoding="utf-8"),
                    verify_deploy_release.UPSTREAM_SCAN_SCRIPT.read_text(
                        encoding="utf-8"
                    ),
                ),
            ),
            (
                "rollback-assets",
                lambda: verify_rollback_assets.rollback_asset_errors(
                    duplicate,
                    verify_rollback_assets.ENV_EXAMPLE.read_text(encoding="utf-8"),
                    verify_rollback_assets.ROLLBACK_SCRIPT.read_text(
                        encoding="utf-8"
                    ),
                ),
            ),
            (
                "runtime-secrets",
                lambda: verify_runtime_secrets.verification_errors(
                    compose_text=duplicate
                ),
            ),
        )

        for name, invoke in cases:
            with self.subTest(consumer=name):
                errors = invoke()
                self.assertTrue(errors)
                self.assertTrue(
                    any("invalid" in error.lower() or "inspect" in error.lower()
                        for error in errors),
                    errors,
                )

    def test_validated_text_loader_returns_source_and_rejects_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "compose.yml"
            source = "services:\n  api:\n    image: reviewed\n"
            path.write_bytes(source.encode("utf-8"))
            value, loaded_source = external_yaml.load_unique_yaml_with_text(path)
            self.assertEqual(value, {"services": {"api": {"image": "reviewed"}}})
            self.assertEqual(loaded_source, source)

            path.write_text("services: {}\nservices: {}\n", encoding="utf-8")
            with self.assertRaises(yaml.YAMLError):
                external_yaml.load_unique_yaml_with_text(path)

    def test_multi_document_loader_is_bounded_and_preserves_documents(self) -> None:
        prefix = b"---\nkind: ConfigMap\n---\nkind: Service\n#"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "resources.yaml"
            path.write_bytes(prefix + b"x" * (MAX_YAML_BYTES - len(prefix)))
            self.assertEqual(
                external_yaml.load_unique_yaml_all(path),
                [{"kind": "ConfigMap"}, {"kind": "Service"}],
            )

            path.write_bytes(prefix + b"x" * (MAX_YAML_BYTES + 1 - len(prefix)))
            with self.assertRaises(OSError):
                external_yaml.load_unique_yaml_all(path)

    def test_multi_document_loader_rejects_duplicate_keys_at_every_depth(self) -> None:
        source = (
            "---\nkind: ConfigMap\nmetadata:\n  name: first\n"
            "---\nkind: Service\nmetadata:\n  name: second\n  name: second\n"
        )
        with self.assertRaises(yaml.YAMLError):
            external_yaml.parse_unique_yaml_all(source)

    def test_raw_compose_consumers_use_validated_source_text(self) -> None:
        consumers = (
            (
                rollback_release,
                lambda: rollback_release._load_compose_input_variables(COMPOSE),
            ),
            (
                target_platform_inventory,
                lambda: target_platform_inventory.runtime_alignment_errors(
                    target_platform_inventory._load(
                        target_platform_inventory.INVENTORY
                    )
                ),
            ),
            (
                verify_chapter13_defaults,
                lambda: verify_chapter13_defaults.decision_errors(
                    verify_chapter13_defaults.EXPECTED
                ),
            ),
        )
        for module, invoke in consumers:
            with self.subTest(module=module.__name__), mock.patch.object(
                module,
                "load_unique_yaml_with_text",
                side_effect=_LoaderCalled,
            ) as loader:
                try:
                    invoke()
                except _LoaderCalled:
                    pass
                loader.assert_called()

    def test_remaining_yaml_consumers_use_shared_file_loaders(self) -> None:
        with mock.patch.object(
            verify_internal_tls,
            "load_unique_yaml",
            wraps=external_yaml.load_unique_yaml,
        ) as loader:
            verify_internal_tls.load_assets()
        self.assertEqual(
            [call.args[0] for call in loader.call_args_list[:2]],
            [verify_internal_tls.COMPOSE, verify_internal_tls.PROMETHEUS],
        )

        cases = (
            (
                verify_kubernetes_portability,
                "load_unique_yaml_all",
                lambda: verify_kubernetes_portability.load_documents(
                    verify_kubernetes_portability.KUBERNETES_ROOT
                ),
            ),
            (
                verify_rolling_release,
                "load_unique_yaml_with_text",
                verify_rolling_release.verification_errors,
            ),
        )
        for module, loader_name, invoke in cases:
            with self.subTest(module=module.__name__), mock.patch.object(
                module,
                loader_name,
                side_effect=_LoaderCalled,
            ) as loader:
                try:
                    invoke()
                except _LoaderCalled:
                    pass
                loader.assert_called()

    def test_raw_text_injection_contracts_reject_duplicate_compose_keys(self) -> None:
        duplicate = "services: {}\n" + COMPOSE.read_text(encoding="utf-8")
        inventory = target_platform_inventory._load(
            target_platform_inventory.INVENTORY
        )
        cases = (
            (
                "target-platform-inventory",
                lambda: target_platform_inventory.runtime_alignment_errors(
                    inventory,
                    compose_text=duplicate,
                ),
            ),
            (
                "chapter13-defaults",
                lambda: verify_chapter13_defaults.decision_errors(
                    verify_chapter13_defaults.EXPECTED,
                    compose_text=duplicate,
                ),
            ),
        )
        for name, invoke in cases:
            with self.subTest(consumer=name):
                errors = invoke()
                self.assertTrue(errors)
                self.assertTrue(
                    any("unavailable" in error.lower() or "unreadable" in error.lower()
                        for error in errors),
                    errors,
                )

    def test_workflow_yaml_consumers_use_shared_file_boundary(self) -> None:
        consumers = (
            (
                verify_ci_workflow,
                "load_unique_yaml",
                verify_ci_workflow.verification_errors,
            ),
            (
                verify_security_workflow,
                "load_unique_yaml",
                verify_security_workflow.main,
            ),
            (
                verify_release_workflow,
                "load_unique_yaml_with_text",
                verify_release_workflow.main,
            ),
            (
                verify_container_supply_chain,
                "load_unique_yaml",
                verify_container_supply_chain.load_workflows,
            ),
        )
        for module, loader_name, invoke in consumers:
            with self.subTest(module=module.__name__), mock.patch.object(
                module,
                loader_name,
                side_effect=_LoaderCalled,
            ) as loader:
                try:
                    invoke()
                except _LoaderCalled:
                    pass
                loader.assert_called()

    def test_workflow_file_entrypoints_reject_oversized_sources(self) -> None:
        fixtures = (
            (verify_ci_workflow.CI_PATH, "CI_PATH"),
            (verify_security_workflow.WORKFLOW, "WORKFLOW"),
            (verify_release_workflow.WORKFLOW, "WORKFLOW"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            paths: dict[str, Path] = {}
            for source_path, label in fixtures:
                source = source_path.read_bytes()
                oversized = Path(temporary) / f"{source_path.stem}-{label}.yml"
                oversized.write_bytes(
                    source + b"\n#" + b"x" * (MAX_YAML_BYTES + 1 - len(source) - 2)
                )
                paths[f"{source_path.name}-{label}"] = oversized

            with mock.patch.object(
                verify_ci_workflow,
                "CI_PATH",
                paths["ci.yml-CI_PATH"],
            ):
                self.assertTrue(verify_ci_workflow.verification_errors())

            with mock.patch.object(
                verify_security_workflow,
                "WORKFLOW",
                paths["security.yml-WORKFLOW"],
            ), mock.patch("builtins.print"):
                self.assertEqual(verify_security_workflow.main(), 1)

            with mock.patch.object(
                verify_release_workflow,
                "WORKFLOW",
                paths["release.yml-WORKFLOW"],
            ), mock.patch("builtins.print"):
                self.assertEqual(verify_release_workflow.main(), 1)

            supply_security = paths["security.yml-WORKFLOW"]
            with mock.patch.object(
                verify_container_supply_chain,
                "SECURITY",
                supply_security,
            ):
                with self.assertRaises(OSError):
                    verify_container_supply_chain.load_workflows()

    def test_workflow_inputs_reject_duplicate_keys(self) -> None:
        ci_text = verify_ci_workflow.CI_PATH.read_text(encoding="utf-8")
        release_text = verify_release_workflow.WORKFLOW.read_text(encoding="utf-8")
        self.assertTrue(
            verify_ci_workflow.verification_errors("permissions: {}\n" + ci_text)
        )
        self.assertTrue(
            verify_release_workflow.workflow_errors("jobs: {}\n" + release_text)
        )

        with tempfile.TemporaryDirectory() as temporary:
            duplicate_security = Path(temporary) / "security.yml"
            duplicate_security.write_text(
                "jobs: {}\n"
                + verify_security_workflow.WORKFLOW.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            with mock.patch.object(
                verify_security_workflow,
                "WORKFLOW",
                duplicate_security,
            ), mock.patch("builtins.print"):
                self.assertEqual(verify_security_workflow.main(), 1)

            with mock.patch.object(
                verify_container_supply_chain,
                "SECURITY",
                duplicate_security,
            ):
                with self.assertRaises(yaml.YAMLError):
                    verify_container_supply_chain.load_workflows()


if __name__ == "__main__":
    unittest.main()
