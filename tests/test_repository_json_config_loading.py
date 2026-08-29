from __future__ import annotations

from contextlib import redirect_stderr
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from scripts import decision_envelope_validation
from scripts import external_json
from scripts import external_yaml
from scripts import verify_keycloak_realm
from scripts import verify_kubernetes_portability
from scripts import verify_migration_compatibility


MAX_CONFIG_BYTES = 64 * 1024


class RepositoryJsonConfigLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.oidc_decision = json.loads(
            decision_envelope_validation.OIDC_IDENTITY_DECISION.read_text(
                encoding="utf-8"
            )
        )
        self.documents = verify_kubernetes_portability.load_documents()
        self.compose = external_yaml.load_unique_yaml(
            verify_kubernetes_portability.COMPOSE
        )
        self.release_manifest = json.loads(
            verify_kubernetes_portability.RELEASE_MANIFEST.read_text(
                encoding="utf-8"
            )
        )
        self.target_requirements = json.loads(
            verify_kubernetes_portability.TARGET_REQUIREMENTS.read_text(
                encoding="utf-8"
            )
        )

    def _cases(self):
        return (
            (
                "keycloak-verifier",
                verify_keycloak_realm,
                "REALM",
                verify_keycloak_realm.REALM,
                verify_keycloak_realm.main,
                lambda result: result == 1,
            ),
            (
                "decision-envelope-realm",
                decision_envelope_validation,
                "KEYCLOAK_REALM",
                verify_keycloak_realm.REALM,
                lambda: decision_envelope_validation.runtime_alignment_errors(
                    self.oidc_decision
                ),
                lambda result: result == ["Keycloak realm is unavailable"],
            ),
            (
                "kubernetes-release-manifest",
                verify_kubernetes_portability,
                "RELEASE_MANIFEST",
                verify_kubernetes_portability.RELEASE_MANIFEST,
                lambda: verify_kubernetes_portability.deployment_alignment_errors(
                    self.documents,
                    compose=self.compose,
                    target_requirements=self.target_requirements,
                ),
                lambda result: result
                == ["Kubernetes repository alignment inputs are unavailable"],
            ),
            (
                "kubernetes-target-requirements",
                verify_kubernetes_portability,
                "TARGET_REQUIREMENTS",
                verify_kubernetes_portability.TARGET_REQUIREMENTS,
                lambda: verify_kubernetes_portability.deployment_alignment_errors(
                    self.documents,
                    compose=self.compose,
                    release_manifest=self.release_manifest,
                ),
                lambda result: result
                == ["Kubernetes repository alignment inputs are unavailable"],
            ),
            (
                "kubernetes-secret-contract",
                verify_kubernetes_portability,
                "SECRET_CONTRACT",
                verify_kubernetes_portability.SECRET_CONTRACT,
                verify_kubernetes_portability._contract_errors,
                lambda result: result
                == ["Kubernetes external secret contract is unavailable"],
            ),
            (
                "migration-baseline",
                verify_migration_compatibility,
                "BASELINE",
                verify_migration_compatibility.BASELINE,
                verify_migration_compatibility.verification_errors,
                lambda result: len(result) == 1
                and result[0].startswith("cannot load migration baseline:"),
            ),
        )

    def test_consumers_use_shared_64_kib_file_boundary(self) -> None:
        with mock.patch.object(
            verify_keycloak_realm,
            "load_unique_json",
            wraps=external_json.load_unique_json,
        ) as keycloak_loader, mock.patch.object(
            decision_envelope_validation,
            "load_unique_json",
            wraps=external_json.load_unique_json,
        ) as decision_loader, mock.patch.object(
            verify_kubernetes_portability,
            "load_unique_json",
            wraps=external_json.load_unique_json,
        ) as kubernetes_loader, mock.patch.object(
            verify_migration_compatibility,
            "load_unique_json",
            wraps=external_json.load_unique_json,
        ) as migration_loader, mock.patch("builtins.print"):
            self.assertEqual(verify_keycloak_realm.main(), 0)
            self.assertEqual(
                decision_envelope_validation.runtime_alignment_errors(
                    self.oidc_decision
                ),
                [],
            )
            self.assertEqual(
                verify_kubernetes_portability.deployment_alignment_errors(
                    self.documents,
                    compose=self.compose,
                ),
                [],
            )
            self.assertEqual(verify_kubernetes_portability._contract_errors(), [])
            self.assertEqual(
                verify_migration_compatibility.verification_errors(),
                [],
            )

        self.assertEqual(
            keycloak_loader.call_args_list,
            [
                mock.call(
                    verify_keycloak_realm.REALM,
                    max_bytes=MAX_CONFIG_BYTES,
                )
            ],
        )
        self.assertEqual(
            decision_loader.call_args_list,
            [
                mock.call(
                    decision_envelope_validation.KEYCLOAK_REALM,
                    max_bytes=MAX_CONFIG_BYTES,
                )
            ],
        )
        self.assertEqual(
            kubernetes_loader.call_args_list,
            [
                mock.call(
                    verify_kubernetes_portability.RELEASE_MANIFEST,
                    max_bytes=MAX_CONFIG_BYTES,
                ),
                mock.call(
                    verify_kubernetes_portability.TARGET_REQUIREMENTS,
                    max_bytes=MAX_CONFIG_BYTES,
                ),
                mock.call(
                    verify_kubernetes_portability.SECRET_CONTRACT,
                    max_bytes=MAX_CONFIG_BYTES,
                ),
            ],
        )
        self.assertEqual(
            migration_loader.call_args_list,
            [
                mock.call(
                    verify_migration_compatibility.BASELINE,
                    max_bytes=MAX_CONFIG_BYTES,
                )
            ],
        )

    def test_consumers_reject_files_over_64_kib(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for label, module, path_name, source_path, invoke, failed in self._cases():
                source = source_path.read_bytes()
                oversized = Path(temporary) / f"{label}.json"
                oversized.write_bytes(
                    source + b" " * (MAX_CONFIG_BYTES + 1 - len(source))
                )
                with self.subTest(consumer=label), mock.patch.object(
                    module,
                    path_name,
                    oversized,
                    create=True,
                ), mock.patch("builtins.print"):
                    self.assertTrue(failed(invoke()))

    def test_keycloak_invalid_source_uses_fixed_safe_cli_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "realm.json"
            source = verify_keycloak_realm.REALM.read_text(encoding="utf-8")
            path.write_text(
                '{"realm":"email-platform",' + source.lstrip()[1:],
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with mock.patch.object(verify_keycloak_realm, "REALM", path), redirect_stderr(
                stderr
            ):
                self.assertEqual(verify_keycloak_realm.main(), 1)
            self.assertEqual(
                stderr.getvalue().strip(),
                "Keycloak realm is invalid",
            )

    def test_consumers_reject_same_value_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for label, module, path_name, source_path, invoke, failed in self._cases():
                source = source_path.read_text(encoding="utf-8")
                document = json.loads(source)
                key = next(iter(document))
                duplicate = Path(temporary) / f"{label}.json"
                duplicate.write_text(
                    "{"
                    + json.dumps(key)
                    + ":"
                    + json.dumps(document[key], ensure_ascii=False)
                    + ","
                    + source.lstrip()[1:],
                    encoding="utf-8",
                )
                with self.subTest(consumer=label), mock.patch.object(
                    module,
                    path_name,
                    duplicate,
                    create=True,
                ), mock.patch("builtins.print"):
                    self.assertTrue(failed(invoke()))

    def test_consumers_reject_link_or_reparse_sources_before_open(self) -> None:
        for label, module, path_name, source_path, invoke, failed in self._cases():
            with self.subTest(consumer=label), mock.patch.object(
                module,
                path_name,
                source_path,
                create=True,
            ), mock.patch.object(
                external_json,
                "has_link_or_reparse_ancestor",
                return_value=True,
            ), mock.patch.object(external_json.os, "open") as open_file, mock.patch(
                "builtins.print"
            ):
                self.assertTrue(failed(invoke()))
                open_file.assert_not_called()

    def test_consumers_reject_open_file_shape_drift(self) -> None:
        real_fstat = os.fstat
        for label, module, path_name, source_path, invoke, failed in self._cases():
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
                            metadata,
                            "st_file_attributes",
                            0,
                        ),
                    )
                return metadata

            with self.subTest(consumer=label), mock.patch.object(
                module,
                path_name,
                source_path,
                create=True,
            ), mock.patch("os.fstat", side_effect=drifting_fstat), mock.patch(
                "builtins.print"
            ):
                self.assertTrue(failed(invoke()))
                self.assertEqual(calls, 2)


if __name__ == "__main__":
    unittest.main()
