from __future__ import annotations

from contextlib import redirect_stderr
import io
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import scripts.external_json as external_json
from scripts import decision_envelope_validation
from scripts import phase0_boundary_approval
from scripts import phase6_operations_evidence
from scripts import phase6_pilot_evidence
from scripts import phase6_pilot_inputs
from scripts import provider_contract_conformance
from scripts import sub2_execution_evidence
from scripts import target_platform_inventory
from scripts import vault_egress_evidence
from scripts import verify_chapter13_defaults
from scripts import verify_chapter14_mvi
from scripts import verify_phase_acceptance_matrix
from scripts import verify_plan_completion
from scripts import verify_plan_requirements
from scripts import verify_sub2_case_observation


_MAX_EXTERNAL_JSON_BYTES = 5 * 1024 * 1024
_LOADERS = (
    provider_contract_conformance._load,
    decision_envelope_validation._load,
    phase0_boundary_approval._load,
    target_platform_inventory._load,
    sub2_execution_evidence._load,
    vault_egress_evidence._load,
    phase6_pilot_inputs._load,
    phase6_pilot_evidence._load,
    phase6_operations_evidence._load,
    verify_sub2_case_observation._load,
)

_PLAN_CONSUMERS = (
    (verify_chapter13_defaults, "DECISIONS"),
    (verify_chapter14_mvi, "CONTRACT"),
    (verify_phase_acceptance_matrix, "MATRIX"),
    (verify_plan_completion, "LEDGER"),
    (verify_plan_requirements, "INVENTORY"),
)


class _LoaderCalled(RuntimeError):
    pass


class ExternalJsonLoadingTests(unittest.TestCase):
    def test_stable_reader_rejects_open_file_mode_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "mode-drift.json"
            path.write_text('{"reviewed":true}', encoding="utf-8")
            real_fstat = os.fstat
            calls = 0

            def drifting_fstat(descriptor: int):
                nonlocal calls
                calls += 1
                metadata = real_fstat(descriptor)
                if calls == 2:
                    return SimpleNamespace(
                        st_mode=metadata.st_mode ^ stat.S_IWUSR,
                        st_dev=metadata.st_dev,
                        st_ino=metadata.st_ino,
                        st_nlink=metadata.st_nlink,
                        st_size=metadata.st_size,
                        st_mtime_ns=metadata.st_mtime_ns,
                        st_ctime_ns=metadata.st_ctime_ns,
                        st_file_attributes=getattr(
                            metadata, "st_file_attributes", 0
                        ),
                    )
                return metadata

            with mock.patch("os.fstat", side_effect=drifting_fstat):
                with self.assertRaises(external_json.StableFileError):
                    external_json.read_stable_bytes(path, max_bytes=1024)
            self.assertEqual(calls, 2)

    def test_stable_reader_rejects_non_regular_open_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "not-regular.json"
            path.write_text('{"reviewed":true}', encoding="utf-8")
            real_fstat = os.fstat

            def non_regular_fstat(descriptor: int):
                metadata = real_fstat(descriptor)
                return SimpleNamespace(
                    st_mode=stat.S_IFIFO | 0o600,
                    st_dev=metadata.st_dev,
                    st_ino=metadata.st_ino,
                    st_nlink=metadata.st_nlink,
                    st_size=metadata.st_size,
                    st_mtime_ns=metadata.st_mtime_ns,
                    st_ctime_ns=metadata.st_ctime_ns,
                    st_file_attributes=getattr(metadata, "st_file_attributes", 0),
                )

            with mock.patch("os.fstat", side_effect=non_regular_fstat):
                with self.assertRaises(external_json.StableFileError):
                    external_json.read_stable_bytes(path, max_bytes=1024)

    def test_plan_governance_consumers_use_shared_file_boundary(self) -> None:
        for module, _ in _PLAN_CONSUMERS:
            with self.subTest(module=module.__name__), mock.patch.object(
                module,
                "load_unique_json",
                side_effect=_LoaderCalled,
            ) as loader:
                with self.assertRaises(_LoaderCalled):
                    module.main()
                loader.assert_called()

    def test_plan_governance_entrypoints_reject_files_over_64_kib(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for module, path_name in _PLAN_CONSUMERS:
                source_path = getattr(module, path_name)
                source = source_path.read_bytes()
                oversized = Path(temporary) / source_path.name
                oversized.write_bytes(
                    source + b" " * (64 * 1024 + 1 - len(source))
                )
                with self.subTest(module=module.__name__), mock.patch.object(
                    module,
                    path_name,
                    oversized,
                ), mock.patch("builtins.print"):
                    self.assertEqual(module.main(), 1)

    def test_plan_governance_entrypoints_reject_same_value_duplicate_keys(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for module, path_name in _PLAN_CONSUMERS:
                source_path = getattr(module, path_name)
                duplicate = Path(temporary) / source_path.name
                source = source_path.read_text(encoding="utf-8")
                duplicate.write_text(
                    '{"schema_version":1,' + source.lstrip()[1:],
                    encoding="utf-8",
                )
                with self.subTest(module=module.__name__), mock.patch.object(
                    module,
                    path_name,
                    duplicate,
                ), mock.patch("builtins.print"):
                    self.assertEqual(module.main(), 1)

    def test_plan_governance_entrypoints_reject_link_or_reparse_sources(
        self,
    ) -> None:
        for module, _ in _PLAN_CONSUMERS:
            with self.subTest(module=module.__name__), mock.patch.object(
                external_json,
                "has_link_or_reparse_ancestor",
                return_value=True,
            ), mock.patch.object(external_json.os, "open") as open_file, mock.patch(
                "builtins.print"
            ):
                self.assertEqual(module.main(), 1)
                open_file.assert_not_called()

    def test_plan_governance_entrypoints_reject_open_file_shape_drift(
        self,
    ) -> None:
        real_fstat = os.fstat
        for module, _ in _PLAN_CONSUMERS:
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

            with self.subTest(module=module.__name__), mock.patch(
                "os.fstat",
                side_effect=drifting_fstat,
            ), mock.patch("builtins.print"):
                self.assertEqual(module.main(), 1)
                self.assertEqual(calls, 2)

    def test_all_standalone_loaders_reject_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text(
                '{"outer":{"reviewed":false,"reviewed":true}}',
                encoding="utf-8",
            )

            for loader in _LOADERS:
                with self.subTest(module=loader.__module__):
                    with self.assertRaises(json.JSONDecodeError):
                        loader(path)

    def test_all_standalone_loaders_reject_files_over_five_mib(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "oversized.json"
            path.write_bytes(
                b"{}" + b" " * (_MAX_EXTERNAL_JSON_BYTES + 1 - 2)
            )

            for loader in _LOADERS:
                with self.subTest(module=loader.__module__):
                    with self.assertRaises(OSError):
                        loader(path)

    def test_standalone_loader_rejects_open_file_shape_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "drifting.json"
            path.write_text('{"reviewed":true}', encoding="utf-8")
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
                    provider_contract_conformance._load(path)
            self.assertEqual(calls, 2)

    def test_standalone_loader_does_not_open_link_or_reparse_path(self) -> None:
        path = Path("repository-external-artifact.json")
        with mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            return_value=True,
        ), mock.patch.object(external_json.os, "open") as open_file:
            with self.assertRaises(OSError):
                provider_contract_conformance._load(path)
        open_file.assert_not_called()

    def test_standalone_cli_keeps_generic_error_and_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text(
                '{"contract_type":"mail","contract_type":"sub2"}',
                encoding="utf-8",
            )
            stderr = io.StringIO()

            with redirect_stderr(stderr):
                result = provider_contract_conformance.main(
                    [
                        "check",
                        "--input",
                        str(path),
                        "--expected-type",
                        "mail",
                    ]
                )

            self.assertEqual(result, 1)
            self.assertEqual(stderr.getvalue().strip(), "provider-contract-invalid")

    def test_standalone_manifest_argument_keeps_64_kib_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / "oversized-manifest.json"
            manifest.write_bytes(b"{}" + b" " * (64 * 1024 + 1 - 2))
            stderr = io.StringIO()

            with redirect_stderr(stderr):
                result = phase0_boundary_approval.main(
                    [
                        "check",
                        "--input",
                        str(phase0_boundary_approval.APPROVAL),
                        "--intake-manifest",
                        str(manifest),
                        "--expected-intake-manifest-payload-sha256",
                        "0" * 64,
                        "--expected-intake-manifest-file-sha256",
                        "0" * 64,
                    ]
                )

            self.assertEqual(result, 2)
            self.assertEqual(
                stderr.getvalue().strip(),
                "phase0-boundary-approval intake manifest caller binding is invalid",
            )


if __name__ == "__main__":
    unittest.main()
