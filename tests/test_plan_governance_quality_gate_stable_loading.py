from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from scripts import external_json
from scripts import external_text
from scripts import verify_plan_completion
from scripts import verify_plan_requirements


class PlanGovernanceQualityGateStableLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ledger = json.loads(
            verify_plan_completion.LEDGER.read_text(encoding="utf-8")
        )
        self.inventory = json.loads(
            verify_plan_requirements.INVENTORY.read_text(encoding="utf-8")
        )
        source_path = (
            verify_plan_requirements.ROOT / self.inventory["source"]["path"]
        )
        self.plan_source_bytes = external_json.read_stable_bytes(
            source_path,
            max_bytes=verify_plan_requirements.MAX_PLAN_SOURCE_BYTES,
        )
        self.gate_text = external_text.load_stable_text(
            verify_plan_completion.QUALITY_GATE
        )

    def _requirement_errors(self) -> list[str]:
        with mock.patch.object(
            verify_plan_requirements,
            "read_stable_bytes",
            return_value=self.plan_source_bytes,
        ):
            return verify_plan_requirements.inventory_errors(
                self.inventory,
                check_files=True,
            )

    def _cases(self):
        return (
            (
                verify_plan_completion,
                lambda: verify_plan_completion.repository_entrypoint_errors(
                    self.ledger
                ),
                "completion ledger quality gate is unavailable",
            ),
            (
                verify_plan_requirements,
                self._requirement_errors,
                "plan requirement quality gate is unavailable",
            ),
        )

    def test_each_verifier_reads_the_gate_once_through_the_stable_boundary(
        self,
    ) -> None:
        real_read_text = Path.read_text

        def guarded_read_text(path: Path, *args, **kwargs):
            if path == verify_plan_completion.QUALITY_GATE:
                raise AssertionError("Path.read_text bypassed stable loading")
            return real_read_text(path, *args, **kwargs)

        for module, run, _ in self._cases():
            with self.subTest(module=module.__name__), mock.patch.object(
                Path,
                "read_text",
                guarded_read_text,
            ), mock.patch.object(
                module,
                "load_stable_text",
                wraps=external_text.load_stable_text,
                create=True,
            ) as stable_read:
                self.assertEqual(run(), [])
            stable_read.assert_called_once_with(
                module.QUALITY_GATE,
                max_bytes=module.MAX_QUALITY_GATE_BYTES,
            )

    def test_each_verifier_accepts_the_exact_limit_and_rejects_one_extra_byte(
        self,
    ) -> None:
        source = self.gate_text.encode("utf-8")
        if not source.endswith(b"\n"):
            source += b"\n"
        limit = 64 * 1024
        padding = limit - len(source)
        self.assertGreater(padding, 1)
        exact = source + b"#" + b"x" * (padding - 1)

        for module, run, unavailable in self._cases():
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as temporary:
                gate = Path(temporary) / "quality_gate.ps1"
                gate.write_bytes(exact)
                with mock.patch.object(module, "QUALITY_GATE", gate):
                    self.assertEqual(run(), [])
                    gate.write_bytes(exact + b"x")
                    self.assertEqual(run(), [unavailable])

    def test_invalid_utf8_keeps_each_fixed_unavailable_diagnostic(self) -> None:
        for module, run, unavailable in self._cases():
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as temporary:
                gate = Path(temporary) / "quality_gate.ps1"
                gate.write_bytes(b"\xff")
                with mock.patch.object(module, "QUALITY_GATE", gate):
                    self.assertEqual(run(), [unavailable])

    def test_link_or_reparse_gate_is_rejected_before_open(self) -> None:
        for module, run, unavailable in self._cases():
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as temporary:
                gate = Path(temporary) / "quality_gate.ps1"
                gate.write_text(self.gate_text, encoding="utf-8")
                with mock.patch.object(
                    module,
                    "QUALITY_GATE",
                    gate,
                ), mock.patch.object(
                    external_json,
                    "has_link_or_reparse_ancestor",
                    return_value=True,
                ), mock.patch.object(external_json.os, "open") as open_file:
                    self.assertEqual(run(), [unavailable])
                open_file.assert_not_called()

    def test_non_regular_open_gate_is_rejected(self) -> None:
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

        for module, run, unavailable in self._cases():
            with self.subTest(module=module.__name__), mock.patch.object(
                external_json.os,
                "fstat",
                side_effect=non_regular_fstat,
            ):
                self.assertEqual(run(), [unavailable])

    def test_gate_read_shape_drift_is_rejected(self) -> None:
        real_fstat = os.fstat

        for module, run, unavailable in self._cases():
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

            with self.subTest(module=module.__name__), mock.patch.object(
                external_json.os,
                "fstat",
                side_effect=drifting_fstat,
            ):
                self.assertEqual(run(), [unavailable])
            self.assertEqual(calls, 2)

    def test_loader_failures_do_not_leak_private_reasons(self) -> None:
        for module, run, unavailable in self._cases():
            for reason in ("open", "read", "changed", "decode"):
                with self.subTest(
                    module=module.__name__,
                    reason=reason,
                ), mock.patch.object(
                    module,
                    "load_stable_text",
                    side_effect=external_json.StableFileError(reason),
                    create=True,
                ) as stable_read:
                    errors = run()
                self.assertEqual(errors, [unavailable])
                self.assertNotIn(reason, "; ".join(errors))
                stable_read.assert_called_once_with(
                    module.QUALITY_GATE,
                    max_bytes=module.MAX_QUALITY_GATE_BYTES,
                )

    def test_existing_command_drift_and_check_files_semantics_are_preserved(
        self,
    ) -> None:
        completion_command = (
            "python scripts/phase0_boundary_approval.py verify-repository"
        )
        requirement_command = "python scripts/verify_plan_requirements.py"
        scenarios = (
            (
                verify_plan_completion,
                lambda: verify_plan_completion.repository_entrypoint_errors(
                    self.ledger
                ),
                completion_command,
                "completion ledger phase 0 gate command is not active",
            ),
            (
                verify_plan_requirements,
                self._requirement_errors,
                requirement_command,
                "plan requirement verifier is not active in quality gate",
            ),
        )
        for module, run, command, expected in scenarios:
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as temporary:
                gate = Path(temporary) / "quality_gate.ps1"
                gate.write_text(
                    self.gate_text.replace(command, "", 1),
                    encoding="utf-8",
                )
                with mock.patch.object(module, "QUALITY_GATE", gate):
                    self.assertIn(expected, run())

        with mock.patch.object(
            verify_plan_requirements,
            "load_stable_text",
            side_effect=AssertionError("check_files=False read the gate"),
            create=True,
        ) as stable_read:
            self.assertEqual(
                verify_plan_requirements.inventory_errors(
                    self.inventory,
                    check_files=False,
                ),
                [],
            )
        stable_read.assert_not_called()

    def test_sources_use_explicit_bounded_stable_gate_snapshots(self) -> None:
        for module, _, _ in self._cases():
            with self.subTest(module=module.__name__):
                source = Path(module.__file__).read_text(encoding="utf-8")
                self.assertNotIn("QUALITY_GATE.read_text", source)
                self.assertIn("MAX_QUALITY_GATE_BYTES = 64 * 1024", source)
                self.assertIn("load_stable_text(", source)
                self.assertIn("max_bytes=MAX_QUALITY_GATE_BYTES", source)


if __name__ == "__main__":
    unittest.main()
