from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import external_json
from scripts import external_text
from scripts import external_yaml
from scripts import verify_ci_workflow


class CiQualityGateStableLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow_text = external_yaml.read_stable_yaml_text(
            verify_ci_workflow.CI_PATH
        )
        self.gate_text = external_text.load_stable_text(
            verify_ci_workflow.QUALITY_GATE_PATH
        )

    @staticmethod
    def run_main() -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_ci_workflow.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_default_gate_is_loaded_once_without_path_read_text(self) -> None:
        real_read_text = Path.read_text

        def guarded_read_text(path: Path, *args, **kwargs):
            if path == verify_ci_workflow.QUALITY_GATE_PATH:
                raise AssertionError("Path.read_text bypassed stable loading")
            return real_read_text(path, *args, **kwargs)

        with mock.patch.object(
            Path,
            "read_text",
            guarded_read_text,
        ), mock.patch.object(
            verify_ci_workflow,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as stable_read:
            errors = verify_ci_workflow.verification_errors(
                workflow_text=self.workflow_text
            )

        self.assertEqual(errors, [])
        stable_read.assert_called_once_with(verify_ci_workflow.QUALITY_GATE_PATH)

    def test_gate_accepts_exact_limit_and_rejects_one_extra_byte(self) -> None:
        source = self.gate_text.encode("utf-8")
        if not source.endswith(b"\n"):
            source += b"\n"
        padding = external_text.MAX_REPOSITORY_TEXT_BYTES - len(source)
        self.assertGreater(padding, 1)
        exact = source + b"#" + b"x" * (padding - 1)

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "quality_gate.ps1"
            path.write_bytes(exact)
            with mock.patch.object(verify_ci_workflow, "QUALITY_GATE_PATH", path):
                self.assertEqual(
                    verify_ci_workflow.verification_errors(
                        workflow_text=self.workflow_text
                    ),
                    [],
                )
                path.write_bytes(exact + b"x")
                self.assertEqual(
                    verify_ci_workflow.verification_errors(
                        workflow_text=self.workflow_text
                    ),
                    ["CI workflow is invalid"],
                )

    def test_link_or_reparse_gate_is_rejected_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "quality_gate.ps1"
            path.write_text("unused", encoding="utf-8")
            with mock.patch.object(
                verify_ci_workflow,
                "QUALITY_GATE_PATH",
                path,
            ), mock.patch.object(
                external_json,
                "has_link_or_reparse_ancestor",
                return_value=True,
            ), mock.patch.object(external_json.os, "open") as open_file:
                errors = verify_ci_workflow.verification_errors(
                    workflow_text=self.workflow_text
                )

        self.assertEqual(errors, ["CI workflow is invalid"])
        open_file.assert_not_called()

    def test_loader_failure_keeps_cli_error_fixed(self) -> None:
        with mock.patch.object(
            verify_ci_workflow,
            "load_stable_text",
            side_effect=external_json.StableFileError("read"),
            create=True,
        ):
            result = self.run_main()

        self.assertEqual(
            result,
            (1, "ci-workflow-error: CI workflow is invalid\n", ""),
        )
        self.assertNotIn("file cannot be read safely", result[1])

    def test_fully_injected_contract_reads_no_default_gate(self) -> None:
        with mock.patch.object(
            verify_ci_workflow,
            "load_stable_text",
            side_effect=AssertionError("injected gate was read"),
            create=True,
        ) as stable_read:
            errors = verify_ci_workflow.verification_errors(
                workflow_text=self.workflow_text,
                quality_gate_text=self.gate_text,
            )

        self.assertEqual(errors, [])
        stable_read.assert_not_called()

    def test_source_has_one_stable_default_gate_boundary(self) -> None:
        source = Path(verify_ci_workflow.__file__).read_text(encoding="utf-8")
        self.assertNotIn(".read_text(", source)
        self.assertIn("load_stable_text(QUALITY_GATE_PATH)", source)


if __name__ == "__main__":
    unittest.main()
