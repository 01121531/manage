from __future__ import annotations

from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import external_json
from scripts import external_text
from scripts import verify_phase6_evidence_outputs


FIXED_READ_ERROR = "phase6-evidence-output-error: required file cannot be read\n"
MAX_PHASE6_SOURCE_BYTES = 64 * 1024
SOURCE_NAMES = (
    "PHASE6_SCRIPT",
    "TRAINING_SCRIPT",
    "OUTPUT_POLICY_SCRIPT",
)


class Phase6EvidenceOutputStableLoadingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.paths = tuple(
            getattr(verify_phase6_evidence_outputs, name)
            for name in SOURCE_NAMES
        )
        cls.sources = tuple(
            external_text.load_stable_text(path)
            for path in cls.paths
        )

    @staticmethod
    def run_main(**replacements: Path) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with ExitStack() as stack:
            for name, path in replacements.items():
                stack.enter_context(
                    mock.patch.object(
                        verify_phase6_evidence_outputs,
                        name,
                        path,
                    )
                )
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = verify_phase6_evidence_outputs.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_three_sources_are_loaded_once_without_path_read_text(self) -> None:
        real_read_text = Path.read_text

        def guarded_read_text(path: Path, *args, **kwargs):
            if path in self.paths:
                raise AssertionError("Path.read_text bypassed stable loading")
            return real_read_text(path, *args, **kwargs)

        with mock.patch.object(
            Path,
            "read_text",
            guarded_read_text,
        ), mock.patch.object(
            verify_phase6_evidence_outputs,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as stable_read:
            result = self.run_main()

        self.assertEqual(
            result,
            (
                0,
                "phase6-evidence-output-ok "
                "external-write-once-preflight-publish-verify\n",
                "",
            ),
        )
        self.assertEqual(
            stable_read.call_args_list,
            [
                mock.call(path, max_bytes=MAX_PHASE6_SOURCE_BYTES)
                for path in self.paths
            ],
        )

    def test_each_source_accepts_exact_limit_and_rejects_one_extra_byte(self) -> None:
        for name, source in zip(SOURCE_NAMES, self.sources, strict=True):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                replacement = Path(temporary) / f"{name.lower()}.py"
                raw = source.encode("utf-8")
                if not raw.endswith(b"\n"):
                    raw += b"\n"
                prefix = raw + b"#"
                padding = MAX_PHASE6_SOURCE_BYTES - len(prefix)
                self.assertGreaterEqual(padding, 0)
                exact = prefix + b"x" * padding
                replacement.write_bytes(exact)

                self.assertEqual(self.run_main(**{name: replacement})[0], 0)
                replacement.write_bytes(exact + b"x")
                self.assertEqual(
                    self.run_main(**{name: replacement}),
                    (1, "", FIXED_READ_ERROR),
                )

    def test_invalid_utf8_uses_fixed_read_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            replacement = Path(temporary) / "phase6_rehearsal.py"
            replacement.write_bytes(b"\xff")
            result = self.run_main(PHASE6_SCRIPT=replacement)

        self.assertEqual(result, (1, "", FIXED_READ_ERROR))
        self.assertNotIn("utf-8", result[2])

    def test_link_or_reparse_source_is_rejected_before_open(self) -> None:
        with mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            return_value=True,
        ), mock.patch.object(external_json.os, "open") as open_file:
            result = self.run_main()

        self.assertEqual(result, (1, "", FIXED_READ_ERROR))
        open_file.assert_not_called()

    def test_stable_file_shape_failures_keep_read_error_fixed(self) -> None:
        for reason in ("not-regular", "changed"):
            with self.subTest(reason=reason), mock.patch.object(
                verify_phase6_evidence_outputs,
                "load_stable_text",
                side_effect=external_json.StableFileError(reason),
                create=True,
            ) as stable_read:
                result = self.run_main()

            self.assertEqual(result, (1, "", FIXED_READ_ERROR))
            self.assertNotIn(reason, result[2])
            stable_read.assert_called_once_with(
                verify_phase6_evidence_outputs.PHASE6_SCRIPT,
                max_bytes=MAX_PHASE6_SOURCE_BYTES,
            )

    def test_syntax_error_keeps_existing_ast_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            replacement = Path(temporary) / "phase6_rehearsal.py"
            replacement.write_text("not python )\n", encoding="utf-8")
            result = self.run_main(PHASE6_SCRIPT=replacement)

        self.assertEqual(
            result,
            (
                1,
                "",
                "phase6-evidence-output-error: Phase 6 evidence output assets "
                "must parse as Python\n",
            ),
        )

    def test_injected_contract_sources_do_not_read_files(self) -> None:
        with mock.patch.object(
            Path,
            "read_text",
            side_effect=AssertionError("unexpected default text read"),
        ), mock.patch.object(
            verify_phase6_evidence_outputs,
            "load_stable_text",
            side_effect=AssertionError("unexpected stable text read"),
            create=True,
        ):
            errors = verify_phase6_evidence_outputs.phase6_output_contract_errors(
                *self.sources
            )

        self.assertEqual(errors, [])

    def test_source_uses_bounded_stable_snapshots(self) -> None:
        source = Path(verify_phase6_evidence_outputs.__file__).read_text(
            encoding="utf-8"
        )
        for name in SOURCE_NAMES:
            self.assertNotIn(f"{name}.read_text(", source)
        self.assertIn("MAX_PHASE6_SOURCE_BYTES = 64 * 1024", source)
        self.assertIn(
            "load_stable_text(\n            PHASE6_SCRIPT,\n"
            "            max_bytes=MAX_PHASE6_SOURCE_BYTES,\n        )",
            source,
        )


if __name__ == "__main__":
    unittest.main()
