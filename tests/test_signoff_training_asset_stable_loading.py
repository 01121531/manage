from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from scripts import external_json
from scripts import external_text
from scripts import verify_signoff_template
from scripts import verify_training_assets


class SignoffTrainingAssetStableLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signoff_text = external_text.load_stable_text(
            verify_signoff_template.TEMPLATE
        )
        self.runbook_text = external_text.load_stable_text(
            verify_training_assets.RUNBOOK
        )

    @staticmethod
    def _run_main(module) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = module.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def _asset_specs(self):
        return (
            (
                "signoff-template",
                verify_signoff_template,
                "TEMPLATE",
                self.signoff_text,
                (1, "", "Missing production signoff template\n"),
            ),
            (
                "training-runbook",
                verify_training_assets,
                "RUNBOOK",
                self.runbook_text,
                (
                    1,
                    "",
                    "training-assets-error: required file cannot be read\n",
                ),
            ),
            (
                "training-signoff",
                verify_training_assets,
                "SIGNOFF",
                self.signoff_text,
                (
                    1,
                    "",
                    "training-assets-error: required file cannot be read\n",
                ),
            ),
        )

    @staticmethod
    def _max_bytes(module) -> int:
        if module is verify_signoff_template:
            return module.MAX_SIGNOFF_TEMPLATE_BYTES
        return module.MAX_TRAINING_ASSET_BYTES

    def _selective_loader(self, target: Path):
        defaults = {
            verify_signoff_template.TEMPLATE: self.signoff_text,
            verify_training_assets.RUNBOOK: self.runbook_text,
            verify_training_assets.SIGNOFF: self.signoff_text,
        }

        def load(path: Path, *, max_bytes: int) -> str:
            if path == target:
                return external_text.load_stable_text(
                    path,
                    max_bytes=max_bytes,
                )
            return defaults[path]

        return load

    def test_default_assets_are_loaded_once_without_path_read_text(self) -> None:
        protected = {
            verify_signoff_template.TEMPLATE,
            verify_training_assets.RUNBOOK,
            verify_training_assets.SIGNOFF,
        }
        real_read_text = Path.read_text

        def guarded_read_text(path: Path, *args, **kwargs):
            if path in protected:
                raise AssertionError("Path.read_text bypassed stable loading")
            return real_read_text(path, *args, **kwargs)

        with mock.patch.object(
            Path,
            "read_text",
            guarded_read_text,
        ), mock.patch.object(
            verify_signoff_template,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as signoff_read:
            self.assertEqual(
                self._run_main(verify_signoff_template),
                (0, "signoff-template-ok readiness-gates-covered\n", ""),
            )
        signoff_read.assert_called_once_with(
            verify_signoff_template.TEMPLATE,
            max_bytes=verify_signoff_template.MAX_SIGNOFF_TEMPLATE_BYTES,
        )

        with mock.patch.object(
            Path,
            "read_text",
            guarded_read_text,
        ), mock.patch.object(
            verify_training_assets,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as training_read:
            self.assertEqual(
                self._run_main(verify_training_assets),
                (
                    0,
                    "training-assets-ok roles-scenarios-independent-review-and-sealed-evidence\n",
                    "",
                ),
            )
        self.assertEqual(
            training_read.call_args_list,
            [
                mock.call(
                    verify_training_assets.RUNBOOK,
                    max_bytes=verify_training_assets.MAX_TRAINING_ASSET_BYTES,
                ),
                mock.call(
                    verify_training_assets.SIGNOFF,
                    max_bytes=verify_training_assets.MAX_TRAINING_ASSET_BYTES,
                ),
            ],
        )

    def test_each_asset_accepts_the_exact_limit_and_rejects_one_extra_byte(
        self,
    ) -> None:
        for name, module, attribute, text, fixed_failure in self._asset_specs():
            source = text.encode("utf-8")
            if not source.endswith(b"\n"):
                source += b"\n"
            limit = 64 * 1024
            padding = limit - len(source)
            self.assertGreater(padding, 1)
            exact = source + b"<!--" + b"x" * (padding - 7) + b"-->"
            self.assertEqual(len(exact), limit)

            with self.subTest(asset=name), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / Path(getattr(module, attribute)).name
                path.write_bytes(exact)
                with mock.patch.object(module, attribute, path):
                    self.assertEqual(self._run_main(module)[0], 0)
                    path.write_bytes(exact + b"x")
                    self.assertEqual(self._run_main(module), fixed_failure)

    def test_invalid_utf8_keeps_fixed_read_diagnostics(self) -> None:
        for name, module, attribute, _, fixed_failure in self._asset_specs():
            with self.subTest(asset=name), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / Path(getattr(module, attribute)).name
                path.write_bytes(b"\xff")
                with mock.patch.object(module, attribute, path):
                    self.assertEqual(self._run_main(module), fixed_failure)

    def test_link_or_reparse_assets_are_rejected_before_open(self) -> None:
        for name, module, attribute, text, fixed_failure in self._asset_specs():
            with self.subTest(asset=name), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / Path(getattr(module, attribute)).name
                path.write_text(text, encoding="utf-8")
                with mock.patch.object(
                    module,
                    attribute,
                    path,
                ), mock.patch.object(
                    module,
                    "load_stable_text",
                    side_effect=self._selective_loader(path),
                    create=True,
                ), mock.patch.object(
                    external_json,
                    "has_link_or_reparse_ancestor",
                    return_value=True,
                ), mock.patch.object(external_json.os, "open") as open_file:
                    self.assertEqual(self._run_main(module), fixed_failure)
                open_file.assert_not_called()

    def test_non_regular_open_assets_are_rejected(self) -> None:
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

        for name, module, attribute, text, fixed_failure in self._asset_specs():
            with self.subTest(asset=name), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / Path(getattr(module, attribute)).name
                path.write_text(text, encoding="utf-8")
                with mock.patch.object(
                    module,
                    attribute,
                    path,
                ), mock.patch.object(
                    module,
                    "load_stable_text",
                    side_effect=self._selective_loader(path),
                    create=True,
                ), mock.patch.object(
                    external_json.os,
                    "fstat",
                    side_effect=non_regular_fstat,
                ):
                    self.assertEqual(self._run_main(module), fixed_failure)

    def test_read_shape_drift_is_rejected_for_each_asset(self) -> None:
        real_fstat = os.fstat

        for name, module, attribute, text, fixed_failure in self._asset_specs():
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

            with self.subTest(asset=name), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / Path(getattr(module, attribute)).name
                path.write_text(text, encoding="utf-8")
                with mock.patch.object(
                    module,
                    attribute,
                    path,
                ), mock.patch.object(
                    module,
                    "load_stable_text",
                    side_effect=self._selective_loader(path),
                    create=True,
                ), mock.patch.object(
                    external_json.os,
                    "fstat",
                    side_effect=drifting_fstat,
                ):
                    self.assertEqual(self._run_main(module), fixed_failure)
            self.assertEqual(calls, 2)

    def test_loader_failures_are_fixed_and_do_not_leak_reasons(self) -> None:
        for name, module, attribute, _, fixed_failure in self._asset_specs():
            target = getattr(module, attribute)

            def failed_loader(path: Path, *, max_bytes: int) -> str:
                if path == target:
                    raise external_json.StableFileError("private-target-path")
                if path == verify_training_assets.RUNBOOK:
                    return self.runbook_text
                return self.signoff_text

            with self.subTest(asset=name), mock.patch.object(
                module,
                "load_stable_text",
                side_effect=failed_loader,
                create=True,
            ):
                result = self._run_main(module)
            self.assertEqual(result, fixed_failure)
            self.assertNotIn("private-target-path", result[2])

    def test_existing_missing_and_policy_drift_diagnostics_are_preserved(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing-signoff.md"
            with mock.patch.object(
                verify_signoff_template,
                "TEMPLATE",
                missing,
            ):
                self.assertEqual(
                    self._run_main(verify_signoff_template),
                    (1, "", "Missing production signoff template\n"),
                )

            drifted = Path(temporary) / "drifted-signoff.md"
            drifted.write_text(
                self.signoff_text.replace("Approved for production", "", 1),
                encoding="utf-8",
            )
            with mock.patch.object(
                verify_signoff_template,
                "TEMPLATE",
                drifted,
            ):
                result = self._run_main(verify_signoff_template)
            self.assertEqual(result[0], 1)
            self.assertIn(
                "Signoff template missing items: Approved for production",
                result[2],
            )

            runbook = Path(temporary) / "role-training.md"
            runbook.write_text(
                self.runbook_text.replace("independent reviewer", "", 1),
                encoding="utf-8",
            )
            with mock.patch.object(
                verify_training_assets,
                "RUNBOOK",
                runbook,
            ):
                result = self._run_main(verify_training_assets)
            self.assertEqual(result[0], 1)
            self.assertIn(
                "training-assets-error: role-training runbook is missing: independent reviewer",
                result[2],
            )

    def test_sources_use_explicit_bounded_stable_text_boundaries(self) -> None:
        expectations = (
            (
                verify_signoff_template,
                "MAX_SIGNOFF_TEMPLATE_BYTES = 64 * 1024",
                "max_bytes=MAX_SIGNOFF_TEMPLATE_BYTES",
            ),
            (
                verify_training_assets,
                "MAX_TRAINING_ASSET_BYTES = 64 * 1024",
                "max_bytes=MAX_TRAINING_ASSET_BYTES",
            ),
        )
        for module, limit_marker, call_marker in expectations:
            with self.subTest(module=module.__name__):
                source = Path(module.__file__).read_text(encoding="utf-8")
                self.assertNotIn(".read_text(", source)
                self.assertIn(limit_marker, source)
                self.assertIn("load_stable_text(", source)
                self.assertIn(call_marker, source)


if __name__ == "__main__":
    unittest.main()
