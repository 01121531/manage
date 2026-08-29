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

import yaml

from scripts import external_json
from scripts import external_text
from scripts import verify_rolling_release


YAML_ASSET = "docker-compose.rolling.yml"
TEXT_ASSETS = (
    "infra/nginx/email-platform.conf.template",
    "scripts/rolling_release.py",
    "scripts/rolling_release_evidence.py",
    "scripts/deploy_release.py",
    "scripts/rollback_release.py",
    "platform/migrations/versions/0024_schema_compatibility.py",
    "infra/nginx/slots/blue.conf",
    "infra/nginx/slots/green.conf",
)
FIXED_ERROR = "Cannot inspect rolling release assets"


class RollingReleaseVerifierStableLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = verify_rolling_release.ROOT
        self.documents = {
            relative: external_text.load_stable_text(self.root / relative)
            for relative in TEXT_ASSETS
        }
        self.compose = verify_rolling_release.load_unique_yaml_with_text(
            self.root / YAML_ASSET
        )

    @staticmethod
    def _run_main() -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_rolling_release.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def _selective_loader(self, target: Path, replacement: Path | None = None):
        def load(path: Path, *, max_bytes: int) -> str:
            if path == target:
                return external_text.load_stable_text(
                    replacement or path,
                    max_bytes=max_bytes,
                )
            return self.documents[path.relative_to(self.root).as_posix()]

        return load

    @staticmethod
    def _exact_limit(source: str) -> bytes:
        raw = source.encode("utf-8")
        prefix = b"\n#"
        suffix = b"\n"
        padding = 64 * 1024 - len(raw) - len(prefix) - len(suffix)
        if padding < 0:
            raise AssertionError("repository rolling asset exceeds the boundary")
        exact = raw + prefix + (b"x" * padding) + suffix
        if len(exact) != 64 * 1024:
            raise AssertionError("invalid exact-limit fixture")
        return exact

    def test_nine_asset_inventory_uses_one_snapshot_per_asset(self) -> None:
        protected = {self.root / relative for relative in TEXT_ASSETS}
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
            verify_rolling_release,
            "load_unique_yaml_with_text",
            wraps=verify_rolling_release.load_unique_yaml_with_text,
        ) as yaml_read, mock.patch.object(
            verify_rolling_release,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as text_read:
            self.assertEqual(verify_rolling_release.verification_errors(), [])

        yaml_read.assert_called_once_with(self.root / YAML_ASSET)
        self.assertEqual(
            text_read.call_args_list,
            [
                mock.call(
                    self.root / relative,
                    max_bytes=verify_rolling_release.MAX_ROLLING_ASSET_BYTES,
                )
                for relative in TEXT_ASSETS
            ],
        )

    def test_each_text_asset_accepts_exact_limit_and_rejects_one_extra_byte(
        self,
    ) -> None:
        for relative in TEXT_ASSETS:
            target = self.root / relative
            exact = self._exact_limit(self.documents[relative])
            with self.subTest(asset=relative), tempfile.TemporaryDirectory() as temporary:
                replacement = Path(temporary) / Path(relative).name
                replacement.write_bytes(exact)
                with mock.patch.object(
                    verify_rolling_release,
                    "load_unique_yaml_with_text",
                    return_value=self.compose,
                ), mock.patch.object(
                    verify_rolling_release,
                    "load_stable_text",
                    side_effect=self._selective_loader(target, replacement),
                    create=True,
                ):
                    self.assertEqual(verify_rolling_release.verification_errors(), [])
                    replacement.write_bytes(exact + b"x")
                    self.assertEqual(
                        verify_rolling_release.verification_errors(),
                        [FIXED_ERROR],
                    )

    def test_invalid_utf8_for_each_text_asset_uses_fixed_error(self) -> None:
        for relative in TEXT_ASSETS:
            target = self.root / relative
            with self.subTest(asset=relative), tempfile.TemporaryDirectory() as temporary:
                replacement = Path(temporary) / Path(relative).name
                replacement.write_bytes(b"\xff")
                with mock.patch.object(
                    verify_rolling_release,
                    "load_unique_yaml_with_text",
                    return_value=self.compose,
                ), mock.patch.object(
                    verify_rolling_release,
                    "load_stable_text",
                    side_effect=self._selective_loader(target, replacement),
                    create=True,
                ):
                    self.assertEqual(
                        verify_rolling_release.verification_errors(),
                        [FIXED_ERROR],
                    )

    def test_link_or_reparse_text_assets_are_rejected_before_open(self) -> None:
        real_open = os.open
        for relative in TEXT_ASSETS:
            target = self.root / relative
            with self.subTest(asset=relative), mock.patch.object(
                verify_rolling_release,
                "load_unique_yaml_with_text",
                return_value=self.compose,
            ), mock.patch.object(
                verify_rolling_release,
                "load_stable_text",
                side_effect=self._selective_loader(target),
                create=True,
            ), mock.patch.object(
                external_json,
                "has_link_or_reparse_ancestor",
                side_effect=lambda path: path == target,
            ), mock.patch.object(
                external_json.os,
                "open",
                wraps=real_open,
            ) as open_file:
                self.assertEqual(
                    verify_rolling_release.verification_errors(),
                    [FIXED_ERROR],
                )
            self.assertNotIn(target, [Path(call.args[0]) for call in open_file.call_args_list])

    def test_non_regular_open_text_assets_are_rejected(self) -> None:
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

        for relative in TEXT_ASSETS:
            target = self.root / relative
            with self.subTest(asset=relative), mock.patch.object(
                verify_rolling_release,
                "load_unique_yaml_with_text",
                return_value=self.compose,
            ), mock.patch.object(
                verify_rolling_release,
                "load_stable_text",
                side_effect=self._selective_loader(target),
                create=True,
            ), mock.patch.object(
                external_json.os,
                "fstat",
                side_effect=non_regular_fstat,
            ):
                self.assertEqual(
                    verify_rolling_release.verification_errors(),
                    [FIXED_ERROR],
                )

    def test_read_shape_drift_is_rejected_for_each_text_asset(self) -> None:
        real_fstat = os.fstat
        for relative in TEXT_ASSETS:
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

            target = self.root / relative
            with self.subTest(asset=relative), mock.patch.object(
                verify_rolling_release,
                "load_unique_yaml_with_text",
                return_value=self.compose,
            ), mock.patch.object(
                verify_rolling_release,
                "load_stable_text",
                side_effect=self._selective_loader(target),
                create=True,
            ), mock.patch.object(
                external_json.os,
                "fstat",
                side_effect=drifting_fstat,
            ):
                self.assertEqual(
                    verify_rolling_release.verification_errors(),
                    [FIXED_ERROR],
                )
            self.assertEqual(calls, 2)

    def test_loader_failures_are_fixed_and_cli_does_not_leak_details(self) -> None:
        for relative in TEXT_ASSETS:
            target = self.root / relative

            def failed_loader(path: Path, *, max_bytes: int) -> str:
                if path == target:
                    raise external_json.StableFileError("private-rolling-path")
                return self.documents[path.relative_to(self.root).as_posix()]

            with self.subTest(asset=relative), mock.patch.object(
                verify_rolling_release,
                "load_unique_yaml_with_text",
                return_value=self.compose,
            ), mock.patch.object(
                verify_rolling_release,
                "load_stable_text",
                side_effect=failed_loader,
                create=True,
            ):
                self.assertEqual(
                    verify_rolling_release.verification_errors(),
                    [FIXED_ERROR],
                )
                result = self._run_main()
            self.assertEqual(
                result,
                (1, "", f"rolling-release-error: {FIXED_ERROR}\n"),
            )
            self.assertNotIn("private-rolling-path", result[2])
            self.assertNotIn(str(target), result[2])

    def test_yaml_read_failure_is_fixed_without_hiding_yaml_syntax_drift(self) -> None:
        with mock.patch.object(
            verify_rolling_release,
            "load_unique_yaml_with_text",
            side_effect=external_json.StableFileError("private-compose-path"),
        ), mock.patch.object(
            verify_rolling_release,
            "load_stable_text",
        ) as text_read:
            self.assertEqual(
                verify_rolling_release.verification_errors(),
                [FIXED_ERROR],
            )
            result = self._run_main()
        text_read.assert_not_called()
        self.assertEqual(
            result,
            (1, "", f"rolling-release-error: {FIXED_ERROR}\n"),
        )
        self.assertNotIn("private-compose-path", result[2])

        with mock.patch.object(
            verify_rolling_release,
            "load_unique_yaml_with_text",
            side_effect=yaml.YAMLError("invalid syntax detail"),
        ), mock.patch.object(
            verify_rolling_release,
            "load_stable_text",
            side_effect=lambda path, *, max_bytes: self.documents[
                path.relative_to(self.root).as_posix()
            ],
        ):
            errors = verify_rolling_release.verification_errors()
        self.assertIn("rolling Compose is not valid YAML", errors)
        self.assertNotIn(FIXED_ERROR, errors)

    def test_missing_and_ast_diagnostics_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.assertIn(
                "missing rolling release asset: docker-compose.rolling.yml",
                verify_rolling_release.verification_errors(Path(temporary)),
            )

        rolling = self.root / "scripts/rolling_release.py"

        def invalid_ast_loader(path: Path, *, max_bytes: int) -> str:
            if path == rolling:
                return "def invalid(:\n"
            return self.documents[path.relative_to(self.root).as_posix()]

        with mock.patch.object(
            verify_rolling_release,
            "load_unique_yaml_with_text",
            return_value=self.compose,
        ), mock.patch.object(
            verify_rolling_release,
            "load_stable_text",
            side_effect=invalid_ast_loader,
            create=True,
        ):
            errors = verify_rolling_release.verification_errors()
        self.assertIn("rolling executor is not valid Python", errors)
        self.assertNotIn(FIXED_ERROR, errors)

    def test_source_uses_explicit_bounded_shared_snapshots(self) -> None:
        source = Path(verify_rolling_release.__file__).read_text(encoding="utf-8")
        self.assertNotIn(".read_text(", source)
        self.assertIn("MAX_ROLLING_ASSET_BYTES = 64 * 1024", source)
        self.assertIn("load_stable_text(", source)
        self.assertIn("max_bytes=MAX_ROLLING_ASSET_BYTES", source)
        self.assertIn('texts["infra/nginx/email-platform.conf.template"]', source)
        self.assertIn('texts["scripts/rolling_release.py"]', source)


if __name__ == "__main__":
    unittest.main()
