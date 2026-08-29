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
from scripts import verify_rollback_assets


FIXED_ERROR = "Cannot inspect rollback assets"


class RollbackAssetStableLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compose_text = verify_rollback_assets.read_stable_yaml_text(
            verify_rollback_assets.COMPOSE
        )
        self.assets = {
            verify_rollback_assets.ENV_EXAMPLE: external_text.load_stable_text(
                verify_rollback_assets.ENV_EXAMPLE
            ),
            verify_rollback_assets.ROLLBACK_SCRIPT: external_text.load_stable_text(
                verify_rollback_assets.ROLLBACK_SCRIPT
            ),
            verify_rollback_assets.ROLLBACK_EVIDENCE: external_text.load_stable_text(
                verify_rollback_assets.ROLLBACK_EVIDENCE
            ),
        }

    @staticmethod
    def _run_main() -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_rollback_assets.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def _selective_loader(self, target: Path, replacement: Path | None = None):
        def load(path: Path, *, max_bytes: int) -> str:
            if path == target:
                return external_text.load_stable_text(
                    replacement or path,
                    max_bytes=max_bytes,
                )
            return self.assets[path]

        return load

    @staticmethod
    def _exact_limit(source: str) -> bytes:
        raw = source.encode("utf-8")
        prefix = b"\n#"
        suffix = b"\n"
        padding = 64 * 1024 - len(raw) - len(prefix) - len(suffix)
        if padding < 0:
            raise AssertionError("repository rollback asset exceeds the boundary")
        exact = raw + prefix + (b"x" * padding) + suffix
        if len(exact) != 64 * 1024:
            raise AssertionError("invalid exact-limit fixture")
        return exact

    def test_default_entrypoint_loads_each_text_asset_once_without_read_text(
        self,
    ) -> None:
        protected = set(self.assets)
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
            verify_rollback_assets,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as stable_read:
            result = self._run_main()

        self.assertEqual(
            result,
            (
                0,
                "rollback-assets-ok image-overrides=required "
                "internal-tls-smoke=verified write-once-evidence=verified "
                "production_acceptance=false\n",
                "",
            ),
        )
        self.assertEqual(
            stable_read.call_args_list,
            [
                mock.call(
                    path,
                    max_bytes=verify_rollback_assets.MAX_ROLLBACK_ASSET_BYTES,
                )
                for path in self.assets
            ],
        )

    def test_each_text_asset_accepts_exact_limit_and_rejects_one_extra_byte(
        self,
    ) -> None:
        for target, source in self.assets.items():
            exact = self._exact_limit(source)
            with self.subTest(asset=target.name), tempfile.TemporaryDirectory() as temporary:
                replacement = Path(temporary) / target.name
                replacement.write_bytes(exact)
                with mock.patch.object(
                    verify_rollback_assets,
                    "read_stable_yaml_text",
                    return_value=self.compose_text,
                ), mock.patch.object(
                    verify_rollback_assets,
                    "load_stable_text",
                    side_effect=self._selective_loader(target, replacement),
                    create=True,
                ):
                    self.assertEqual(self._run_main()[0], 0)
                    replacement.write_bytes(exact + b"x")
                    self.assertEqual(
                        self._run_main(),
                        (1, f"rollback-assets-error: {FIXED_ERROR}\n", ""),
                    )

    def test_invalid_utf8_for_each_text_asset_uses_fixed_error(self) -> None:
        for target in self.assets:
            with self.subTest(asset=target.name), tempfile.TemporaryDirectory() as temporary:
                replacement = Path(temporary) / target.name
                replacement.write_bytes(b"\xff")
                with mock.patch.object(
                    verify_rollback_assets,
                    "read_stable_yaml_text",
                    return_value=self.compose_text,
                ), mock.patch.object(
                    verify_rollback_assets,
                    "load_stable_text",
                    side_effect=self._selective_loader(target, replacement),
                    create=True,
                ):
                    self.assertEqual(
                        self._run_main(),
                        (1, f"rollback-assets-error: {FIXED_ERROR}\n", ""),
                    )

    def test_link_or_reparse_text_assets_are_rejected_before_open(self) -> None:
        real_open = os.open
        for target in self.assets:
            with self.subTest(asset=target.name), mock.patch.object(
                verify_rollback_assets,
                "read_stable_yaml_text",
                return_value=self.compose_text,
            ), mock.patch.object(
                verify_rollback_assets,
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
                    self._run_main(),
                    (1, f"rollback-assets-error: {FIXED_ERROR}\n", ""),
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

        for target in self.assets:
            with self.subTest(asset=target.name), mock.patch.object(
                verify_rollback_assets,
                "read_stable_yaml_text",
                return_value=self.compose_text,
            ), mock.patch.object(
                verify_rollback_assets,
                "load_stable_text",
                side_effect=self._selective_loader(target),
                create=True,
            ), mock.patch.object(
                external_json.os,
                "fstat",
                side_effect=non_regular_fstat,
            ):
                self.assertEqual(
                    self._run_main(),
                    (1, f"rollback-assets-error: {FIXED_ERROR}\n", ""),
                )

    def test_read_shape_drift_is_rejected_for_each_text_asset(self) -> None:
        real_fstat = os.fstat
        for target in self.assets:
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

            with self.subTest(asset=target.name), mock.patch.object(
                verify_rollback_assets,
                "read_stable_yaml_text",
                return_value=self.compose_text,
            ), mock.patch.object(
                verify_rollback_assets,
                "load_stable_text",
                side_effect=self._selective_loader(target),
                create=True,
            ), mock.patch.object(
                external_json.os,
                "fstat",
                side_effect=drifting_fstat,
            ):
                self.assertEqual(
                    self._run_main(),
                    (1, f"rollback-assets-error: {FIXED_ERROR}\n", ""),
                )
            self.assertEqual(calls, 2)

    def test_complete_and_partial_injection_only_load_missing_sources(self) -> None:
        env_text = self.assets[verify_rollback_assets.ENV_EXAMPLE]
        rollback_text = self.assets[verify_rollback_assets.ROLLBACK_SCRIPT]
        evidence_text = self.assets[verify_rollback_assets.ROLLBACK_EVIDENCE]

        with mock.patch.object(
            verify_rollback_assets,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as stable_read:
            self.assertEqual(
                verify_rollback_assets.rollback_asset_errors(
                    self.compose_text,
                    env_text,
                    rollback_text,
                    evidence_text,
                ),
                [],
            )
        stable_read.assert_not_called()

        cases = (
            (rollback_text, None, [verify_rollback_assets.ROLLBACK_EVIDENCE]),
            (None, evidence_text, [verify_rollback_assets.ROLLBACK_SCRIPT]),
            (
                None,
                None,
                [
                    verify_rollback_assets.ROLLBACK_SCRIPT,
                    verify_rollback_assets.ROLLBACK_EVIDENCE,
                ],
            ),
        )
        for rollback_source, evidence_source, expected_paths in cases:
            with self.subTest(expected_paths=expected_paths), mock.patch.object(
                verify_rollback_assets,
                "load_stable_text",
                wraps=external_text.load_stable_text,
                create=True,
            ) as stable_read:
                self.assertEqual(
                    verify_rollback_assets.rollback_asset_errors(
                        self.compose_text,
                        env_text,
                        rollback_source,
                        evidence_source,
                    ),
                    [],
                )
            self.assertEqual(
                [call.args[0] for call in stable_read.call_args_list],
                expected_paths,
            )

    def test_loader_failures_are_fixed_and_do_not_disclose_details(self) -> None:
        for target in self.assets:

            def failed_loader(path: Path, *, max_bytes: int) -> str:
                if path == target:
                    raise external_json.StableFileError("private-rollback-path")
                return self.assets[path]

            with self.subTest(asset=target.name), mock.patch.object(
                verify_rollback_assets,
                "read_stable_yaml_text",
                return_value=self.compose_text,
            ), mock.patch.object(
                verify_rollback_assets,
                "load_stable_text",
                side_effect=failed_loader,
                create=True,
            ):
                result = self._run_main()
            self.assertEqual(
                result,
                (1, f"rollback-assets-error: {FIXED_ERROR}\n", ""),
            )
            self.assertNotIn("private-rollback-path", result[1])
            self.assertNotIn(str(target), result[1])

    def test_missing_evidence_and_ast_diagnostics_are_preserved(self) -> None:
        env_text = self.assets[verify_rollback_assets.ENV_EXAMPLE]
        rollback_text = self.assets[verify_rollback_assets.ROLLBACK_SCRIPT]
        evidence_text = self.assets[verify_rollback_assets.ROLLBACK_EVIDENCE]
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            verify_rollback_assets,
            "ROLLBACK_EVIDENCE",
            Path(temporary) / "missing-evidence.py",
        ):
            errors = verify_rollback_assets.rollback_asset_errors(
                self.compose_text,
                env_text,
                rollback_text,
            )
        self.assertIn(
            "missing rollback evidence asset: missing-evidence.py",
            errors,
        )

        errors = verify_rollback_assets.rollback_asset_errors(
            self.compose_text,
            env_text,
            "def invalid(:\n",
            evidence_text,
        )
        self.assertTrue(
            any(error.startswith("rollback evidence AST is invalid Python:") for error in errors)
        )
        self.assertNotIn(FIXED_ERROR, errors)

    def test_source_uses_explicit_bounded_shared_snapshots(self) -> None:
        source = Path(verify_rollback_assets.__file__).read_text(encoding="utf-8")
        self.assertNotIn(".read_text(", source)
        self.assertIn("MAX_ROLLBACK_ASSET_BYTES = 64 * 1024", source)
        self.assertIn("load_stable_text(", source)
        self.assertIn("max_bytes=MAX_ROLLBACK_ASSET_BYTES", source)
        self.assertIn("evidence_text: str | None = None", source)


if __name__ == "__main__":
    unittest.main()
