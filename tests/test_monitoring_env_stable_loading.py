from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import external_json
from scripts import external_text
from scripts import verify_monitoring_assets


FIXED_ENV_ERROR = (
    "Monitoring asset load failed: "
    "Cannot inspect monitoring environment example\n"
)
MAX_MONITORING_ENV_BYTES = 64 * 1024


class MonitoringEnvStableLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assets = verify_monitoring_assets.load_assets()
        self.env_text = external_text.load_stable_text(
            verify_monitoring_assets.ENV_EXAMPLE,
            max_bytes=MAX_MONITORING_ENV_BYTES,
        )

    def run_main(self) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            verify_monitoring_assets,
            "load_assets",
            return_value=self.assets,
        ), mock.patch.object(
            verify_monitoring_assets,
            "_optional_native_checks",
            return_value=([], []),
        ), redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_monitoring_assets.main([])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_env_example_is_loaded_once_without_path_read_text(self) -> None:
        real_read_text = Path.read_text

        def guarded_read_text(path: Path, *args, **kwargs):
            if path == verify_monitoring_assets.ENV_EXAMPLE:
                raise AssertionError("Path.read_text bypassed stable loading")
            return real_read_text(path, *args, **kwargs)

        with mock.patch.object(
            Path,
            "read_text",
            guarded_read_text,
        ), mock.patch.object(
            verify_monitoring_assets,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as stable_read:
            result = self.run_main()

        self.assertEqual(result[0], 0)
        self.assertIn("monitoring-assets-ok", result[1])
        self.assertEqual(result[2], "")
        stable_read.assert_called_once_with(
            verify_monitoring_assets.ENV_EXAMPLE,
            max_bytes=MAX_MONITORING_ENV_BYTES,
        )

    def test_env_accepts_exact_limit_and_rejects_one_extra_byte(self) -> None:
        raw = self.env_text.encode("utf-8")
        if not raw.endswith(b"\n"):
            raw += b"\n"
        prefix = raw + b"#"
        padding = MAX_MONITORING_ENV_BYTES - len(prefix)
        self.assertGreaterEqual(padding, 0)
        exact = prefix + b"x" * padding

        with tempfile.TemporaryDirectory() as temporary:
            replacement = Path(temporary) / ".env.example"
            replacement.write_bytes(exact)
            with mock.patch.object(
                verify_monitoring_assets,
                "ENV_EXAMPLE",
                replacement,
            ):
                self.assertEqual(self.run_main()[0], 0)
                replacement.write_bytes(exact + b"x")
                self.assertEqual(
                    self.run_main(),
                    (1, "", FIXED_ENV_ERROR),
                )

    def test_invalid_utf8_uses_fixed_env_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            replacement = Path(temporary) / ".env.example"
            replacement.write_bytes(b"\xff")
            with mock.patch.object(
                verify_monitoring_assets,
                "ENV_EXAMPLE",
                replacement,
            ):
                result = self.run_main()

        self.assertEqual(result, (1, "", FIXED_ENV_ERROR))
        self.assertNotIn("utf-8", result[2])

    def test_link_or_reparse_env_is_rejected_before_open(self) -> None:
        with mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            return_value=True,
        ), mock.patch.object(external_json.os, "open") as open_file:
            result = self.run_main()

        self.assertEqual(result, (1, "", FIXED_ENV_ERROR))
        open_file.assert_not_called()

    def test_stable_file_shape_failures_keep_env_error_fixed(self) -> None:
        for reason in ("not-regular", "changed"):
            with self.subTest(reason=reason), mock.patch.object(
                verify_monitoring_assets,
                "load_stable_text",
                side_effect=external_json.StableFileError(reason),
                create=True,
            ) as stable_read:
                result = self.run_main()

            self.assertEqual(result, (1, "", FIXED_ENV_ERROR))
            self.assertNotIn(reason, result[2])
            stable_read.assert_called_once_with(
                verify_monitoring_assets.ENV_EXAMPLE,
                max_bytes=MAX_MONITORING_ENV_BYTES,
            )

    def test_invalid_alertmanager_path_keeps_existing_policy_error(self) -> None:
        changed = self.env_text.replace(
            "ALERTMANAGER_CONFIG_FILE=/CHANGE_ME/alertmanager/alertmanager.yml",
            "ALERTMANAGER_CONFIG_FILE=relative.yml",
            1,
        )
        self.assertNotEqual(changed, self.env_text)
        with mock.patch.object(
            verify_monitoring_assets,
            "load_stable_text",
            return_value=changed,
            create=True,
        ):
            result = self.run_main()

        self.assertEqual(
            result,
            (
                1,
                "",
                ".env.example Alertmanager config must use an absolute host path\n",
            ),
        )

    def test_yaml_load_error_keeps_existing_diagnostic(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            verify_monitoring_assets,
            "load_assets",
            side_effect=ValueError("invalid monitoring mapping"),
        ), mock.patch.object(
            verify_monitoring_assets,
            "load_stable_text",
            create=True,
        ) as stable_read, redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_monitoring_assets.main([])

        self.assertEqual(
            (code, stdout.getvalue(), stderr.getvalue()),
            (1, "", "Monitoring asset load failed: invalid monitoring mapping\n"),
        )
        stable_read.assert_not_called()

    def test_source_uses_bounded_stable_env_snapshot(self) -> None:
        source = Path(verify_monitoring_assets.__file__).read_text(
            encoding="utf-8"
        )
        self.assertNotIn("ENV_EXAMPLE.read_text(", source)
        self.assertIn("MAX_MONITORING_ENV_BYTES = 64 * 1024", source)
        self.assertIn(
            "load_stable_text(\n            ENV_EXAMPLE,\n"
            "            max_bytes=MAX_MONITORING_ENV_BYTES,\n        )",
            source,
        )


if __name__ == "__main__":
    unittest.main()
