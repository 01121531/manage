from __future__ import annotations

from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from scripts import external_json
from scripts import external_text
from scripts import verify_desktop_package


FIXED_SOURCE_ERROR = (
    "desktop-package-error: Cannot inspect desktop package sources\n"
)
MAX_DESKTOP_SOURCE_BYTES = 256 * 1024


class DesktopPackageStableLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.reachable = verify_desktop_package.reachable_local_modules()
        self.asset_paths = (
            verify_desktop_package.BUILD_SCRIPT,
            *self.reachable.values(),
        )
        self.asset_texts = {
            path: external_text.load_stable_text(
                path,
                max_bytes=MAX_DESKTOP_SOURCE_BYTES,
            )
            for path in self.asset_paths
        }

    @staticmethod
    def run_main() -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            sys,
            "argv",
            ["verify_desktop_package.py"],
        ), redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_desktop_package.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_build_and_reachable_sources_are_loaded_once_without_read_text(
        self,
    ) -> None:
        real_read_text = Path.read_text

        def guarded_read_text(path: Path, *args, **kwargs):
            if path in self.asset_paths:
                raise AssertionError("Path.read_text bypassed stable loading")
            return real_read_text(path, *args, **kwargs)

        with mock.patch.object(
            Path,
            "read_text",
            guarded_read_text,
        ), mock.patch.object(
            verify_desktop_package,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as stable_read:
            result = self.run_main()

        self.assertEqual(
            result,
            (0, "desktop-package-ok source platform-only\n", ""),
        )
        self.assertEqual(
            Counter(call.args[0] for call in stable_read.call_args_list),
            Counter(self.asset_paths),
        )
        self.assertTrue(
            all(
                call.kwargs == {"max_bytes": MAX_DESKTOP_SOURCE_BYTES}
                for call in stable_read.call_args_list
            )
        )

    def test_each_source_accepts_exact_limit_and_rejects_one_extra_byte(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for index, target in enumerate(self.asset_paths):
                with self.subTest(path=target):
                    raw = self.asset_texts[target].encode("utf-8")
                    if not raw.endswith(b"\n"):
                        raw += b"\n"
                    prefix = raw + b"#"
                    padding = MAX_DESKTOP_SOURCE_BYTES - len(prefix)
                    self.assertGreaterEqual(padding, 0)
                    exact = prefix + b"x" * padding
                    replacement = Path(temporary) / f"source-{index}"
                    replacement.write_bytes(exact)

                    def redirected(
                        path: Path, *, max_bytes: int
                    ) -> str:
                        return external_text.load_stable_text(
                            replacement if path == target else path,
                            max_bytes=max_bytes,
                        )

                    with mock.patch.object(
                        verify_desktop_package,
                        "load_stable_text",
                        side_effect=redirected,
                        create=True,
                    ):
                        self.assertEqual(self.run_main()[0], 0)
                        replacement.write_bytes(exact + b"x")
                        self.assertEqual(
                            self.run_main(),
                            (1, FIXED_SOURCE_ERROR, ""),
                        )

    def test_invalid_utf8_for_each_source_uses_fixed_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            replacement = Path(temporary) / "invalid"
            replacement.write_bytes(b"\xff")
            for target in self.asset_paths:
                with self.subTest(path=target):

                    def redirected(
                        path: Path, *, max_bytes: int
                    ) -> str:
                        return external_text.load_stable_text(
                            replacement if path == target else path,
                            max_bytes=max_bytes,
                        )

                    with mock.patch.object(
                        verify_desktop_package,
                        "load_stable_text",
                        side_effect=redirected,
                        create=True,
                    ):
                        self.assertEqual(
                            self.run_main(),
                            (1, FIXED_SOURCE_ERROR, ""),
                        )

    def test_link_or_reparse_source_is_rejected_before_open(self) -> None:
        with mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            return_value=True,
        ), mock.patch.object(external_json.os, "open") as open_file:
            result = self.run_main()

        self.assertEqual(result, (1, FIXED_SOURCE_ERROR, ""))
        open_file.assert_not_called()

    def test_stable_file_shape_failures_keep_cli_error_fixed(self) -> None:
        for reason in ("not-regular", "changed"):
            with self.subTest(reason=reason), mock.patch.object(
                verify_desktop_package,
                "load_stable_text",
                side_effect=external_json.StableFileError(reason),
                create=True,
            ) as stable_read:
                result = self.run_main()

            self.assertEqual(result, (1, FIXED_SOURCE_ERROR, ""))
            self.assertNotIn(reason, result[1])
            stable_read.assert_called_once_with(
                verify_desktop_package.BUILD_SCRIPT,
                max_bytes=MAX_DESKTOP_SOURCE_BYTES,
            )

    def test_ast_failure_keeps_cli_error_fixed(self) -> None:
        entry_path = self.reachable["app"]

        def invalid_entry(path: Path, *, max_bytes: int) -> str:
            if path == entry_path:
                return "def broken("
            return external_text.load_stable_text(
                path,
                max_bytes=max_bytes,
            )

        with mock.patch.object(
            verify_desktop_package,
            "load_stable_text",
            side_effect=invalid_entry,
            create=True,
        ):
            result = self.run_main()

        self.assertEqual(result, (1, FIXED_SOURCE_ERROR, ""))
        self.assertNotIn("broken", result[1])

    def test_source_uses_shared_snapshots_and_public_api_keeps_paths(self) -> None:
        source = Path(verify_desktop_package.__file__).read_text(
            encoding="utf-8"
        )
        self.assertNotIn(".read_text(", source)
        self.assertIn("MAX_DESKTOP_SOURCE_BYTES = 256 * 1024", source)
        self.assertIn("load_stable_text(\n        BUILD_SCRIPT,", source)
        self.assertIn(
            "path,\n            max_bytes=MAX_DESKTOP_SOURCE_BYTES,",
            source,
        )
        self.assertTrue(self.reachable)
        self.assertTrue(
            all(isinstance(path, Path) for path in self.reachable.values())
        )


if __name__ == "__main__":
    unittest.main()
