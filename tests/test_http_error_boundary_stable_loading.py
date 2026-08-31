from __future__ import annotations

from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import external_json
from scripts import external_text
from scripts import verify_http_error_boundary


FIXED_SOURCE_ERROR = (
    "http-error-boundary-read: "
    "Cannot inspect HTTP error boundary sources\n"
)
MAX_HTTP_BOUNDARY_SOURCE_BYTES = 320 * 1024


class HttpErrorBoundaryStableLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.asset_paths = (
            verify_http_error_boundary.ERRORS,
            verify_http_error_boundary.APP,
            *verify_http_error_boundary.ROUTES,
        )
        self.asset_texts = {
            path: external_text.load_stable_text(
                path,
                max_bytes=MAX_HTTP_BOUNDARY_SOURCE_BYTES,
            )
            for path in self.asset_paths
        }

    @staticmethod
    def run_main() -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_http_error_boundary.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_all_sources_are_loaded_once_without_path_read_text(self) -> None:
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
            verify_http_error_boundary,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as stable_read:
            result = self.run_main()

        self.assertEqual(
            result,
            (
                0,
                "http-error-boundary-ok fixed-contract-and-reviewed-headers\n",
                "",
            ),
        )
        self.assertEqual(
            Counter(call.args[0] for call in stable_read.call_args_list),
            Counter(self.asset_paths),
        )
        self.assertTrue(
            all(
                call.kwargs == {"max_bytes": MAX_HTTP_BOUNDARY_SOURCE_BYTES}
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
                    padding = MAX_HTTP_BOUNDARY_SOURCE_BYTES - len(prefix)
                    self.assertGreaterEqual(padding, 0)
                    exact = prefix + b"x" * padding
                    replacement = Path(temporary) / f"source-{index}"
                    replacement.write_bytes(exact)

                    def redirected(path: Path, *, max_bytes: int) -> str:
                        return external_text.load_stable_text(
                            replacement if path == target else path,
                            max_bytes=max_bytes,
                        )

                    with mock.patch.object(
                        verify_http_error_boundary,
                        "load_stable_text",
                        side_effect=redirected,
                        create=True,
                    ):
                        self.assertEqual(self.run_main()[0], 0)
                        replacement.write_bytes(exact + b"x")
                        self.assertEqual(
                            self.run_main(),
                            (1, "", FIXED_SOURCE_ERROR),
                        )

    def test_invalid_utf8_for_each_source_uses_fixed_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            replacement = Path(temporary) / "invalid"
            replacement.write_bytes(b"\xff")
            for target in self.asset_paths:
                with self.subTest(path=target):

                    def redirected(path: Path, *, max_bytes: int) -> str:
                        return external_text.load_stable_text(
                            replacement if path == target else path,
                            max_bytes=max_bytes,
                        )

                    with mock.patch.object(
                        verify_http_error_boundary,
                        "load_stable_text",
                        side_effect=redirected,
                        create=True,
                    ):
                        self.assertEqual(
                            self.run_main(),
                            (1, "", FIXED_SOURCE_ERROR),
                        )

    def test_link_or_reparse_source_is_rejected_before_open(self) -> None:
        with mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            return_value=True,
        ), mock.patch.object(external_json.os, "open") as open_file:
            result = self.run_main()

        self.assertEqual(result, (1, "", FIXED_SOURCE_ERROR))
        open_file.assert_not_called()

    def test_stable_file_shape_failures_keep_cli_error_fixed(self) -> None:
        for reason in ("not-regular", "changed"):
            with self.subTest(reason=reason), mock.patch.object(
                verify_http_error_boundary,
                "load_stable_text",
                side_effect=external_json.StableFileError(reason),
                create=True,
            ) as stable_read:
                result = self.run_main()

            self.assertEqual(result, (1, "", FIXED_SOURCE_ERROR))
            self.assertNotIn(reason, result[2])
            stable_read.assert_called_once_with(
                verify_http_error_boundary.ERRORS,
                max_bytes=MAX_HTTP_BOUNDARY_SOURCE_BYTES,
            )

    def test_ast_failure_uses_stable_verifier_code(self) -> None:
        def invalid_errors(path: Path, *, max_bytes: int) -> str:
            if path == verify_http_error_boundary.ERRORS:
                return "def broken("
            return external_text.load_stable_text(path, max_bytes=max_bytes)

        with mock.patch.object(
            verify_http_error_boundary,
            "load_stable_text",
            side_effect=invalid_errors,
            create=True,
        ):
            result = self.run_main()

        self.assertEqual(
            result,
            (
                1,
                "",
                "HTTP error boundary verification failed: syntax:errors\n",
            ),
        )
        self.assertNotIn("broken", result[2])

    def test_source_uses_one_bounded_stable_snapshot_per_asset(self) -> None:
        source = Path(verify_http_error_boundary.__file__).read_text(
            encoding="utf-8"
        )
        self.assertNotIn(".read_text(", source)
        self.assertIn(
            "MAX_HTTP_BOUNDARY_SOURCE_BYTES = 320 * 1024",
            source,
        )
        self.assertIn(
            "load_stable_text(\n                path,",
            source,
        )


if __name__ == "__main__":
    unittest.main()
