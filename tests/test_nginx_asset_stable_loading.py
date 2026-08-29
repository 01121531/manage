from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import external_json
from scripts import external_text
from scripts import verify_edge_assets
from scripts import verify_nginx_headers
from scripts import verify_nginx_logging


class StableTextLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_accepts_exact_limit_and_rejects_one_extra_byte(self) -> None:
        path = self.root / "asset.conf"
        path.write_bytes(b"x" * external_text.MAX_REPOSITORY_TEXT_BYTES)
        self.assertEqual(
            len(external_text.load_stable_text(path)),
            external_text.MAX_REPOSITORY_TEXT_BYTES,
        )

        path.write_bytes(
            b"x" * (external_text.MAX_REPOSITORY_TEXT_BYTES + 1)
        )
        with self.assertRaises(external_json.StableFileError):
            external_text.load_stable_text(path)

    def test_rejects_invalid_utf8_with_a_fixed_stable_error(self) -> None:
        path = self.root / "asset.conf"
        path.write_bytes(b"\xff")

        with self.assertRaises(external_json.StableFileError) as raised:
            external_text.load_stable_text(path)

        self.assertEqual(str(raised.exception), "file cannot be read safely")

    def test_rejects_link_or_reparse_before_opening(self) -> None:
        path = self.root / "asset.conf"
        path.write_text("safe", encoding="utf-8")

        with mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            return_value=True,
        ), mock.patch.object(external_json.os, "open") as open_file:
            with self.assertRaises(external_json.StableFileError):
                external_text.load_stable_text(path)

        open_file.assert_not_called()


class NginxVerifierStableLoadingTests(unittest.TestCase):
    @staticmethod
    def run_main(main) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_all_nginx_asset_paths_use_the_shared_stable_loader(self) -> None:
        expected = [
            verify_edge_assets.DOCKERFILE,
            verify_edge_assets.RENDERER,
            verify_edge_assets.TEMPLATE,
            verify_edge_assets.ENV_EXAMPLE,
            verify_edge_assets.WEB_DOCKERFILE,
            verify_edge_assets.WEB_CONFIG,
            verify_edge_assets.WEB_VALIDATOR,
            verify_edge_assets.ROOT / "infra" / "nginx" / "slots" / "blue.conf",
            verify_edge_assets.ROOT / "infra" / "nginx" / "slots" / "green.conf",
        ]
        with mock.patch.object(
            Path,
            "read_text",
            side_effect=AssertionError("Path.read_text bypassed stable loading"),
        ), mock.patch.object(
            verify_edge_assets,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as stable_read:
            assets = verify_edge_assets.load_assets()
            self.assertEqual(verify_edge_assets.validate_edge_assets(*assets), [])

        self.assertEqual(
            [call.args[0] for call in stable_read.call_args_list],
            expected,
        )
        for call in stable_read.call_args_list:
            self.assertEqual(call.kwargs, {})

    def test_header_and_logging_verifiers_share_the_stable_loader(self) -> None:
        with mock.patch.object(
            Path,
            "read_text",
            side_effect=AssertionError("Path.read_text bypassed stable loading"),
        ), mock.patch.object(
            verify_nginx_headers,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as header_read, mock.patch.object(
            verify_nginx_logging,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as logging_read:
            self.assertEqual(
                verify_nginx_headers._check_file(
                    verify_nginx_headers.TEMPLATE
                ),
                (True, ""),
            )
            self.assertEqual(
                verify_nginx_headers._check_file(
                    verify_nginx_headers.WEB_CONF
                ),
                (True, ""),
            )
            self.assertEqual(
                verify_nginx_logging.validate_nginx_logging(
                    verify_nginx_logging.load_assets()
                ),
                [],
            )

        self.assertEqual(header_read.call_count, 2)
        self.assertEqual(logging_read.call_count, 2)

    def test_edge_load_failure_is_fixed_and_does_not_disclose_details(self) -> None:
        with mock.patch.object(
            verify_edge_assets,
            "load_assets",
            side_effect=external_json.StableFileError("read"),
        ):
            result = self.run_main(verify_edge_assets.main)

        self.assertEqual(result, (1, "", "Edge asset load failed\n"))

    def test_header_load_failure_is_fixed_and_does_not_disclose_details(self) -> None:
        with mock.patch.object(
            verify_nginx_headers,
            "_check_file",
            side_effect=external_json.StableFileError("read"),
        ):
            result = self.run_main(verify_nginx_headers.main)

        self.assertEqual(result, (1, "", "Unable to load Nginx header assets\n"))

    def test_logging_load_failure_is_fixed_and_does_not_disclose_details(self) -> None:
        with mock.patch.object(
            verify_nginx_logging,
            "load_assets",
            side_effect=external_json.StableFileError("read"),
        ):
            result = self.run_main(verify_nginx_logging.main)

        self.assertEqual(result, (1, "", "Unable to load Nginx logging assets\n"))

    def test_sources_have_no_direct_nginx_asset_text_reads(self) -> None:
        for module in (
            verify_edge_assets,
            verify_nginx_headers,
            verify_nginx_logging,
        ):
            with self.subTest(module=module.__name__):
                source = Path(module.__file__).read_text(encoding="utf-8")
                self.assertNotIn(".read_text(", source)
                self.assertIn("load_stable_text", source)


if __name__ == "__main__":
    unittest.main()
