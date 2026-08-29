from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import external_json
from scripts import external_text
from scripts import verify_internal_tls


class InternalTlsAssetStableLoadingTests(unittest.TestCase):
    @staticmethod
    def run_main() -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_internal_tls.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_all_text_assets_are_loaded_once_without_path_read_text(self) -> None:
        real_read_text = Path.read_text

        def guarded_read_text(path: Path, *args, **kwargs):
            if path in verify_internal_tls.ASSET_PATHS:
                raise AssertionError("Path.read_text bypassed stable loading")
            return real_read_text(path, *args, **kwargs)

        with mock.patch.object(
            Path,
            "read_text",
            guarded_read_text,
        ), mock.patch.object(
            verify_internal_tls,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as stable_read:
            result = self.run_main()

        self.assertEqual(
            result,
            (
                0,
                "internal-tls-ok cross-container-https-ca-hostname-verification-"
                "enforced\n",
                "",
            ),
        )
        self.assertEqual(
            [call.args[0] for call in stable_read.call_args_list],
            list(verify_internal_tls.ASSET_PATHS),
        )
        self.assertTrue(all(not call.kwargs for call in stable_read.call_args_list))

    def test_text_loader_accepts_exact_limit_and_rejects_one_extra_byte(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "asset.txt"
            path.write_bytes(b"x" * external_text.MAX_REPOSITORY_TEXT_BYTES)
            with mock.patch.object(verify_internal_tls, "ASSET_PATHS", (path,)):
                self.assertEqual(
                    len(verify_internal_tls.load_text_assets()[path]),
                    external_text.MAX_REPOSITORY_TEXT_BYTES,
                )

                path.write_bytes(
                    b"x" * (external_text.MAX_REPOSITORY_TEXT_BYTES + 1)
                )
                with self.assertRaises(external_json.StableFileError):
                    verify_internal_tls.load_text_assets()

    def test_link_or_reparse_failure_is_fixed_and_precedes_open(self) -> None:
        with mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            return_value=True,
        ), mock.patch.object(external_json.os, "open") as open_file:
            result = self.run_main()

        self.assertEqual(result, (1, "", "Internal TLS asset load failed\n"))
        open_file.assert_not_called()

    def test_asset_failure_is_fixed_and_does_not_disclose_details(self) -> None:
        with mock.patch.object(
            verify_internal_tls,
            "load_assets",
            side_effect=external_json.StableFileError("read"),
        ):
            result = self.run_main()

        self.assertEqual(result, (1, "", "Internal TLS asset load failed\n"))
        self.assertNotIn("file cannot be read safely", result[2])

    def test_expiry_module_executes_the_authenticated_source_snapshot(self) -> None:
        path = Path("does-not-exist.py")

        module = verify_internal_tls._load_expiry_monitor(
            path,
            "CERTIFICATE_ENV = {'source': 'stable-snapshot'}\n",
        )

        self.assertEqual(module.CERTIFICATE_ENV, {"source": "stable-snapshot"})
        self.assertEqual(module.__file__, str(path))

    def test_expiry_module_failure_is_fixed_and_does_not_disclose_details(self) -> None:
        assets = verify_internal_tls.load_assets()
        broken_assets = (*assets[:-2], "raise RuntimeError('sensitive detail')\n", assets[-1])
        with mock.patch.object(
            verify_internal_tls,
            "load_assets",
            return_value=broken_assets,
        ):
            result = self.run_main()

        self.assertEqual(
            result,
            (1, "", "Internal TLS expiry monitor load failed\n"),
        )
        self.assertNotIn("sensitive detail", result[2])

    def test_source_has_one_stable_text_snapshot_boundary(self) -> None:
        source = Path(verify_internal_tls.__file__).read_text(encoding="utf-8")
        self.assertNotIn(".read_text(", source)
        self.assertNotIn("spec_from_file_location", source)
        self.assertIn("text_assets = load_text_assets()", source)
        self.assertIn("load_stable_text", source)


if __name__ == "__main__":
    unittest.main()
