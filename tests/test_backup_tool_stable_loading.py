from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import scripts as scripts_package
from scripts import external_json
from scripts import external_text
from scripts import verify_backup_tools


class BackupToolStableLoadingTests(unittest.TestCase):
    @staticmethod
    def run_main() -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = verify_backup_tools.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_all_assets_are_loaded_once_without_path_read_text(self) -> None:
        real_read_text = Path.read_text

        def guarded_read_text(path: Path, *args, **kwargs):
            if path in verify_backup_tools.ASSET_PATHS:
                raise AssertionError("Path.read_text bypassed stable loading")
            return real_read_text(path, *args, **kwargs)

        with mock.patch.object(
            Path,
            "read_text",
            guarded_read_text,
        ), mock.patch.object(
            verify_backup_tools,
            "load_stable_text",
            wraps=external_text.load_stable_text,
            create=True,
        ) as stable_read:
            code, stdout, stderr = self.run_main()

        self.assertEqual(code, 0)
        self.assertEqual(
            stdout,
            "backup-tools-ok encrypted-write-once-platform-keycloak-redis-vault-"
            "audit-archive-validated\n",
        )
        self.assertEqual(stderr, "")
        self.assertEqual(
            [call.args[0] for call in stable_read.call_args_list],
            list(verify_backup_tools.ASSET_PATHS),
        )
        self.assertTrue(all(not call.kwargs for call in stable_read.call_args_list))

    def test_asset_loader_accepts_exact_limit_and_rejects_one_extra_byte(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "asset.txt"
            path.write_bytes(b"x" * external_text.MAX_REPOSITORY_TEXT_BYTES)
            with mock.patch.object(verify_backup_tools, "ASSET_PATHS", (path,)):
                self.assertEqual(
                    len(verify_backup_tools.load_assets()[path]),
                    external_text.MAX_REPOSITORY_TEXT_BYTES,
                )

                path.write_bytes(
                    b"x" * (external_text.MAX_REPOSITORY_TEXT_BYTES + 1)
                )
                with self.assertRaises(external_json.StableFileError):
                    verify_backup_tools.load_assets()

    def test_link_or_reparse_failure_is_fixed_and_precedes_open(self) -> None:
        with mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            return_value=True,
        ), mock.patch.object(external_json.os, "open") as open_file:
            result = self.run_main()

        self.assertEqual(result, (1, "", "Cannot load backup tooling assets\n"))
        open_file.assert_not_called()

    def test_asset_failure_is_fixed_and_does_not_disclose_details(self) -> None:
        with mock.patch.object(
            verify_backup_tools,
            "load_assets",
            side_effect=external_json.StableFileError("read"),
            create=True,
        ):
            result = self.run_main()

        self.assertEqual(result, (1, "", "Cannot load backup tooling assets\n"))
        self.assertNotIn("file cannot be read safely", result[2])

    def test_module_loader_executes_the_authenticated_source_snapshot(self) -> None:
        name = "verified_nonexistent_backup_asset"
        path = Path("does-not-exist.py")
        self.addCleanup(sys.modules.pop, name, None)

        module = verify_backup_tools._load_module(
            path,
            name,
            "VALUE = 'from-stable-snapshot'\n",
        )

        self.assertEqual(module.VALUE, "from-stable-snapshot")
        self.assertEqual(module.__file__, str(path))

    def test_verified_module_loading_restores_the_import_registry(self) -> None:
        name = "scripts.backup_crypto"
        previous_module = sys.modules.get(name)
        had_attribute = hasattr(scripts_package, "backup_crypto")
        previous_attribute = getattr(scripts_package, "backup_crypto", None)

        verify_backup_tools._load_verified_modules(
            verify_backup_tools.load_assets()
        )

        self.assertIs(sys.modules.get(name), previous_module)
        self.assertEqual(hasattr(scripts_package, "backup_crypto"), had_attribute)
        if had_attribute:
            self.assertIs(scripts_package.backup_crypto, previous_attribute)

    def test_source_has_one_stable_snapshot_boundary(self) -> None:
        source = Path(verify_backup_tools.__file__).read_text(encoding="utf-8")
        self.assertNotIn(".read_text(", source)
        self.assertNotIn("spec_from_file_location", source)
        self.assertIn("assets = load_assets()", source)
        self.assertIn("load_stable_text", source)


if __name__ == "__main__":
    unittest.main()
