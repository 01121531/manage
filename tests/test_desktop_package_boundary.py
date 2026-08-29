import unittest

from scripts.verify_desktop_package import (
    archive_boundary_errors,
    reachable_local_modules,
    source_boundary_errors,
)


class DesktopPackageBoundaryTests(unittest.TestCase):
    def test_platform_entry_import_graph_excludes_legacy_clients(self) -> None:
        reachable = reachable_local_modules()
        self.assertIn("platform_desktop", reachable)
        self.assertNotIn("legacy_app", reachable)
        self.assertNotIn("admin_oauth", reachable)
        self.assertNotIn("oauth_dialog", reachable)
        self.assertEqual(source_boundary_errors(), [])

    def test_archive_gate_rejects_legacy_modules_and_sidecar_settings(self) -> None:
        clean = {
            "app_version",
            "platform_clipboard",
            "platform_client",
            "platform_desktop",
            "platform_login_dialog",
            "session_store",
            "scripts.external_json",
            "update_client",
        }
        self.assertEqual(archive_boundary_errors(clean, ["app.exe.sha256"]), [])
        errors = archive_boundary_errors(
            clean | {"admin_oauth", "oauth_dialog"},
            ["proxy_id.txt", "account_name.txt"],
        )
        self.assertTrue(any("legacy modules" in item for item in errors))
        self.assertTrue(any("legacy configuration" in item for item in errors))


if __name__ == "__main__":
    unittest.main()
