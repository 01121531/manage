import tempfile
import unittest
from pathlib import Path

from scripts.create_update_manifest import ASSET_NAME, build_manifest


class UpdateManifestBuildTests(unittest.TestCase):
    def test_builds_official_release_urls_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / ASSET_NAME
            exe.write_bytes(b"MZ" + b"x" * (1024 * 1024 - 2))
            value = build_manifest(exe, "1.2.3", "01121531/manage")
        self.assertEqual(value["version"], "1.2.3")
        self.assertEqual(
            value["download_url"],
            "https://github.com/01121531/manage/releases/download/v1.2.3/"
            + ASSET_NAME,
        )
        self.assertEqual(len(value["sha256"]), 64)

    def test_rejects_unsafe_version_or_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / "app.exe"
            exe.write_bytes(b"x" * (1024 * 1024))
            with self.assertRaises(ValueError):
                build_manifest(exe, "latest", "01121531/manage")
            with self.assertRaises(ValueError):
                build_manifest(exe, "1.0.0", "https://example.com/repo")


if __name__ == "__main__":
    unittest.main()
