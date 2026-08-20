import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "release_manifest.py"
SPEC = importlib.util.spec_from_file_location("release_manifest", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
release_manifest = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = release_manifest
SPEC.loader.exec_module(release_manifest)


class ReleaseManifestTests(unittest.TestCase):
    def test_manifest_matches_repository_state(self) -> None:
        manifest = release_manifest.build_release_manifest()
        errors = release_manifest.verify_manifest(manifest)
        self.assertEqual(errors, [])
        self.assertEqual(manifest["release_id"], "0.1.3")
        self.assertEqual(manifest["migration_head"], "0009_upload_policy_governance")
        self.assertIn("worker-mail", manifest["compose_images"])


if __name__ == "__main__":
    unittest.main()
