import unittest
from pathlib import Path

from scripts.verify_release_workflow import ROOT, workflow_errors


class ReleaseWorkflowTests(unittest.TestCase):
    def test_repository_workflow_passes(self) -> None:
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(workflow_errors(text), [])

    def test_missing_integrity_manifest_fails(self) -> None:
        self.assertTrue(workflow_errors("gh release create"))


if __name__ == "__main__":
    unittest.main()
