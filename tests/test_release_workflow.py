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

    def test_phase6_evidence_cannot_be_dropped_or_cross_commit(self) -> None:
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        without_upload = text.replace(
            "      - name: Upload Phase 6 CI rehearsal evidence",
            "      - name: Upload removed evidence",
            1,
        )
        self.assertTrue(workflow_errors(without_upload))

        missing_allowed = text.replace(
            "          if-no-files-found: error",
            "          if-no-files-found: ignore",
            1,
        )
        self.assertTrue(workflow_errors(missing_allowed))

        without_commit_binding = text.replace(
            '            --expected-commit "${{ github.sha }}"',
            "            --expected-commit cross-commit",
            1,
        )
        self.assertTrue(workflow_errors(without_commit_binding))

        without_release_asset = text.replace(
            "          release/assets/phase6-ci-rehearsal.json.sha256\n",
            "",
            1,
        )
        self.assertTrue(workflow_errors(without_release_asset))


if __name__ == "__main__":
    unittest.main()
