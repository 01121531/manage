import unittest

from scripts.verify_ci_workflow import verification_errors


class CiWorkflowTests(unittest.TestCase):
    def test_ci_builds_and_uploads_verified_windows_release(self) -> None:
        self.assertEqual(verification_errors(), [])

    def test_windows_release_installs_platform_test_dependencies(self) -> None:
        workflow_path = ".github/workflows/ci.yml"
        with open(workflow_path, encoding="utf-8") as workflow_file:
            workflow = workflow_file.read()
        self.assertIn("-r platform/requirements-test.txt", workflow)

    def test_ci_uploads_verified_phase6_rehearsal_evidence(self) -> None:
        with open(".github/workflows/ci.yml", encoding="utf-8") as workflow_file:
            workflow = workflow_file.read()
        with open("scripts/quality_gate.ps1", encoding="utf-8") as gate_file:
            quality_gate = gate_file.read()
        self.assertIn("phase6-ci-rehearsal-${{ github.sha }}", workflow)
        self.assertIn("phase6_rehearsal.py run", quality_gate)
        self.assertIn("phase6_rehearsal.py verify", quality_gate)


if __name__ == "__main__":
    unittest.main()
