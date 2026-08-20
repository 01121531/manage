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


if __name__ == "__main__":
    unittest.main()
