import unittest

from scripts.verify_ci_workflow import verification_errors


class CiWorkflowTests(unittest.TestCase):
    def test_ci_builds_and_uploads_verified_windows_release(self) -> None:
        self.assertEqual(verification_errors(), [])


if __name__ == "__main__":
    unittest.main()
