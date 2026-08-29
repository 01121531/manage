import tempfile
import unittest
from pathlib import Path

from scripts.release_control_lock import ReleaseControlLocked, release_control_lock


class ReleaseControlLockTests(unittest.TestCase):
    def test_second_release_control_is_rejected_without_stale_file_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release.lock"
            with release_control_lock(path):
                with self.assertRaises(ReleaseControlLocked):
                    with release_control_lock(path):
                        self.fail("nested release control unexpectedly acquired the lock")
            self.assertTrue(path.is_file())
            with release_control_lock(path):
                pass


if __name__ == "__main__":
    unittest.main()
