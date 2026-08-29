from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import backup_crypto, private_secret_file


class PrivateSecretFileTests(unittest.TestCase):
    def test_reads_one_permission_bound_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "secret"
            path.write_bytes(b"stable-secret")
            if os.name != "nt":
                path.chmod(0o600)
            descriptors: list[int] = []

            def permission(descriptor, _metadata, *, require_read_only):
                descriptors.append(descriptor)
                self.assertFalse(require_read_only)
                return "stable-permissions"

            with mock.patch.object(
                backup_crypto,
                "_validate_key_permissions",
                side_effect=permission,
            ):
                self.assertEqual(
                    private_secret_file.read_private_secret_bytes(
                        path,
                        max_bytes=64,
                    ),
                    b"stable-secret",
                )
        self.assertEqual(len(descriptors), 2)
        self.assertEqual(descriptors[0], descriptors[1])

    def test_read_only_requirement_is_checked_on_both_identity_reads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "secret"
            path.write_bytes(b"stable-secret")
            requirements: list[bool] = []

            def permission(_descriptor, _metadata, *, require_read_only):
                requirements.append(require_read_only)
                return "stable-read-only-permissions"

            with mock.patch.object(
                backup_crypto, "_validate_key_permissions", side_effect=permission
            ):
                self.assertEqual(
                    private_secret_file.read_private_secret_bytes(
                        path, max_bytes=64, require_read_only=True
                    ),
                    b"stable-secret",
                )
        self.assertEqual(requirements, [True, True])

    def test_rejects_hardlink_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "secret"
            alias = root / "alias"
            path.write_bytes(b"stable-secret")
            try:
                os.link(path, alias)
            except OSError as error:
                self.skipTest(f"hard links unavailable: {error}")
            with mock.patch.object(
                backup_crypto,
                "_validate_key_permissions",
                return_value="stable-permissions",
            ), self.assertRaises(private_secret_file.PrivateSecretFileError):
                private_secret_file.read_private_secret_bytes(path, max_bytes=64)

    def test_rejects_permission_fingerprint_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "secret"
            path.write_bytes(b"stable-secret")
            with mock.patch.object(
                backup_crypto,
                "_validate_key_permissions",
                side_effect=("before", "after"),
            ), self.assertRaises(private_secret_file.PrivateSecretFileError):
                private_secret_file.read_private_secret_bytes(path, max_bytes=64)

    @unittest.skipIf(os.name == "nt", "POSIX permission bits are required")
    def test_rejects_group_or_world_access(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "secret"
            path.write_bytes(b"stable-secret")
            for mode in (0o640, 0o604):
                with self.subTest(mode=oct(mode)):
                    path.chmod(mode)
                    with self.assertRaises(private_secret_file.PrivateSecretFileError):
                        private_secret_file.read_private_secret_bytes(path, max_bytes=64)

    def test_rejects_relative_empty_and_oversized_inputs(self) -> None:
        with self.assertRaises(private_secret_file.PrivateSecretFileError):
            private_secret_file.read_private_secret_bytes(
                Path("relative-secret"),
                max_bytes=64,
            )
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            backup_crypto,
            "_validate_key_permissions",
            return_value="stable-permissions",
        ):
            path = Path(directory).resolve() / "secret"
            for raw in (b"", b"x" * 65):
                with self.subTest(size=len(raw)):
                    path.write_bytes(raw)
                    with self.assertRaises(private_secret_file.PrivateSecretFileError):
                        private_secret_file.read_private_secret_bytes(path, max_bytes=64)


if __name__ == "__main__":
    unittest.main()
