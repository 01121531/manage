from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import external_json
from scripts import secret_scan


class SecretScanStableLoadingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        root_patch = mock.patch.object(secret_scan, "ROOT", self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)

    @staticmethod
    def run_main() -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = secret_scan.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_accepts_exact_limit_and_rejects_one_extra_byte(self) -> None:
        path = self.root / "candidate.txt"
        path.write_bytes(b"x" * secret_scan.MAX_SCANNED_FILE_BYTES)
        self.assertEqual(self.run_main(), (0, "secret-scan-ok\n", ""))

        path.write_bytes(path.read_bytes() + b"x")
        code, stdout, stderr = self.run_main()
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertEqual(
            stderr,
            "Potential secrets found:\ncandidate.txt: cannot scan safely\n",
        )

    def test_uses_one_stable_read_without_path_read_text(self) -> None:
        path = self.root / "candidate.txt"
        path.write_text("safe text", encoding="utf-8")
        with mock.patch.object(
            Path,
            "read_text",
            side_effect=AssertionError("Path.read_text bypassed stable loading"),
        ), mock.patch.object(
            secret_scan,
            "read_stable_bytes",
            wraps=external_json.read_stable_bytes,
            create=True,
        ) as stable_read:
            self.assertEqual(self.run_main(), (0, "secret-scan-ok\n", ""))
        stable_read.assert_called_once_with(
            path,
            max_bytes=secret_scan.MAX_SCANNED_FILE_BYTES,
            allow_empty=True,
        )

    def test_link_or_reparse_candidate_is_rejected_before_open(self) -> None:
        path = self.root / "candidate.txt"
        path.write_text("safe text", encoding="utf-8")
        with mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            return_value=True,
        ), mock.patch.object(external_json.os, "open") as open_file:
            code, _, stderr = self.run_main()
        self.assertEqual(code, 1)
        self.assertEqual(
            stderr,
            "Potential secrets found:\ncandidate.txt: cannot scan safely\n",
        )
        open_file.assert_not_called()

    def test_non_regular_open_candidate_is_rejected(self) -> None:
        path = self.root / "candidate.txt"
        path.write_text("safe text", encoding="utf-8")
        real_fstat = os.fstat

        def non_regular_fstat(descriptor: int):
            metadata = real_fstat(descriptor)
            return SimpleNamespace(
                st_mode=stat.S_IFIFO | 0o600,
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
                st_nlink=metadata.st_nlink,
                st_size=metadata.st_size,
                st_mtime_ns=metadata.st_mtime_ns,
                st_file_attributes=getattr(metadata, "st_file_attributes", 0),
            )

        with mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            return_value=False,
        ), mock.patch.object(external_json.os, "fstat", non_regular_fstat):
            code, _, stderr = self.run_main()
        self.assertEqual(code, 1)
        self.assertEqual(
            stderr,
            "Potential secrets found:\ncandidate.txt: cannot scan safely\n",
        )

    def test_named_candidate_replacement_during_read_is_rejected(self) -> None:
        path = self.root / "candidate.txt"
        path.write_text("safe text", encoding="utf-8")
        real_lstat = Path.lstat
        calls = 0

        def drifting_lstat(candidate: Path):
            nonlocal calls
            metadata = real_lstat(candidate)
            if candidate == path:
                calls += 1
                if calls == 2:
                    return SimpleNamespace(
                        st_mode=metadata.st_mode,
                        st_dev=metadata.st_dev,
                        st_ino=metadata.st_ino,
                        st_nlink=metadata.st_nlink,
                        st_size=metadata.st_size + 1,
                        st_mtime_ns=metadata.st_mtime_ns,
                        st_file_attributes=getattr(
                            metadata, "st_file_attributes", 0
                        ),
                    )
            return metadata

        with mock.patch.object(
            external_json,
            "has_link_or_reparse_ancestor",
            return_value=False,
        ), mock.patch.object(Path, "lstat", drifting_lstat):
            code, _, stderr = self.run_main()
        self.assertEqual(code, 1)
        self.assertEqual(calls, 2)
        self.assertEqual(
            stderr,
            "Potential secrets found:\ncandidate.txt: cannot scan safely\n",
        )

    def test_empty_and_binary_files_keep_existing_non_secret_behavior(self) -> None:
        (self.root / "empty.txt").write_bytes(b"")
        (self.root / "binary.bin").write_bytes(b"\xff\x00\xfe")
        self.assertEqual(self.run_main(), (0, "secret-scan-ok\n", ""))

    def test_sub2_admin_key_pattern_is_rejected_without_echoing_value(self) -> None:
        candidate = "admin-" + ("a" * 64)
        (self.root / "candidate.txt").write_text(candidate, encoding="utf-8")

        code, stdout, stderr = self.run_main()

        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertEqual(
            stderr,
            "Potential secrets found:\ncandidate.txt: matched sub2-admin-key\n",
        )
        self.assertNotIn(candidate, stderr)

    @unittest.skipUnless(os.name == "nt", "Windows synthesizes executable mode bits")
    def test_windows_executable_mode_projection_keeps_binary_skip(self) -> None:
        (self.root / "application.exe").write_bytes(b"\xff\x00\xfe")
        self.assertEqual(self.run_main(), (0, "secret-scan-ok\n", ""))

    def test_read_failure_is_fixed_and_does_not_disclose_os_error(self) -> None:
        (self.root / "candidate.txt").write_text("safe text", encoding="utf-8")
        with mock.patch.object(
            secret_scan,
            "read_stable_bytes",
            side_effect=external_json.StableFileError("read"),
            create=True,
        ):
            code, _, stderr = self.run_main()
        self.assertEqual(code, 1)
        self.assertEqual(
            stderr,
            "Potential secrets found:\ncandidate.txt: cannot scan safely\n",
        )
        self.assertNotIn("file cannot be read safely", stderr)

    def test_traversal_failure_is_fixed_and_does_not_disclose_os_error(self) -> None:
        with mock.patch.object(
            secret_scan.os,
            "walk",
            side_effect=OSError("sensitive traversal detail"),
        ):
            code, stdout, stderr = self.run_main()
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertEqual(
            stderr,
            "Potential secrets found:\nrepository traversal: cannot scan safely\n",
        )
        self.assertNotIn("sensitive traversal detail", stderr)

    def test_source_keeps_pruned_stable_bounded_scan(self) -> None:
        source = Path(secret_scan.__file__).read_text(encoding="utf-8")
        self.assertIn("MAX_SCANNED_FILE_BYTES = 16 * 1024 * 1024", source)
        self.assertIn("in os.walk(", source)
        self.assertIn("followlinks=False", source)
        self.assertIn("onerror=_raise_walk_error", source)
        self.assertNotIn("ROOT.rglob(", source)
        self.assertNotIn("path.read_text(", source)
        self.assertNotIn("path.is_file(", source)


if __name__ == "__main__":
    unittest.main()
