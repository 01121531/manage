from contextlib import redirect_stderr
import hashlib
import io
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts import create_update_manifest
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
        self.assertEqual(value["size"], 1024 * 1024)
        self.assertEqual(
            value["sha256"],
            hashlib.sha256(b"MZ" + b"x" * (1024 * 1024 - 2)).hexdigest(),
        )

    def test_rejects_unsafe_version_or_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / "app.exe"
            exe.write_bytes(b"x" * (1024 * 1024))
            with self.assertRaises(ValueError):
                build_manifest(exe, "latest", "01121531/manage")
            with self.assertRaises(ValueError):
                build_manifest(exe, "1.0.0", "https://example.com/repo")

    def test_exact_size_limits_are_accepted_and_one_byte_outside_is_rejected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            create_update_manifest,
            "MIN_EXE_BYTES",
            4,
        ), mock.patch.object(create_update_manifest, "MAX_EXE_BYTES", 8):
            exe = Path(directory) / ASSET_NAME
            for size in (4, 8):
                with self.subTest(size=size):
                    exe.write_bytes(b"x" * size)
                    value = build_manifest(exe, "1.2.3", "01121531/manage")
                    self.assertEqual(value["size"], size)
                    self.assertEqual(
                        value["sha256"], hashlib.sha256(b"x" * size).hexdigest()
                    )
            for size in (0, 3, 9):
                with self.subTest(size=size):
                    exe.write_bytes(b"x" * size)
                    with self.assertRaisesRegex(
                        ValueError,
                        "^EXE size is outside the updater safety boundary$",
                    ):
                        build_manifest(exe, "1.2.3", "01121531/manage")

    def test_exe_is_streamed_without_path_read_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / ASSET_NAME
            exe.write_bytes(b"x" * (1024 * 1024 + 1))
            with mock.patch.object(
                Path,
                "read_bytes",
                side_effect=AssertionError("whole-file read must not be used"),
            ):
                value = build_manifest(exe, "1.2.3", "01121531/manage")
        self.assertEqual(value["size"], 1024 * 1024 + 1)

    def test_short_or_appended_descriptor_stream_is_rejected(self) -> None:
        class RecordingStream(io.BytesIO):
            def __init__(self, payload: bytes) -> None:
                super().__init__(payload)
                self.read_sizes: list[int] = []

            def read(self, size: int = -1) -> bytes:
                self.read_sizes.append(size)
                return super().read(size)

        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / ASSET_NAME
            expected_size = 1024 * 1024
            exe.write_bytes(b"x" * expected_size)
            for observed_size in (expected_size - 1, expected_size + 1):
                stream = RecordingStream(b"x" * observed_size)
                with self.subTest(observed_size=observed_size), mock.patch.object(
                    create_update_manifest.os,
                    "fdopen",
                    return_value=stream,
                ):
                    with self.assertRaisesRegex(
                        ValueError,
                        "^EXE cannot be read safely$",
                    ):
                        build_manifest(exe, "1.2.3", "01121531/manage")
                self.assertTrue(stream.read_sizes)
                self.assertEqual(
                    set(stream.read_sizes),
                    {create_update_manifest.HASH_CHUNK_BYTES},
                )

    def test_link_or_reparse_exe_is_rejected_before_open(self) -> None:
        exe = Path("release/assets/email-platform-windows.exe")
        with mock.patch.object(
            create_update_manifest,
            "has_link_or_reparse_ancestor",
            return_value=True,
        ), mock.patch.object(create_update_manifest.os, "open") as open_file:
            with self.assertRaisesRegex(
                ValueError,
                "^EXE cannot be read safely$",
            ):
                build_manifest(exe, "1.2.3", "01121531/manage")
        open_file.assert_not_called()

    def test_non_regular_open_exe_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / ASSET_NAME
            exe.write_bytes(b"x" * (1024 * 1024))
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
                    st_ctime_ns=metadata.st_ctime_ns,
                    st_file_attributes=getattr(metadata, "st_file_attributes", 0),
                )

            with mock.patch.object(
                create_update_manifest.os,
                "fstat",
                side_effect=non_regular_fstat,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "^EXE cannot be read safely$",
                ):
                    build_manifest(exe, "1.2.3", "01121531/manage")

    def test_open_exe_shape_drift_is_rejected_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / "sensitive-build-name.exe"
            exe.write_bytes(b"x" * (1024 * 1024))
            real_fstat = os.fstat
            calls = 0

            def drifting_fstat(descriptor: int):
                nonlocal calls
                calls += 1
                metadata = real_fstat(descriptor)
                if calls == 2:
                    return SimpleNamespace(
                        st_mode=metadata.st_mode,
                        st_dev=metadata.st_dev,
                        st_ino=metadata.st_ino,
                        st_nlink=metadata.st_nlink,
                        st_size=metadata.st_size + 1,
                        st_mtime_ns=metadata.st_mtime_ns,
                        st_ctime_ns=metadata.st_ctime_ns,
                        st_file_attributes=getattr(
                            metadata, "st_file_attributes", 0
                        ),
                    )
                return metadata

            with mock.patch.object(
                create_update_manifest.os,
                "fstat",
                side_effect=drifting_fstat,
            ):
                with self.assertRaises(ValueError) as caught:
                    build_manifest(exe, "1.2.3", "01121531/manage")

        self.assertEqual(str(caught.exception), "EXE cannot be read safely")
        self.assertNotIn(exe.name, str(caught.exception))
        self.assertEqual(calls, 2)

    def test_open_exe_mode_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / ASSET_NAME
            exe.write_bytes(b"x" * (1024 * 1024))
            real_fstat = os.fstat
            calls = 0

            def drifting_fstat(descriptor: int):
                nonlocal calls
                calls += 1
                metadata = real_fstat(descriptor)
                if calls == 2:
                    return SimpleNamespace(
                        st_mode=metadata.st_mode ^ stat.S_IWUSR,
                        st_dev=metadata.st_dev,
                        st_ino=metadata.st_ino,
                        st_nlink=metadata.st_nlink,
                        st_size=metadata.st_size,
                        st_mtime_ns=metadata.st_mtime_ns,
                        st_ctime_ns=metadata.st_ctime_ns,
                        st_file_attributes=getattr(
                            metadata, "st_file_attributes", 0
                        ),
                    )
                return metadata

            with mock.patch.object(
                create_update_manifest.os,
                "fstat",
                side_effect=drifting_fstat,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "^EXE cannot be read safely$",
                ):
                    build_manifest(exe, "1.2.3", "01121531/manage")
        self.assertEqual(calls, 2)

    def test_named_exe_replacement_during_read_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / ASSET_NAME
            exe.write_bytes(b"x" * (1024 * 1024))
            real_lstat = Path.lstat
            calls = 0

            def replacing_lstat(path: Path):
                nonlocal calls
                calls += 1
                metadata = real_lstat(path)
                if calls == 2:
                    return SimpleNamespace(
                        st_mode=metadata.st_mode,
                        st_dev=metadata.st_dev,
                        st_ino=metadata.st_ino + 1,
                        st_nlink=metadata.st_nlink,
                        st_size=metadata.st_size,
                        st_mtime_ns=metadata.st_mtime_ns,
                        st_ctime_ns=metadata.st_ctime_ns,
                        st_file_attributes=getattr(
                            metadata, "st_file_attributes", 0
                        ),
                    )
                return metadata

            with mock.patch.object(
                create_update_manifest,
                "has_link_or_reparse_ancestor",
                return_value=False,
            ), mock.patch.object(Path, "lstat", replacing_lstat):
                with self.assertRaisesRegex(
                    ValueError,
                    "^EXE cannot be read safely$",
                ):
                    build_manifest(exe, "1.2.3", "01121531/manage")
        self.assertEqual(calls, 2)

    def test_cli_reports_a_fixed_error_without_creating_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "update-manifest.json"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = create_update_manifest.main(
                    [
                        "--exe",
                        str(root / "private-build-name.exe"),
                        "--version",
                        "1.2.3",
                        "--repository",
                        "01121531/manage",
                        "--output",
                        str(output),
                    ]
                )
        self.assertEqual(result, 1)
        self.assertEqual(stderr.getvalue().strip(), "update-manifest-invalid")
        self.assertFalse(output.exists())

    def test_repository_source_keeps_stable_streaming_exe_read(self) -> None:
        source = Path(create_update_manifest.__file__).read_text(encoding="utf-8")
        self.assertNotIn(".read_bytes()", source)
        for marker in (
            "MIN_EXE_BYTES = 1024 * 1024",
            "MAX_EXE_BYTES = 200 * 1024 * 1024",
            "HASH_CHUNK_BYTES = 1024 * 1024",
            "has_link_or_reparse_ancestor(exe)",
            "os.fstat(descriptor)",
            "stream.read(HASH_CHUNK_BYTES)",
        ):
            self.assertIn(marker, source)


if __name__ == "__main__":
    unittest.main()
