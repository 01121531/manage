from __future__ import annotations

import math
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from platform import file_boundary
from platform import uploads


class WorkerHeartbeatBoundaryTests(unittest.TestCase):
    def test_reader_uses_one_bounded_stable_ascii_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            heartbeat = Path(directory) / "worker.heartbeat"
            heartbeat.write_bytes(b"123.25")
            with mock.patch.object(
                uploads,
                "read_stable_runtime_bytes",
                wraps=file_boundary.read_stable_runtime_bytes,
                create=True,
            ) as stable_read:
                self.assertTrue(
                    uploads.worker_heartbeat_is_fresh(
                        heartbeat,
                        max_age_seconds=1,
                        now=124,
                    )
                )
            stable_read.assert_called_once_with(
                heartbeat,
                max_bytes=uploads._MAX_WORKER_HEARTBEAT_BYTES,
            )

    def test_exact_limit_is_accepted_and_one_extra_byte_is_false(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            heartbeat = Path(directory) / "worker.heartbeat"
            exact = b"1" + (b"0" * 63)
            self.assertEqual(len(exact), 64)
            timestamp = float(exact.decode("ascii"))
            self.assertTrue(math.isfinite(timestamp))
            heartbeat.write_bytes(exact)
            self.assertTrue(
                uploads.worker_heartbeat_is_fresh(
                    heartbeat,
                    max_age_seconds=1,
                    now=timestamp,
                )
            )

            heartbeat.write_bytes(exact + b"0")
            oversized_timestamp = float((exact + b"0").decode("ascii"))
            self.assertFalse(
                uploads.worker_heartbeat_is_fresh(
                    heartbeat,
                    max_age_seconds=1,
                    now=oversized_timestamp,
                )
            )

    def test_invalid_ascii_empty_and_nonfinite_values_are_false(self) -> None:
        invalid_values = (
            b"",
            b"   \n",
            b"\xff",
            b"nan",
            b"inf",
            b"-inf",
        )
        with tempfile.TemporaryDirectory() as directory:
            heartbeat = Path(directory) / "worker.heartbeat"
            for raw in invalid_values:
                with self.subTest(raw=raw):
                    heartbeat.write_bytes(raw)
                    self.assertFalse(
                        uploads.worker_heartbeat_is_fresh(
                            heartbeat,
                            max_age_seconds=10,
                            now=100,
                        )
                    )

            heartbeat.write_bytes("１２３".encode("utf-8"))
            self.assertFalse(
                uploads.worker_heartbeat_is_fresh(
                    heartbeat,
                    max_age_seconds=10,
                    now=123,
                )
            )

    def test_missing_unstable_or_nonregular_snapshot_is_false(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            heartbeat = Path(directory) / "private-heartbeat"
            self.assertFalse(
                uploads.worker_heartbeat_is_fresh(
                    heartbeat,
                    max_age_seconds=10,
                    now=100,
                )
            )
            with mock.patch.object(
                uploads,
                "read_stable_runtime_bytes",
                side_effect=file_boundary.RuntimeFileError("private-detail"),
                create=True,
            ):
                self.assertFalse(
                    uploads.worker_heartbeat_is_fresh(
                        heartbeat,
                        max_age_seconds=10,
                        now=100,
                    )
                )

    def test_fresh_stale_and_future_timestamp_contract_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            heartbeat = Path(directory) / "worker.heartbeat"
            heartbeat.write_bytes(b"100")
            self.assertTrue(
                uploads.worker_heartbeat_is_fresh(
                    heartbeat,
                    max_age_seconds=10,
                    now=100,
                )
            )
            self.assertTrue(
                uploads.worker_heartbeat_is_fresh(
                    heartbeat,
                    max_age_seconds=10,
                    now=110,
                )
            )
            self.assertFalse(
                uploads.worker_heartbeat_is_fresh(
                    heartbeat,
                    max_age_seconds=10,
                    now=110.001,
                )
            )
            self.assertFalse(
                uploads.worker_heartbeat_is_fresh(
                    heartbeat,
                    max_age_seconds=10,
                    now=99.999,
                )
            )

    def test_max_age_must_be_positive_and_finite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            heartbeat = Path(directory) / "worker.heartbeat"
            heartbeat.write_bytes(b"100")
            for max_age in (0, -1, math.nan, math.inf):
                with self.subTest(max_age=max_age), self.assertRaisesRegex(
                    ValueError,
                    "max_age_seconds must be positive",
                ):
                    uploads.worker_heartbeat_is_fresh(
                        heartbeat,
                        max_age_seconds=max_age,
                        now=100,
                    )

    def test_writer_flushes_and_atomically_replaces_from_same_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            heartbeat = Path(directory) / "nested" / "worker.heartbeat"
            with mock.patch.object(
                uploads.time,
                "time",
                return_value=123.25,
            ), mock.patch.object(
                uploads.os,
                "fsync",
                wraps=os.fsync,
                create=True,
            ) as fsync, mock.patch.object(
                uploads.os,
                "replace",
                wraps=os.replace,
                create=True,
            ) as replace:
                uploads.write_worker_heartbeat(heartbeat)

            fsync.assert_called_once()
            replace.assert_called_once()
            temporary_path, destination = map(Path, replace.call_args.args)
            self.assertEqual(temporary_path.parent, heartbeat.parent)
            self.assertNotEqual(temporary_path, heartbeat)
            self.assertEqual(destination, heartbeat)
            self.assertEqual(heartbeat.read_bytes(), b"123.25")

    def test_failed_replace_preserves_old_file_and_removes_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            heartbeat = root / "worker.heartbeat"
            heartbeat.write_bytes(b"old")
            with mock.patch.object(
                uploads.os,
                "replace",
                side_effect=OSError("private-detail"),
                create=True,
            ), self.assertRaises(OSError):
                uploads.write_worker_heartbeat(heartbeat)

            self.assertEqual(heartbeat.read_bytes(), b"old")
            self.assertEqual(list(root.iterdir()), [heartbeat])

    def test_cleanup_failure_does_not_mask_replace_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            heartbeat = Path(directory) / "worker.heartbeat"
            heartbeat.write_bytes(b"old")
            with mock.patch.object(
                uploads.os,
                "replace",
                side_effect=OSError("replace-detail"),
                create=True,
            ), mock.patch.object(
                uploads.Path,
                "unlink",
                side_effect=PermissionError("cleanup-detail"),
            ), self.assertRaisesRegex(OSError, "replace-detail"):
                uploads.write_worker_heartbeat(heartbeat)

    @unittest.skipIf(os.name == "nt", "POSIX symlink support is required")
    def test_atomic_writer_replaces_leaf_symlink_without_touching_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            victim = root / "victim"
            victim.write_bytes(b"do-not-touch")
            heartbeat = root / "worker.heartbeat"
            heartbeat.symlink_to(victim)

            with mock.patch.object(uploads.time, "time", return_value=123.25):
                uploads.write_worker_heartbeat(heartbeat)

            self.assertEqual(victim.read_bytes(), b"do-not-touch")
            self.assertFalse(heartbeat.is_symlink())
            self.assertEqual(heartbeat.read_bytes(), b"123.25")

    def test_source_has_no_direct_heartbeat_read_or_overwrite(self) -> None:
        source = Path(uploads.__file__).read_text(encoding="utf-8")
        heartbeat_source = source.split(
            "def write_worker_heartbeat", 1
        )[1].split("def run_upload_worker", 1)[0]
        self.assertNotIn(".read_text(", heartbeat_source)
        self.assertNotIn(".write_text(", heartbeat_source)
        self.assertIn("read_stable_runtime_bytes(", heartbeat_source)
        self.assertIn("NamedTemporaryFile(", heartbeat_source)
        self.assertIn("os.fsync(", heartbeat_source)
        self.assertIn("os.replace(", heartbeat_source)


if __name__ == "__main__":
    unittest.main()
