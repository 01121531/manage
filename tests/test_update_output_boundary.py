from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import update_client
from scripts import external_json


class UpdateOutputBoundaryTests(unittest.TestCase):
    def test_notice_delegates_one_closed_bounded_payload_to_atomic_writer(self) -> None:
        code = update_client._ROLLED_BACK_NOTICE
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            update_client,
            "update_cache_dir",
            return_value=Path(directory),
        ), mock.patch.object(
            update_client,
            "write_atomic_bytes",
            create=True,
        ) as atomic_write:
            update_client._write_update_notice(code)

        atomic_write.assert_called_once()
        path, raw = atomic_write.call_args.args
        self.assertEqual(path, Path(directory).resolve() / "update-notice.json")
        self.assertLessEqual(len(raw), 256)
        self.assertEqual(json.loads(raw.decode("utf-8")), {"code": code})

    def test_unknown_notice_code_has_no_file_side_effect(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            update_client,
            "update_cache_dir",
            return_value=Path(directory) / "updates",
        ), mock.patch.object(
            update_client,
            "write_atomic_bytes",
            create=True,
        ) as atomic_write:
            update_client._write_update_notice("unreviewed-code")

        atomic_write.assert_not_called()
        self.assertFalse((Path(directory) / "updates").exists())

    def test_notice_writer_accepts_exact_limit_and_rejects_one_extra(self) -> None:
        payload_overhead = len(b'{"code":""}')
        exact_code = "x" * (256 - payload_overhead)
        oversized_code = exact_code + "x"
        messages = {exact_code: "exact", oversized_code: "oversized"}
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            update_client,
            "update_cache_dir",
            return_value=Path(directory),
        ), mock.patch.object(
            update_client,
            "_NOTICE_MESSAGES",
            messages,
        ), mock.patch.object(
            update_client,
            "write_atomic_bytes",
            create=True,
        ) as atomic_write:
            update_client._write_update_notice(exact_code)
            update_client._write_update_notice(oversized_code)

        atomic_write.assert_called_once()
        self.assertEqual(len(atomic_write.call_args.args[1]), 256)

    def test_notice_writer_failure_is_best_effort_without_partial_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            update_client,
            "update_cache_dir",
            return_value=Path(directory),
        ), mock.patch.object(
            update_client,
            "write_atomic_bytes",
            side_effect=OSError("private-output-detail"),
            create=True,
        ):
            update_client._write_update_notice(update_client._ROLLED_BACK_NOTICE)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_replace_failure_preserves_old_notice_and_cleans_temporary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            notice = cache / "update-notice.json"
            old_notice = b'{"code":"old-reviewed-code"}'
            notice.write_bytes(old_notice)
            with mock.patch.object(
                update_client,
                "update_cache_dir",
                return_value=cache,
            ), mock.patch.object(
                external_json.os,
                "replace",
                side_effect=OSError("private-replace-detail"),
            ):
                update_client._write_update_notice(update_client._ROLLED_BACK_NOTICE)

            self.assertEqual(notice.read_bytes(), old_notice)
            self.assertEqual(list(cache.glob(".update-notice.json.*.tmp")), [])

    def test_notice_consumer_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            notice = cache / "update-notice.json"
            notice.write_text(
                json.dumps(
                    {
                        "code": update_client._ROLLED_BACK_NOTICE,
                        "detail": "private-output-detail",
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(
                update_client,
                "update_cache_dir",
                return_value=cache,
            ):
                self.assertIsNone(update_client.consume_update_notice())
            self.assertFalse(notice.exists())

    def test_apply_cli_does_not_persist_raw_update_error(self) -> None:
        private_detail = "SENSITIVE /private/path token=private-value"
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "updates"
            with mock.patch.object(
                update_client,
                "apply_downloaded_update",
                side_effect=update_client.UpdateError(private_detail),
            ), mock.patch.object(
                update_client,
                "update_cache_dir",
                return_value=cache,
            ):
                result = update_client.apply_update_cli(
                    [
                        "--apply-update",
                        "--package",
                        str(cache / "package.exe"),
                        "--target",
                        str(Path(directory) / "Manage.exe"),
                        "--sha256",
                        "a" * 64,
                        "--parent-pid",
                        "123",
                    ]
                )

            self.assertEqual(result, 1)
            self.assertFalse(cache.exists())

    def test_sources_use_shared_notice_writer_and_no_error_log(self) -> None:
        source = Path(update_client.__file__).read_text(encoding="utf-8")
        notice_source = source.split("def _write_update_notice", 1)[1].split(
            "def consume_update_notice", 1
        )[0]
        cli_source = source.split("def apply_update_cli", 1)[1].split(
            "__all__", 1
        )[0]

        self.assertIn("write_atomic_bytes(", notice_source)
        self.assertNotIn(".write_text(", notice_source)
        self.assertNotIn("os.replace(", notice_source)
        self.assertNotIn("update-error.log", cli_source)
        self.assertNotIn(".write_text(", cli_source)


if __name__ == "__main__":
    unittest.main()
