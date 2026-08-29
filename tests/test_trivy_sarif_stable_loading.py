from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import scripts.external_json as external_json
from scripts.report_trivy_sarif import findings
from scripts.scan_third_party_images import ThirdPartyScanError, _validate_sarif


_SARIF_LIMIT = 32 * 1024 * 1024
_IMAGE = "postgres@sha256:" + "a" * 64


def _sarif() -> dict[str, object]:
    return {
        "runs": [
            {
                "tool": {"driver": {"name": "Trivy"}},
                "properties": {"imageName": _IMAGE},
                "results": [],
            }
        ]
    }


def _write_sarif(path: Path) -> bytes:
    raw = json.dumps(_sarif(), separators=(",", ":")).encode("utf-8")
    path.write_bytes(raw)
    return raw


def _consume_reporter(path: Path) -> None:
    findings(path)


def _consume_scan_gate(path: Path) -> None:
    _validate_sarif(path, _IMAGE)


_CONSUMERS = (
    ("reporter", _consume_reporter, OSError),
    ("scan-gate", _consume_scan_gate, ThirdPartyScanError),
)


class TrivySarifStableLoadingTests(unittest.TestCase):
    def test_both_consumers_reject_same_value_duplicate_keys(self) -> None:
        for name, consume, error in _CONSUMERS:
            with self.subTest(consumer=name), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "report.sarif"
                payload = _sarif()
                raw = json.dumps(payload, separators=(",", ":"))
                duplicate = (
                    "{"
                    + '"runs":'
                    + json.dumps(payload["runs"], separators=(",", ":"))
                    + ","
                    + raw[1:]
                )
                path.write_text(duplicate, encoding="utf-8")

                duplicate_error = (
                    json.JSONDecodeError if name == "reporter" else error
                )
                with self.assertRaises(duplicate_error):
                    consume(path)

    def test_both_consumers_reject_files_over_32_mib(self) -> None:
        for name, consume, error in _CONSUMERS:
            with self.subTest(consumer=name), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "report.sarif"
                raw = json.dumps(_sarif()).encode("utf-8")
                path.write_bytes(raw + b" " * (_SARIF_LIMIT + 1 - len(raw)))

                with self.assertRaises(error):
                    consume(path)

    def test_both_consumers_reject_link_or_reparse_paths(self) -> None:
        for name, consume, error in _CONSUMERS:
            with self.subTest(consumer=name), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "report.sarif"
                _write_sarif(path)

                with mock.patch.object(
                    external_json,
                    "has_link_or_reparse_ancestor",
                    side_effect=lambda candidate, rejected=path: candidate == rejected,
                ), self.assertRaises(error):
                    consume(path)

    def test_both_consumers_reject_open_file_shape_drift(self) -> None:
        for name, consume, error in _CONSUMERS:
            with self.subTest(consumer=name), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "report.sarif"
                _write_sarif(path)
                calls = 0
                real_fstat = external_json.os.fstat

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
                            st_file_attributes=getattr(
                                metadata,
                                "st_file_attributes",
                                0,
                            ),
                        )
                    return metadata

                with mock.patch.object(
                    external_json.os,
                    "fstat",
                    side_effect=drifting_fstat,
                ), self.assertRaises(error):
                    consume(path)
                self.assertEqual(calls, 2)


if __name__ == "__main__":
    unittest.main()
