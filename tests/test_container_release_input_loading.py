from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import scripts.external_json as external_json
from scripts.create_container_release_manifest import build_manifest
from tests.test_container_release_manifest import COMMIT, TAG, write_evidence


_METADATA_LIMIT = 64 * 1024
_ARTIFACT_LIMIT = 32 * 1024 * 1024


def _write_complete_evidence(directory: Path) -> None:
    for name in ("api", "web", "edge"):
        write_evidence(directory, name)


def _load_metadata(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _write_metadata(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


class ContainerReleaseInputLoadingTests(unittest.TestCase):
    def test_metadata_rejects_duplicate_keys_and_files_over_64_kib(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            _write_complete_evidence(directory)
            path = directory / "api.metadata.json"
            metadata = _load_metadata(path)
            raw = json.dumps(metadata, separators=(",", ":"))
            duplicate = "{" + '"tag":' + json.dumps(metadata["tag"]) + "," + raw[1:]

            path.write_text(duplicate, encoding="utf-8")
            with self.subTest(boundary="duplicate-key"), self.assertRaises(
                json.JSONDecodeError
            ):
                build_manifest(directory, tag=TAG, commit=COMMIT)

            encoded = json.dumps(metadata).encode("utf-8")
            path.write_bytes(encoded + b" " * (_METADATA_LIMIT + 1 - len(encoded)))
            with self.subTest(boundary="size"), self.assertRaises(OSError):
                build_manifest(directory, tag=TAG, commit=COMMIT)

    def test_sbom_and_sarif_have_explicit_32_mib_limits(self) -> None:
        cases = (
            ("api.spdx.json", "sbom", "sha256", "missing SBOM artifact: api"),
            (
                "api.trivy.sarif",
                "scan",
                "sha256",
                "missing Trivy scan artifact: api",
            ),
        )
        for filename, section, hash_field, error in cases:
            with self.subTest(artifact=filename), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                _write_complete_evidence(directory)
                artifact = directory / filename
                artifact.write_bytes(b"x" * (_ARTIFACT_LIMIT + 1))
                metadata_path = directory / "api.metadata.json"
                metadata = _load_metadata(metadata_path)
                nested = metadata[section]
                assert isinstance(nested, dict)
                nested[hash_field] = hashlib.sha256(artifact.read_bytes()).hexdigest()
                _write_metadata(metadata_path, metadata)

                with self.assertRaisesRegex(ValueError, error):
                    build_manifest(directory, tag=TAG, commit=COMMIT)

    def test_metadata_sbom_and_sarif_reject_link_or_reparse_paths(self) -> None:
        rejected_paths = (
            "api.metadata.json",
            "api.spdx.json",
            "api.trivy.sarif",
        )
        for filename in rejected_paths:
            with self.subTest(input=filename), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                _write_complete_evidence(directory)
                rejected = directory / filename
                with mock.patch.object(
                    external_json,
                    "has_link_or_reparse_ancestor",
                    side_effect=lambda path, rejected=rejected: path == rejected,
                ), self.assertRaises((OSError, ValueError)):
                    build_manifest(directory, tag=TAG, commit=COMMIT)

    def test_metadata_sbom_and_sarif_reject_open_file_shape_drift(self) -> None:
        cases = (
            ("metadata", 2, OSError),
            ("sbom", 4, ValueError),
            ("sarif", 6, ValueError),
        )
        for boundary, drift_call, error in cases:
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                _write_complete_evidence(directory)
                calls = 0
                real_fstat = external_json.os.fstat

                def drifting_fstat(descriptor: int):
                    nonlocal calls
                    calls += 1
                    metadata = real_fstat(descriptor)
                    if calls == drift_call:
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
                    external_json.os,
                    "fstat",
                    side_effect=drifting_fstat,
                ), self.assertRaises(error):
                    build_manifest(directory, tag=TAG, commit=COMMIT)
                self.assertEqual(calls, drift_call)


if __name__ == "__main__":
    unittest.main()
