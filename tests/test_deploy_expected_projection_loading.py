from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import scripts.external_json as external_json
from scripts.deploy_release_evidence import main
from tests.test_deploy_release_evidence import (
    IMAGES,
    ROLLBACK,
    TARGET_INTAKE,
    TARGET_RELEASE,
    THIRD_PARTY_IMAGES,
    _complete_success,
    _recorder,
)


def _arguments(output: Path, target: Path, rollback: Path) -> list[str]:
    arguments = [
        "--input",
        str(output),
        "--expected-target-release",
        str(target),
        "--expected-target-environment",
        TARGET_INTAKE["environment"],
        "--expected-target-intake-manifest-sha256",
        TARGET_INTAKE["manifest_payload_sha256"],
        "--expected-target-intake-requirements-sha256",
        TARGET_INTAKE["requirements_sha256"],
        "--expected-rollback",
        str(rollback),
    ]
    for service, image in {**IMAGES, **THIRD_PARTY_IMAGES}.items():
        arguments.extend(
            [f"--expected-{service.replace('_', '-')}-image", image]
        )
    return arguments


def _write_fixture(root: Path) -> tuple[Path, Path, Path, list[str]]:
    output = root / "deploy-evidence.json"
    target = root / "target.json"
    rollback = root / "rollback.json"
    recorder = _recorder()
    _complete_success(recorder)
    recorder.write(output)
    target.write_text(json.dumps(TARGET_RELEASE), encoding="utf-8")
    rollback.write_text(json.dumps(ROLLBACK), encoding="utf-8")
    return output, target, rollback, _arguments(output, target, rollback)


def _duplicate_top_level_key(document: dict[str, str], key: str) -> str:
    serialized = json.dumps(document, separators=(",", ":"))
    return "{" + json.dumps(key) + ":" + json.dumps(document[key]) + "," + serialized[1:]


def _run(arguments: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        result = main(arguments)
    return result, stdout.getvalue().strip(), stderr.getvalue().strip()


class DeployExpectedProjectionLoadingTests(unittest.TestCase):
    def test_duplicate_keys_in_either_projection_fail_closed(self) -> None:
        cases = (
            ("target", TARGET_RELEASE, "tag"),
            ("rollback", ROLLBACK, "release_tag"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, target, rollback, arguments = _write_fixture(root)
            for name, document, key in cases:
                target.write_text(json.dumps(TARGET_RELEASE), encoding="utf-8")
                rollback.write_text(json.dumps(ROLLBACK), encoding="utf-8")
                path = target if name == "target" else rollback
                path.write_text(
                    _duplicate_top_level_key(document, key),
                    encoding="utf-8",
                )

                with self.subTest(projection=name):
                    result, stdout, stderr = _run(arguments)
                    self.assertEqual(result, 1)
                    self.assertEqual(stdout, "")
                    self.assertEqual(stderr, "deploy-release-evidence-failed")

    def test_either_projection_over_64_kib_fails_closed(self) -> None:
        cases = (
            ("target", TARGET_RELEASE),
            ("rollback", ROLLBACK),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, target, rollback, arguments = _write_fixture(root)
            for name, document in cases:
                target.write_text(json.dumps(TARGET_RELEASE), encoding="utf-8")
                rollback.write_text(json.dumps(ROLLBACK), encoding="utf-8")
                path = target if name == "target" else rollback
                raw = json.dumps(document).encode("utf-8")
                path.write_bytes(raw + b" " * (64 * 1024 + 1 - len(raw)))

                with self.subTest(projection=name):
                    result, stdout, stderr = _run(arguments)
                    self.assertEqual(result, 1)
                    self.assertEqual(stdout, "")
                    self.assertEqual(stderr, "deploy-release-evidence-failed")

    def test_each_projection_rejects_open_file_shape_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, _, arguments = _write_fixture(root)
            for projection, drift_call in (("target", 4), ("rollback", 6)):
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
                            st_ctime_ns=metadata.st_ctime_ns,
                            st_file_attributes=getattr(
                                metadata, "st_file_attributes", 0
                            ),
                        )
                    return metadata

                with self.subTest(projection=projection), mock.patch.object(
                    external_json.os,
                    "fstat",
                    side_effect=drifting_fstat,
                ):
                    result, stdout, stderr = _run(arguments)
                    self.assertEqual(result, 1)
                    self.assertEqual(stdout, "")
                    self.assertEqual(stderr, "deploy-release-evidence-failed")
                self.assertEqual(calls, drift_call)

    def test_link_or_reparse_projection_is_rejected_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, target, rollback, arguments = _write_fixture(root)
            for projection, rejected in (("target", target), ("rollback", rollback)):
                with self.subTest(projection=projection), mock.patch.object(
                    external_json,
                    "has_link_or_reparse_ancestor",
                    side_effect=lambda path, rejected=rejected: path == rejected,
                ):
                    result, stdout, stderr = _run(arguments)
                    self.assertEqual(result, 1)
                    self.assertEqual(stdout, "")
                    self.assertEqual(stderr, "deploy-release-evidence-failed")


if __name__ == "__main__":
    unittest.main()
