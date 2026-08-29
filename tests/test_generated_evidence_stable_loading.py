from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import scripts.external_json as external_json
from scripts import deploy_release_evidence
from scripts import phase6_rehearsal
from scripts import rollback_release_evidence
from scripts import rolling_release_evidence
from scripts import training_evidence
from scripts.release_execution_binding import release_execution_alignment_errors
from tests.test_release_execution_binding import (
    TARGET_INTAKE,
    TARGET_RELEASE,
    _selector,
)
from tests.test_deploy_release_evidence import _complete_success, _recorder
from tests.test_training_evidence import valid_payload


def _duplicate_top_level_key(document: dict[str, object], key: str) -> str:
    serialized = json.dumps(document, ensure_ascii=False, separators=(",", ":"))
    return "{" + json.dumps(key) + ":" + json.dumps(document[key]) + "," + serialized[1:]


class GeneratedEvidenceStableLoadingTests(unittest.TestCase):
    def test_phase6_and_training_readers_reject_duplicate_keys(self) -> None:
        documents = (
            (
                phase6_rehearsal.run_rehearsal("a" * 40),
                "schema_version",
                phase6_rehearsal.verify_evidence,
                phase6_rehearsal.RehearsalError,
            ),
            (
                training_evidence.seal_evidence(valid_payload()),
                "schema_version",
                training_evidence.verify_evidence,
                training_evidence.TrainingEvidenceError,
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, (document, key, verifier, error_type) in enumerate(documents):
                path = root / f"duplicate-{index}.json"
                path.write_text(
                    _duplicate_top_level_key(document, key),
                    encoding="utf-8",
                )
                with self.subTest(verifier=verifier.__module__):
                    with self.assertRaisesRegex(error_type, "JSON is invalid"):
                        verifier(path)

    def test_five_verifiers_map_open_file_shape_drift_to_read_error(self) -> None:
        cases = (
            (
                phase6_rehearsal.verify_evidence,
                phase6_rehearsal.RehearsalError,
                "evidence cannot be read",
            ),
            (
                training_evidence.verify_evidence,
                training_evidence.TrainingEvidenceError,
                "training evidence file cannot be read",
            ),
            (
                deploy_release_evidence.verify_evidence,
                deploy_release_evidence.DeploymentReleaseEvidenceError,
                "deployment evidence cannot be read",
            ),
            (
                rolling_release_evidence.verify_evidence,
                rolling_release_evidence.RollingReleaseEvidenceError,
                "rolling evidence cannot be read",
            ),
            (
                rollback_release_evidence.verify_evidence,
                rollback_release_evidence.RollbackReleaseEvidenceError,
                "rollback evidence cannot be read",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "drifting.json"
            path.write_text("{}", encoding="utf-8")
            for verifier, error_type, message in cases:
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
                            st_ctime_ns=metadata.st_ctime_ns,
                            st_file_attributes=getattr(
                                metadata, "st_file_attributes", 0
                            ),
                        )
                    return metadata

                with self.subTest(verifier=verifier.__module__):
                    with mock.patch.object(
                        external_json.os,
                        "fstat",
                        side_effect=drifting_fstat,
                    ):
                        with self.assertRaisesRegex(error_type, message):
                            verifier(path)
                    self.assertEqual(calls, 2)

    def test_release_binding_maps_open_file_shape_drift_to_read_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "forward.json"
            recorder = _recorder()
            _complete_success(recorder)
            recorder.write(path)
            selector = _selector(path)
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
                        st_ctime_ns=metadata.st_ctime_ns,
                        st_file_attributes=getattr(
                            metadata, "st_file_attributes", 0
                        ),
                    )
                return metadata

            with mock.patch.object(
                external_json.os,
                "fstat",
                side_effect=drifting_fstat,
            ):
                errors = release_execution_alignment_errors(
                    selector,
                    path,
                    environment=TARGET_INTAKE["environment"],
                    release_tag=TARGET_RELEASE["tag"],
                    release_commit=TARGET_RELEASE["commit"],
                    container_manifest_sha256=TARGET_RELEASE[
                        "container_manifest_sha256"
                    ],
                )
            self.assertEqual(errors, ["release execution evidence cannot be read"])
            self.assertEqual(calls, 2)

    def test_five_verifiers_keep_64_kib_size_error_mapping(self) -> None:
        cases = (
            (
                phase6_rehearsal.verify_evidence,
                phase6_rehearsal.RehearsalError,
                "evidence size is invalid",
            ),
            (
                training_evidence.verify_evidence,
                training_evidence.TrainingEvidenceError,
                "training evidence file size is invalid",
            ),
            (
                deploy_release_evidence.verify_evidence,
                deploy_release_evidence.DeploymentReleaseEvidenceError,
                "deployment evidence size is invalid",
            ),
            (
                rolling_release_evidence.verify_evidence,
                rolling_release_evidence.RollingReleaseEvidenceError,
                "rolling evidence size is invalid",
            ),
            (
                rollback_release_evidence.verify_evidence,
                rollback_release_evidence.RollbackReleaseEvidenceError,
                "rollback evidence size is invalid",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "oversized.json"
            path.write_bytes(b"{}" + b" " * (64 * 1024 + 1 - 2))
            for verifier, error_type, message in cases:
                with self.subTest(verifier=verifier.__module__):
                    with self.assertRaisesRegex(error_type, message):
                        verifier(path)

    def test_release_binding_keeps_64_kib_size_error_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "oversized-forward.json"
            path.write_bytes(b"{}" + b" " * (64 * 1024 + 1 - 2))
            selector = _selector(path)

            errors = release_execution_alignment_errors(
                selector,
                path,
                environment=TARGET_INTAKE["environment"],
                release_tag=TARGET_RELEASE["tag"],
                release_commit=TARGET_RELEASE["commit"],
                container_manifest_sha256=TARGET_RELEASE[
                    "container_manifest_sha256"
                ],
            )

            self.assertEqual(errors, ["release execution evidence size is invalid"])


if __name__ == "__main__":
    unittest.main()
