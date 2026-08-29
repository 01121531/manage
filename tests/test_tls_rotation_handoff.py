from __future__ import annotations

from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.tls_rotation_assessment import generate_assessment
from scripts.tls_rotation_evidence import rotation_plan_digest
from scripts.tls_rotation_executor import execute_tls_rotation
from scripts.tls_rotation_handoff import (
    TlsRotationHandoffError,
    create_tls_rotation_handoff,
    validate_handoff,
)
from scripts.tls_rotation_support import generate_support
from tests.test_compose_tls_rotation_backend import _profile_payload
from tests.test_tls_rotation_executor import Backend, Clock, _projection


class HandoffClock:
    def __init__(self) -> None:
        self.second = 30

    def __call__(self) -> str:
        value = f"2026-08-27T00:00:{self.second:02d}Z"
        self.second += 1
        return value


class TlsRotationHandoffTests(unittest.TestCase):
    def _inputs(self, directory: Path):
        profile_value = _profile_payload()
        profile_raw = json.dumps(profile_value, sort_keys=True, separators=(",", ":"))
        profile_digest = hashlib.sha256(profile_raw.encode()).hexdigest()
        profile_path = directory / "profile.json"
        profile_path.write_text(profile_raw + "\n", encoding="utf-8")

        projection = _projection()
        projection["runtime_profile_sha256"] = profile_digest
        projection_path = directory / "projection.json"
        projection_path.write_text(json.dumps(projection), encoding="utf-8")
        evidence_path = directory / "execution.json"
        with mock.patch(
            "scripts.tls_rotation_executor.release_control_lock", return_value=nullcontext()
        ):
            execute_tls_rotation(
                projection_path,
                evidence_output=evidence_path,
                backend_factory=lambda value: Backend(),
                clock=Clock(),
                confirm_rotation_plan_sha256=rotation_plan_digest(projection),
            )

        support_path = directory / "support.json"
        with mock.patch(
            "scripts.tls_rotation_support.release_control_lock", return_value=nullcontext()
        ):
            generate_support(
                projection_path,
                evidence_path,
                support_path,
                assessor_reference="assessor-1",
                confirm_rotation_plan_sha256=rotation_plan_digest(projection),
            )

        assessment_path = directory / "assessment.json"
        with mock.patch(
            "scripts.tls_rotation_assessment.release_control_lock", return_value=nullcontext()
        ):
            generate_assessment(
                projection_path,
                profile_path,
                evidence_path,
                support_path,
                assessment_path,
                reviewer_reference="reviewer-2",
                confirm_rotation_plan_sha256=rotation_plan_digest(projection),
                clock=lambda: "2026-08-27T00:00:20Z",
            )
        return (
            projection, projection_path, profile_path, support_path,
            assessment_path, evidence_path,
        )

    def _handoff(self, values, output: Path):
        projection, projection_path, profile_path, support_path, assessment_path, evidence_path = values
        return create_tls_rotation_handoff(
            projection_path,
            execution_evidence=evidence_path,
            runtime_profile=profile_path,
            supporting_evidence=support_path,
            assessment_input=assessment_path,
            handoff_output=output,
            confirm_rotation_plan_sha256=rotation_plan_digest(projection),
            clock=HandoffClock(),
        )

    def test_matching_stable_execution_sink_is_committed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            values = self._inputs(directory)
            output = directory / "handoff.json"
            with mock.patch(
                "scripts.tls_rotation_handoff.release_control_lock", return_value=nullcontext()
            ):
                result = self._handoff(values, output)
            self.assertEqual(result, validate_handoff(json.loads(output.read_text())))
            self.assertEqual(result["execution_sink_observation"]["state"], "committed")
            self.assertEqual(result["manual_runtime_assessment"]["state"], "verified_new")
            self.assertFalse(result["production_acceptance"])

    def test_absent_or_invalid_sink_is_unknown_never_not_committed(self) -> None:
        for invalid in (False, True):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as raw:
                directory = Path(raw)
                values = self._inputs(directory)
                evidence_path = values[-1]
                evidence_path.unlink()
                if invalid:
                    evidence_path.write_text('{"secret":"canary"}', encoding="utf-8")
                output = directory / "handoff.json"
                with mock.patch(
                    "scripts.tls_rotation_handoff.release_control_lock", return_value=nullcontext()
                ), self.assertRaises(TlsRotationHandoffError):
                    self._handoff(values, output)
                self.assertFalse(output.exists())
                handoff_source = Path("scripts/tls_rotation_handoff.py").read_text(
                    encoding="utf-8"
                )
                self.assertNotIn('"not_committed"', handoff_source)

    def test_support_or_assessment_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            values = self._inputs(directory)
            support_path = values[3]
            support = json.loads(support_path.read_text())
            support["derived_runtime_state"] = "verified_old"
            support_path.write_text(json.dumps(support), encoding="utf-8")
            output = directory / "handoff.json"
            with mock.patch(
                "scripts.tls_rotation_handoff.release_control_lock", return_value=nullcontext()
            ), self.assertRaises(ValueError):
                self._handoff(values, output)
            self.assertFalse(output.exists())

    def test_publication_failure_is_not_retried(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            values = self._inputs(directory)
            output = directory / "handoff.json"
            with mock.patch(
                "scripts.tls_rotation_handoff.release_control_lock", return_value=nullcontext()
            ), mock.patch(
                "scripts.tls_rotation_handoff.publish_write_once_file",
                side_effect=OSError("private sink detail"),
            ) as publish, self.assertRaises(OSError):
                self._handoff(values, output)
            publish.assert_called_once()
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
