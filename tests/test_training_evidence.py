from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from scripts import training_evidence
from scripts.verify_training_assets import training_asset_errors


COMMIT = "a" * 40


def valid_payload() -> dict[str, object]:
    roles = {}
    for index, role in enumerate(training_evidence.REQUIRED_ROLES, start=1):
        roles[role] = {
            "trainee_id": f"trainee-{index}",
            "reviewer_id": f"reviewer-{index}",
            "status": "passed",
            "completed_at": f"2026-08-20T09:{index:02d}:00Z",
        }
    scenarios = {}
    for index, (scenario, role) in enumerate(
        training_evidence.REQUIRED_SCENARIOS.items(), start=10
    ):
        scenarios[scenario] = {
            "actor_role": role,
            "reviewer_id": "reviewer-1",
            "result": "passed",
            "trace_id": f"training-trace-{index}",
            "completed_at": f"2026-08-20T09:{index:02d}:00Z",
        }
    return {
        "schema_version": 1,
        "evidence_kind": "phase6_role_training",
        "production_acceptance": False,
        "session_id": "training-20260820-001",
        "environment_id": "staging-cn-01",
        "release_tag": "v1.2.3",
        "release_commit": COMMIT,
        "window": {
            "started_at": "2026-08-20T09:00:00Z",
            "finished_at": "2026-08-20T10:00:00Z",
        },
        "roles": roles,
        "scenarios": scenarios,
    }


class TrainingEvidenceTests(unittest.TestCase):
    def test_seal_write_and_verify_is_deterministic_and_release_bound(self) -> None:
        first = training_evidence.seal_evidence(valid_payload())
        second = training_evidence.seal_evidence(valid_payload())
        self.assertEqual(first, second)
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "evidence.json"
            training_evidence.write_evidence(output, first)
            verified = training_evidence.verify_evidence(
                output,
                expected_release_tag="v1.2.3",
                expected_release_commit=COMMIT,
            )
        self.assertFalse(verified["production_acceptance"])
        self.assertRegex(verified["integrity"]["payload_sha256"], r"^[0-9a-f]{64}$")

    def test_missing_role_or_scenario_and_failed_result_are_rejected(self) -> None:
        payload = valid_payload()
        payload["roles"].pop("operator")
        with self.assertRaisesRegex(training_evidence.TrainingEvidenceError, "roles"):
            training_evidence.seal_evidence(payload)

        payload = valid_payload()
        payload["scenarios"].pop("device_revocation")
        with self.assertRaisesRegex(training_evidence.TrainingEvidenceError, "scenarios"):
            training_evidence.seal_evidence(payload)

        payload = valid_payload()
        payload["scenarios"]["unknown_upload_no_blind_retry"]["result"] = "failed"
        with self.assertRaisesRegex(training_evidence.TrainingEvidenceError, "scenario result"):
            training_evidence.seal_evidence(payload)

    def test_wrong_actor_and_non_independent_reviewer_are_rejected(self) -> None:
        payload = valid_payload()
        payload["scenarios"]["device_revocation"]["actor_role"] = "operator"
        with self.assertRaisesRegex(training_evidence.TrainingEvidenceError, "scenario result"):
            training_evidence.seal_evidence(payload)

        payload = valid_payload()
        payload["roles"]["operator"]["reviewer_id"] = "trainee-2"
        with self.assertRaisesRegex(training_evidence.TrainingEvidenceError, "independent"):
            training_evidence.seal_evidence(payload)

    def test_unknown_secret_like_fields_and_unsafe_values_are_rejected(self) -> None:
        payload = valid_payload()
        payload["notes"] = "free text is not evidence"
        with self.assertRaisesRegex(training_evidence.TrainingEvidenceError, "schema"):
            training_evidence.seal_evidence(payload)

        payload = valid_payload()
        payload["roles"]["operator"]["api_token"] = "not-allowed"
        with self.assertRaisesRegex(training_evidence.TrainingEvidenceError, "schema"):
            training_evidence.seal_evidence(payload)

        payload = valid_payload()
        payload["roles"]["operator"]["trainee_id"] = "secret-reviewer"
        with self.assertRaisesRegex(training_evidence.TrainingEvidenceError, "unsafe"):
            training_evidence.seal_evidence(payload)

    def test_time_window_and_release_mismatch_are_rejected(self) -> None:
        payload = valid_payload()
        payload["roles"]["operator"]["completed_at"] = "2026-08-20T11:00:00Z"
        with self.assertRaisesRegex(training_evidence.TrainingEvidenceError, "outside"):
            training_evidence.seal_evidence(payload)

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "evidence.json"
            training_evidence.write_evidence(
                path, training_evidence.seal_evidence(valid_payload())
            )
            with self.assertRaisesRegex(training_evidence.TrainingEvidenceError, "commit mismatch"):
                training_evidence.verify_evidence(
                    path, expected_release_commit="b" * 40
                )

        payload = valid_payload()
        payload["window"]["started_at"] = "2026-08-20Z"
        with self.assertRaisesRegex(training_evidence.TrainingEvidenceError, "timestamp"):
            training_evidence.seal_evidence(payload)

        payload = valid_payload()
        payload["schema_version"] = True
        with self.assertRaisesRegex(training_evidence.TrainingEvidenceError, "identity"):
            training_evidence.seal_evidence(payload)

    def test_tampering_is_rejected(self) -> None:
        evidence = training_evidence.seal_evidence(valid_payload())
        evidence["environment_id"] = "staging-cn-02"
        with self.assertRaisesRegex(training_evidence.TrainingEvidenceError, "integrity"):
            training_evidence.validate_evidence(evidence)

    def test_failed_create_invalidates_stale_output_and_cli_is_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_path = root / "input.json"
            output_path = root / "evidence.json"
            input_path.write_text(json.dumps(valid_payload()), encoding="utf-8")
            self.assertEqual(
                training_evidence.main(
                    ["create", "--input", str(input_path), "--output", str(output_path)]
                ),
                0,
            )
            self.assertTrue(output_path.exists())
            input_path.write_text("{}", encoding="utf-8")
            self.assertEqual(
                training_evidence.main(
                    ["create", "--input", str(input_path), "--output", str(output_path)]
                ),
                1,
            )
            self.assertFalse(output_path.exists())

    def test_create_refuses_to_overwrite_its_input(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "session.json"
            original = json.dumps(valid_payload())
            path.write_text(original, encoding="utf-8")
            self.assertEqual(
                training_evidence.main(
                    ["create", "--input", str(path), "--output", str(path)]
                ),
                1,
            )
            self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_repository_training_assets_cover_all_roles_and_scenarios(self) -> None:
        root = Path(__file__).resolve().parents[1]
        errors = training_asset_errors(
            (root / "deploy" / "runbooks" / "role-training.md").read_text(
                encoding="utf-8"
            ),
            (root / "deploy" / "production-signoff-template.md").read_text(
                encoding="utf-8"
            ),
        )
        self.assertEqual(errors, [])
