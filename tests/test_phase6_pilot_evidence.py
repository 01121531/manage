from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.phase6_pilot_evidence import (
    EVIDENCE_INDEX,
    REQUIRED_SCENARIOS,
    index_errors,
    intake_binding_errors,
    main,
    pilot_input_alignment_errors,
    repository_contract_errors,
    seal_index,
)
from scripts.phase6_pilot_inputs import (
    INVENTORY as PILOT_INPUT_INVENTORY,
    REQUIRED_ROLE_RESPONSIBILITIES,
    seal_inventory,
)
from tests.test_deploy_release_evidence import _complete_success, _recorder


class Phase6PilotEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.template = json.loads(EVIDENCE_INDEX.read_text(encoding="utf-8"))

    @staticmethod
    def _reseal(document: dict[str, object]) -> dict[str, object]:
        payload = {key: value for key, value in document.items() if key != "integrity"}
        return seal_index(payload)

    @staticmethod
    def _pilot_inputs() -> dict[str, object]:
        document = json.loads(PILOT_INPUT_INVENTORY.read_text(encoding="utf-8"))
        document.update(
            {
                "inventory_reference": "pilot-input-inventory:record-42",
                "synthetic": False,
                "inventory_status": "reviewed",
                "review_reference": "pilot-review-ref:record-42",
                "environment": "staging",
                "bindings": {
                    "release_tag": "v1.2.3",
                    "release_commit": "a" * 40,
                    "container_manifest_sha256": "b" * 64,
                    "target_platform_inventory_sha256": "c" * 64,
                },
                "ownership": {
                    "pilot_coordinator_reference": "pilot-owner-ref:coordinator-42",
                    "target_operator_owner_reference": "pilot-owner-ref:operations-42",
                    "alert_receiver_owner_reference": "pilot-owner-ref:alerting-42",
                    "maintenance_owner_reference": "pilot-owner-ref:maintenance-42",
                },
                "maintenance_window": {
                    "change_reference": "change-record:pilot-42",
                    "approval_reference": "change-approval:pilot-42",
                    "starts_at": "2026-08-27T01:00:00Z",
                    "rollback_decision_deadline": "2026-08-27T01:30:00Z",
                    "finishes_at": "2026-08-27T02:00:00Z",
                },
            }
        )
        document["pilot_roles"] = {
            role: {
                "participant_reference": f"pilot-subject-ref:subject-{index}a",
                "roster_entry_reference": f"pilot-roster-entry:entry-{index}a",
                "responsibility": responsibility,
            }
            for index, (role, responsibility) in enumerate(
                REQUIRED_ROLE_RESPONSIBILITIES.items(), start=1
            )
        }
        return seal_inventory(
            {key: value for key, value in document.items() if key != "integrity"}
        )

    def _reviewed(self) -> dict[str, object]:
        document = copy.deepcopy(self.template)
        document.update(
            {
                "index_reference": "pilot-evidence-index:record-42",
                "synthetic": False,
                "index_status": "reviewed",
                "review_reference": "pilot-evidence-review:record-42",
                "reviewed_at": "2026-08-27T02:00:00Z",
                "environment": "staging",
                "bindings": {
                    "release_tag": "v1.2.3",
                    "release_commit": "a" * 40,
                    "container_manifest_sha256": "b" * 64,
                    "phase6_pilot_inputs_sha256": "d" * 64,
                    "sub2_execution_evidence_sha256": "e" * 64,
                    "target_platform_inventory_sha256": "c" * 64,
                },
                "pilot_subjects": {
                    "operator": "pilot-subject-ref:subject-1a",
                    "security_auditor": "pilot-subject-ref:subject-3a",
                },
                "trace_set_reference": "pilot-trace-set:record-42",
                "window": {
                    "started_at": "2026-08-27T01:05:00Z",
                    "finished_at": "2026-08-27T01:55:00Z",
                },
                "release_execution": {
                    "ledger_type": "forward",
                    "evidence_object_reference": "worm-release-execution:record-42a",
                    "evidence_sha256": "f" * 64,
                    "target_intake": {
                        "environment": "staging",
                        "manifest_payload_sha256": "9" * 64,
                        "requirements_sha256": "a" * 64,
                        "checkpoint_phase": 0,
                    },
                },
            }
        )
        document["scenarios"] = {
            scenario: {
                "execution_reference": f"pilot-execution:record-{index}a",
                "actor_role": contract["actor_role"],
                "reviewer_reference": "pilot-reviewer-ref:record-42",
                "executed_at": f"2026-08-27T01:{index + 5:02d}:00Z",
                "observation": contract["observation"],
                "result": "passed",
                "evidence_object_reference": f"worm-pilot-evidence:object-{index}a",
                "evidence_sha256": f"{index:064x}",
                "redaction_confirmed": True,
            }
            for index, (scenario, contract) in enumerate(REQUIRED_SCENARIOS.items(), start=1)
        }
        return self._reseal(document)

    @staticmethod
    def _manifest(bindings: dict[str, str]) -> dict[str, object]:
        return {
            "schema_version": 1,
            "environment": "staging",
            "production_acceptance": False,
            "requirements_sha256": "a" * 64,
            "items": [
                {
                    "id": "target_platform_inventory",
                    "status": "provided",
                    "sha256": bindings["target_platform_inventory_sha256"],
                },
                {
                    "id": "sub2_execution_evidence",
                    "status": "provided",
                    "sha256": bindings["sub2_execution_evidence_sha256"],
                },
                {
                    "id": "phase6_pilot_inputs",
                    "status": "provided",
                    "sha256": bindings["phase6_pilot_inputs_sha256"],
                },
                {
                    "id": "phase6_pilot_evidence",
                    "status": "provided",
                    "reviewed_by": "pilot-evidence-review:record-42",
                    "reviewed_at": "2026-08-27T02:00:00Z",
                },
            ],
        }

    def test_repository_template_is_safe_closed_sealed_aligned_and_gated(self) -> None:
        self.assertEqual(index_errors(self.template), [])
        self.assertEqual(repository_contract_errors(), [])
        self.assertTrue(self.template["synthetic"])
        self.assertEqual(self.template["index_status"], "pending")
        self.assertFalse(self.template["production_acceptance"])
        self.assertEqual(self.template["schema_version"], 3)
        self.assertTrue(all(value is None for value in self.template["scenarios"].values()))
        gate = Path("scripts/quality_gate.ps1").read_text(encoding="utf-8")
        self.assertIn("python scripts/phase6_pilot_evidence.py verify-repository", gate)

    def test_exact_nine_target_scenarios_match_ci_dimensions_without_ci_identity(self) -> None:
        self.assertEqual(len(REQUIRED_SCENARIOS), 9)
        self.assertEqual(index_errors(self._reviewed()), [])
        self.assertEqual(
            self.template["execution_scope"],
            {
                "origin": "target_environment",
                "identity_mode": "oidc",
                "connector_mode": "reviewed_real_mail_and_sub2",
                "evidence_policy": "repository_external_worm_metadata_only",
            },
        )
        for forbidden in ("local_test", "sqlite", "fake_mail", "fake_sub2"):
            self.assertNotIn(forbidden, json.dumps(self.template).casefold())

    def test_scenario_inventory_actor_observation_and_passed_result_are_exact(self) -> None:
        reviewed = self._reviewed()
        missing = copy.deepcopy(reviewed)
        missing["scenarios"].pop("authorization_isolation")
        wrong_actor = copy.deepcopy(reviewed)
        wrong_actor["scenarios"]["persistent_secret_scan"]["actor_role"] = "operator"
        wrong_observation = copy.deepcopy(reviewed)
        wrong_observation["scenarios"]["resource_cleanup"]["observation"] = "cleanup_started"
        failed = copy.deepcopy(reviewed)
        failed["scenarios"]["full_business_flow"]["result"] = "failed"
        for document in (missing, wrong_actor, wrong_observation, failed):
            self.assertTrue(index_errors(self._reseal(document)))

    def test_pilot_subjects_must_match_reviewed_input_roster(self) -> None:
        reviewed = self._reviewed()
        pilot_inputs = self._pilot_inputs()
        self.assertEqual(pilot_input_alignment_errors(reviewed, pilot_inputs), [])
        replaced = copy.deepcopy(reviewed)
        replaced["pilot_subjects"]["operator"] = "pilot-subject-ref:replacement-9a"
        replaced = self._reseal(replaced)
        self.assertIn(
            "Phase 6 pilot evidence subjects do not match the reviewed pilot inputs",
            pilot_input_alignment_errors(replaced, pilot_inputs),
        )
        synthetic = json.loads(PILOT_INPUT_INVENTORY.read_text(encoding="utf-8"))
        self.assertIn(
            "Phase 6 pilot evidence requires reviewed non-synthetic pilot inputs",
            pilot_input_alignment_errors(reviewed, synthetic),
        )

    def test_release_identity_must_match_reviewed_pilot_inputs(self) -> None:
        reviewed = self._reviewed()
        pilot_inputs = self._pilot_inputs()
        pilot_inputs["bindings"]["release_commit"] = "f" * 40
        pilot_inputs = seal_inventory(
            {key: value for key, value in pilot_inputs.items() if key != "integrity"}
        )
        self.assertIn(
            "Phase 6 pilot evidence release identity does not match the reviewed pilot inputs",
            pilot_input_alignment_errors(reviewed, pilot_inputs),
        )

    def test_references_are_independent_unique_and_redacted(self) -> None:
        reviewed = self._reviewed()
        duplicate_object = copy.deepcopy(reviewed)
        duplicate_object["scenarios"]["resource_cleanup"]["evidence_object_reference"] = duplicate_object[
            "scenarios"
        ]["server_side_upload"]["evidence_object_reference"]
        same_reviewer = copy.deepcopy(reviewed)
        same_reviewer["scenarios"]["full_business_flow"]["reviewer_reference"] = same_reviewer[
            "pilot_subjects"
        ]["operator"]
        unredacted = copy.deepcopy(reviewed)
        unredacted["scenarios"]["persistent_secret_scan"]["redaction_confirmed"] = False
        for document in (duplicate_object, same_reviewer, unredacted):
            self.assertTrue(index_errors(self._reseal(document)))

    def test_window_release_integrity_unknown_fields_and_sensitive_claims_fail_closed(self) -> None:
        reviewed = self._reviewed()
        outside = copy.deepcopy(reviewed)
        outside["scenarios"]["authenticated_platform_session"]["executed_at"] = "2026-08-27T02:30:00Z"
        bad_commit = copy.deepcopy(reviewed)
        bad_commit["bindings"]["release_commit"] = "not-a-commit"
        unknown = copy.deepcopy(reviewed)
        unknown["raw_log"] = "redacted"
        sensitive = copy.deepcopy(reviewed)
        sensitive["prohibited_content"]["contains_mail_content"] = True
        accepted = copy.deepcopy(reviewed)
        accepted["production_acceptance"] = True
        for document in (outside, bad_commit, unknown, sensitive, accepted):
            self.assertTrue(index_errors(self._reseal(document)))
        tampered = copy.deepcopy(reviewed)
        tampered["environment"] = "production"
        self.assertIn("Phase 6 pilot evidence index integrity is invalid", index_errors(tampered))

        early_review = copy.deepcopy(reviewed)
        early_review["reviewed_at"] = "2026-08-27T01:54:59Z"
        self.assertIn(
            "reviewed Phase 6 pilot evidence review timestamp is invalid",
            index_errors(self._reseal(early_review)),
        )

    def test_binding_requires_same_environment_inputs_and_target_inventory(self) -> None:
        reviewed = self._reviewed()
        manifest = self._manifest(reviewed["bindings"])
        self.assertEqual(intake_binding_errors(reviewed, manifest), [])
        next(
            item for item in manifest["items"]
            if item["id"] == "phase6_pilot_inputs"
        )["sha256"] = "f" * 64
        self.assertIn(
            "Phase 6 pilot evidence phase6_pilot_inputs binding does not match this intake manifest",
            intake_binding_errors(reviewed, manifest),
        )
        manifest["environment"] = "production"
        self.assertIn(
            "Phase 6 pilot evidence environment does not match this intake manifest",
            intake_binding_errors(reviewed, manifest),
        )

    def test_binding_locks_sub2_evidence_and_manifest_review_metadata(self) -> None:
        reviewed = self._reviewed()
        manifest = self._manifest(reviewed["bindings"])
        sub2 = next(
            item for item in manifest["items"]
            if item["id"] == "sub2_execution_evidence"
        )
        sub2["sha256"] = "f" * 64
        self.assertIn(
            "Phase 6 pilot evidence sub2_execution_evidence binding does not match this intake manifest",
            intake_binding_errors(reviewed, manifest),
        )
        sub2["sha256"] = reviewed["bindings"]["sub2_execution_evidence_sha256"]
        own = next(
            item for item in manifest["items"]
            if item["id"] == "phase6_pilot_evidence"
        )
        own["reviewed_at"] = "2026-08-27T02:00:01Z"
        self.assertIn(
            "Phase 6 pilot evidence review metadata does not match this intake manifest",
            intake_binding_errors(reviewed, manifest),
        )

    def test_cli_rejects_synthetic_and_distinguishes_roster_or_manifest_mismatch(self) -> None:
        self.assertEqual(main(["verify-repository"]), 0)
        reviewed = self._reviewed()
        pilot_inputs = self._pilot_inputs()
        manifest = self._manifest(reviewed["bindings"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            index_path = root / "pilot-evidence.json"
            inputs_path = root / "pilot-inputs.json"
            manifest_path = root / "intake.json"
            release_path = root / "forward-release.json"
            recorder = _recorder()
            _complete_success(recorder)
            recorder.write(release_path)
            reviewed["release_execution"]["evidence_sha256"] = hashlib.sha256(
                release_path.read_bytes()
            ).hexdigest()
            reviewed = self._reseal(reviewed)
            inputs_path.write_text(json.dumps(pilot_inputs), encoding="utf-8")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            index_path.write_text(json.dumps(self.template), encoding="utf-8")
            args = ["check", "--input", str(index_path), "--pilot-inputs", str(inputs_path), "--intake-manifest", str(manifest_path), "--release-execution-evidence", str(release_path)]
            self.assertEqual(main(args), 1)
            index_path.write_text(json.dumps(reviewed), encoding="utf-8")
            self.assertEqual(main(args), 0)
            replaced = copy.deepcopy(pilot_inputs)
            replaced["pilot_roles"]["operator"]["participant_reference"] = "pilot-subject-ref:replacement-9a"
            replaced = seal_inventory({key: value for key, value in replaced.items() if key != "integrity"})
            inputs_path.write_text(json.dumps(replaced), encoding="utf-8")
            self.assertEqual(main(args), 2)

    def test_runbook_documents_real_target_boundary_and_external_content_limit(self) -> None:
        text = Path("deploy/runbooks/target-intake-preflight.md").read_text(encoding="utf-8").casefold().replace("\n", " ")
        for expected in (
            "phase6_pilot_evidence.py check",
            "target oidc",
            "reviewed real mail and sub2",
            "ci rehearsal cannot satisfy",
            "does not verify the external evidence content",
        ):
            self.assertIn(expected, text)


if __name__ == "__main__":
    unittest.main()
