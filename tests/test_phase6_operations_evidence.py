from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.phase6_operations_evidence import (
    EVIDENCE_INDEX,
    REQUIRED_ARTIFACT_DIGESTS,
    REQUIRED_SCENARIOS,
    index_errors,
    intake_binding_errors,
    main,
    phase6_alignment_errors,
    repository_contract_errors,
    seal_index,
)
from scripts.phase6_pilot_evidence import (
    EVIDENCE_INDEX as PILOT_EVIDENCE_INDEX,
    REQUIRED_SCENARIOS as PILOT_SCENARIOS,
    seal_index as seal_pilot_evidence,
)
from scripts.phase6_pilot_inputs import (
    INVENTORY as PILOT_INPUT_INVENTORY,
    REQUIRED_ROLE_RESPONSIBILITIES,
    seal_inventory,
)
from tests.test_deploy_release_evidence import _complete_success, _recorder


EVALUATED_AT = datetime(2026, 8, 29, tzinfo=timezone.utc)


class Phase6OperationsEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.template = json.loads(EVIDENCE_INDEX.read_text(encoding="utf-8"))

    @staticmethod
    def _reseal(document: dict[str, object]) -> dict[str, object]:
        return seal_index(
            {key: value for key, value in document.items() if key != "integrity"}
        )

    @staticmethod
    def _pilot_inputs() -> dict[str, object]:
        document = json.loads(PILOT_INPUT_INVENTORY.read_text(encoding="utf-8"))
        document.update(
            {
                "inventory_reference": "pilot-input-inventory:record-43",
                "synthetic": False,
                "inventory_status": "reviewed",
                "review_reference": "pilot-review-ref:record-43",
                "reviewed_at": "2026-08-27T00:30:00Z",
                "valid_until": "2099-08-27T05:30:00Z",
                "environment": "staging",
                "bindings": {
                    "release_tag": "v1.2.3",
                    "release_commit": "a" * 40,
                    "container_manifest_sha256": "b" * 64,
                    "target_platform_inventory_sha256": "c" * 64,
                },
                "ownership": {
                    "pilot_coordinator_reference": "pilot-owner-ref:coordinator-43",
                    "target_operator_owner_reference": "pilot-owner-ref:operations-43",
                    "alert_receiver_owner_reference": "pilot-owner-ref:alerting-43",
                    "maintenance_owner_reference": "pilot-owner-ref:maintenance-43",
                },
                "maintenance_window": {
                    "change_reference": "change-record:pilot-43",
                    "approval_reference": "change-approval:pilot-43",
                    "starts_at": "2026-08-27T01:00:00Z",
                    "rollback_decision_deadline": "2026-08-27T03:00:00Z",
                    "finishes_at": "2026-08-27T05:00:00Z",
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

    @staticmethod
    def _pilot_evidence() -> dict[str, object]:
        document = json.loads(PILOT_EVIDENCE_INDEX.read_text(encoding="utf-8"))
        document.update(
            {
                "index_reference": "pilot-evidence-index:record-43",
                "synthetic": False,
                "index_status": "reviewed",
                "review_reference": "pilot-evidence-review:record-43",
                "reviewed_at": "2026-08-27T02:00:00Z",
                "valid_until": "2099-08-27T05:00:00Z",
                "environment": "staging",
                "bindings": {
                    "release_tag": "v1.2.3",
                    "release_commit": "a" * 40,
                    "container_manifest_sha256": "b" * 64,
                    "phase6_pilot_inputs_sha256": "d" * 64,
                    "sub2_execution_evidence_sha256": "6" * 64,
                    "target_platform_inventory_sha256": "c" * 64,
                },
                "pilot_subjects": {
                    "operator": "pilot-subject-ref:subject-1a",
                    "security_auditor": "pilot-subject-ref:subject-3a",
                },
                "trace_set_reference": "pilot-trace-set:record-43",
                "window": {
                    "started_at": "2026-08-27T01:05:00Z",
                    "finished_at": "2026-08-27T01:55:00Z",
                },
                "release_execution": {
                    "ledger_type": "forward",
                    "evidence_object_reference": "worm-release-execution:record-43a",
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
                "reviewer_reference": "pilot-reviewer-ref:record-43",
                "executed_at": f"2026-08-27T01:{index + 5:02d}:00Z",
                "observation": contract["observation"],
                "result": "passed",
                "evidence_object_reference": f"worm-pilot-evidence:object-{index}a",
                "evidence_sha256": f"{index:064x}",
                "redaction_confirmed": True,
            }
            for index, (scenario, contract) in enumerate(PILOT_SCENARIOS.items(), start=1)
        }
        return seal_pilot_evidence(
            {key: value for key, value in document.items() if key != "integrity"}
        )

    def _reviewed(self) -> dict[str, object]:
        document = copy.deepcopy(self.template)
        document.update(
            {
                "index_reference": "operations-evidence-index:record-43",
                "synthetic": False,
                "index_status": "reviewed",
                "review_reference": "operations-evidence-review:record-43",
                "reviewed_at": "2026-08-27T04:15:00Z",
                "valid_until": "2099-08-27T05:15:00Z",
                "environment": "staging",
                "bindings": {
                    "release_tag": "v1.2.3",
                    "release_commit": "a" * 40,
                    "container_manifest_sha256": "b" * 64,
                    "phase6_pilot_inputs_sha256": "d" * 64,
                    "phase6_pilot_evidence_sha256": "e" * 64,
                    "target_platform_inventory_sha256": "c" * 64,
                },
                "role_subjects": {
                    role: f"pilot-subject-ref:subject-{index}a"
                    for index, role in enumerate(
                        REQUIRED_ROLE_RESPONSIBILITIES, start=1
                    )
                },
                "pilot_trace_set_reference": "pilot-trace-set:record-43",
                "window": {
                    "started_at": "2026-08-27T02:00:00Z",
                    "finished_at": "2026-08-27T04:00:00Z",
                },
                "release_execution": {
                    "ledger_type": "forward",
                    "evidence_object_reference": "worm-release-execution:record-43a",
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
        document["artifact_digests"] = {
            name: f"{index + 20:064x}"
            for index, name in enumerate(REQUIRED_ARTIFACT_DIGESTS)
        }
        document["scenarios"] = {
            scenario: {
                "execution_reference": f"operations-execution:record-{index}a",
                "actor_role": contract["actor_role"],
                "reviewer_reference": "operations-reviewer-ref:record-43",
                "executed_at": f"2026-08-27T02:{index:02d}:00Z",
                "observation": contract["observation"],
                "result": "passed",
                "evidence_object_reference": f"worm-operations-evidence:object-{index}a",
                "evidence_sha256": f"{index + 40:064x}",
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
                    "id": identifier,
                    "status": "provided",
                    "sha256": bindings[binding],
                }
                for identifier, binding in (
                    ("phase6_pilot_inputs", "phase6_pilot_inputs_sha256"),
                    ("phase6_pilot_evidence", "phase6_pilot_evidence_sha256"),
                    ("target_platform_inventory", "target_platform_inventory_sha256"),
                )
            ]
            + [
                {
                    "id": "phase6_operations_evidence",
                    "status": "provided",
                    "reviewed_by": "operations-evidence-review:record-43",
                    "reviewed_at": "2026-08-27T04:15:00Z",
                }
            ],
        }

    def test_repository_template_is_safe_closed_sealed_and_gated(self) -> None:
        self.assertEqual(index_errors(self.template), [])
        self.assertEqual(repository_contract_errors(), [])
        self.assertTrue(self.template["synthetic"])
        self.assertEqual(self.template["index_status"], "pending")
        self.assertFalse(self.template["production_acceptance"])
        self.assertEqual(self.template["schema_version"], 4)
        self.assertIsNone(self.template["valid_until"])
        self.assertTrue(all(value is None for value in self.template["scenarios"].values()))
        gate = Path("scripts/quality_gate.ps1").read_text(encoding="utf-8")
        self.assertIn("python scripts/phase6_operations_evidence.py verify-repository", gate)

    def test_exact_nine_target_operations_scenarios_and_scope(self) -> None:
        self.assertEqual(len(REQUIRED_SCENARIOS), 9)
        self.assertEqual(index_errors(self._reviewed()), [])
        self.assertEqual(
            self.template["execution_scope"],
            {
                "origin": "target_environment",
                "alert_receiver": "approved_external_receiver",
                "restore_scope": "release_bound_postgresql_redis_and_vault",
                "rollback_mode": "executed_release_bound",
                "training_mode": "reviewed_four_role_target_session",
                "evidence_policy": "repository_external_worm_metadata_only",
            },
        )
        for forbidden in ("local_test", "sqlite", "fake_mail", "fake_sub2"):
            self.assertNotIn(forbidden, json.dumps(self.template).casefold())

    def test_scenario_inventory_actor_observation_and_result_are_exact(self) -> None:
        reviewed = self._reviewed()
        missing = copy.deepcopy(reviewed)
        missing["scenarios"].pop("vault_restore")
        wrong_actor = copy.deepcopy(reviewed)
        wrong_actor["scenarios"]["release_bound_rollback"]["actor_role"] = "operator"
        wrong_observation = copy.deepcopy(reviewed)
        wrong_observation["scenarios"]["postgres_redis_restore"]["observation"] = "restore_started"
        failed = copy.deepcopy(reviewed)
        failed["scenarios"]["page_alert_firing_delivery"]["result"] = "failed"
        for document in (missing, wrong_actor, wrong_observation, failed):
            self.assertTrue(index_errors(self._reseal(document)))

    def test_artifact_digest_inventory_is_exact_and_unique(self) -> None:
        reviewed = self._reviewed()
        self.assertEqual(set(reviewed["artifact_digests"]), set(REQUIRED_ARTIFACT_DIGESTS))
        missing = copy.deepcopy(reviewed)
        missing["artifact_digests"].pop("vault_snapshot_sha256")
        duplicate = copy.deepcopy(reviewed)
        duplicate["artifact_digests"]["redis_backup_manifest_sha256"] = duplicate[
            "artifact_digests"
        ]["postgres_backup_manifest_sha256"]
        for document in (missing, duplicate):
            self.assertTrue(index_errors(self._reseal(document)))

    def test_alignment_requires_same_roster_trace_release_and_reviewed_inputs(self) -> None:
        reviewed = self._reviewed()
        pilot_inputs = self._pilot_inputs()
        pilot_evidence = self._pilot_evidence()
        self.assertEqual(
            phase6_alignment_errors(reviewed, pilot_inputs, pilot_evidence), []
        )
        wrong_subject = copy.deepcopy(reviewed)
        wrong_subject["role_subjects"]["ops_admin"] = "pilot-subject-ref:replacement-9a"
        self.assertIn(
            "Phase 6 operations evidence subjects do not match the reviewed pilot inputs",
            phase6_alignment_errors(self._reseal(wrong_subject), pilot_inputs, pilot_evidence),
        )
        wrong_trace = copy.deepcopy(reviewed)
        wrong_trace["pilot_trace_set_reference"] = "pilot-trace-set:replacement-9a"
        self.assertIn(
            "Phase 6 operations evidence trace set does not match the reviewed pilot evidence",
            phase6_alignment_errors(self._reseal(wrong_trace), pilot_inputs, pilot_evidence),
        )
        wrong_execution = copy.deepcopy(reviewed)
        wrong_execution["release_execution"]["evidence_sha256"] = "9" * 64
        self.assertIn(
            "Phase 6 operations evidence release execution does not match the reviewed pilot evidence",
            phase6_alignment_errors(
                self._reseal(wrong_execution), pilot_inputs, pilot_evidence
            ),
        )
        wrong_release = copy.deepcopy(reviewed)
        wrong_release["bindings"]["release_tag"] = "v9.9.9"
        self.assertIn(
            "Phase 6 operations evidence release identity does not match its reviewed dependencies",
            phase6_alignment_errors(self._reseal(wrong_release), pilot_inputs, pilot_evidence),
        )
        synthetic = json.loads(PILOT_EVIDENCE_INDEX.read_text(encoding="utf-8"))
        self.assertIn(
            "Phase 6 operations evidence requires reviewed non-synthetic pilot evidence",
            phase6_alignment_errors(reviewed, pilot_inputs, synthetic),
        )

    def test_references_are_independent_unique_and_redacted(self) -> None:
        reviewed = self._reviewed()
        duplicate = copy.deepcopy(reviewed)
        duplicate["scenarios"]["vault_restore"]["evidence_object_reference"] = duplicate[
            "scenarios"
        ]["postgres_redis_restore"]["evidence_object_reference"]
        same_reviewer = copy.deepcopy(reviewed)
        same_reviewer["scenarios"]["four_role_training"]["reviewer_reference"] = same_reviewer[
            "role_subjects"
        ]["platform_admin"]
        unredacted = copy.deepcopy(reviewed)
        unredacted["scenarios"]["alert_audit_trace_replay"]["redaction_confirmed"] = False
        for document in (duplicate, same_reviewer, unredacted):
            self.assertTrue(index_errors(self._reseal(document)))

    def test_window_integrity_unknown_fields_and_sensitive_claims_fail_closed(self) -> None:
        reviewed = self._reviewed()
        outside = copy.deepcopy(reviewed)
        outside["scenarios"]["page_alert_firing_delivery"]["executed_at"] = "2026-08-27T05:00:00Z"
        unknown = copy.deepcopy(reviewed)
        unknown["raw_restore_log"] = "redacted"
        sensitive = copy.deepcopy(reviewed)
        sensitive["prohibited_content"]["contains_receiver_urls"] = True
        accepted = copy.deepcopy(reviewed)
        accepted["production_acceptance"] = True
        for document in (outside, unknown, sensitive, accepted):
            self.assertTrue(index_errors(self._reseal(document)))
        tampered = copy.deepcopy(reviewed)
        tampered["environment"] = "production"
        self.assertIn(
            "Phase 6 operations evidence index integrity is invalid",
            index_errors(tampered),
        )
        early_review = copy.deepcopy(reviewed)
        early_review["reviewed_at"] = "2026-08-27T03:59:59Z"
        self.assertIn(
            "reviewed Phase 6 operations evidence review validity is invalid",
            index_errors(self._reseal(early_review)),
        )

    def test_operations_are_post_pilot_within_maintenance_and_rollback_deadline(self) -> None:
        reviewed = self._reviewed()
        pilot_inputs = self._pilot_inputs()
        pilot_evidence = self._pilot_evidence()
        self.assertEqual(
            phase6_alignment_errors(
                reviewed,
                pilot_inputs,
                pilot_evidence,
                evaluated_at=EVALUATED_AT,
            ),
            [],
        )
        before_review = copy.deepcopy(reviewed)
        before_review["window"]["started_at"] = "2026-08-27T01:59:59Z"
        after_window = copy.deepcopy(reviewed)
        after_window["window"]["finished_at"] = "2026-08-27T05:00:00Z"
        after_window["reviewed_at"] = "2026-08-27T05:00:00Z"
        late_rollback = copy.deepcopy(reviewed)
        late_rollback["scenarios"]["release_bound_rollback"]["executed_at"] = (
            "2026-08-27T03:00:01Z"
        )
        self.assertIn(
            "Phase 6 operations evidence window is outside the approved post-pilot interval",
            phase6_alignment_errors(
                self._reseal(before_review),
                pilot_inputs,
                pilot_evidence,
                evaluated_at=EVALUATED_AT,
            ),
        )
        self.assertIn(
            "Phase 6 operations evidence window is outside the approved post-pilot interval",
            phase6_alignment_errors(
                self._reseal(after_window),
                pilot_inputs,
                pilot_evidence,
                evaluated_at=EVALUATED_AT,
            ),
        )
        self.assertIn(
            "Phase 6 operations rollback execution is after the approved decision deadline",
            phase6_alignment_errors(
                self._reseal(late_rollback),
                pilot_inputs,
                pilot_evidence,
                evaluated_at=EVALUATED_AT,
            ),
        )

    def test_operations_review_validity_is_half_open(self) -> None:
        reviewed = self._reviewed()
        expired = copy.deepcopy(reviewed)
        expired["valid_until"] = "2026-08-29T00:00:00Z"
        self.assertIn(
            "reviewed Phase 6 operations evidence is not currently valid",
            index_errors(self._reseal(expired), evaluated_at=EVALUATED_AT),
        )

    def test_binding_requires_same_environment_and_three_manifest_artifacts(self) -> None:
        reviewed = self._reviewed()
        manifest = self._manifest(reviewed["bindings"])
        self.assertEqual(intake_binding_errors(reviewed, manifest), [])
        manifest["items"][1]["sha256"] = "9" * 64
        self.assertIn(
            "Phase 6 operations evidence phase6_pilot_evidence binding does not match this intake manifest",
            intake_binding_errors(reviewed, manifest),
        )
        manifest["environment"] = "production"
        self.assertIn(
            "Phase 6 operations evidence environment does not match this intake manifest",
            intake_binding_errors(reviewed, manifest),
        )
        manifest["environment"] = "staging"
        own = next(
            item for item in manifest["items"]
            if item["id"] == "phase6_operations_evidence"
        )
        own["reviewed_by"] = "operations-evidence-review:record-99"
        self.assertIn(
            "Phase 6 operations evidence review metadata does not match this intake manifest",
            intake_binding_errors(reviewed, manifest),
        )

    def test_cli_rejects_synthetic_and_distinguishes_alignment_or_binding_mismatch(self) -> None:
        self.assertEqual(main(["verify-repository"]), 0)
        reviewed = self._reviewed()
        pilot_inputs = self._pilot_inputs()
        pilot_evidence = self._pilot_evidence()
        manifest = self._manifest(reviewed["bindings"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            index_path = root / "operations.json"
            inputs_path = root / "pilot-inputs.json"
            pilot_path = root / "pilot-evidence.json"
            manifest_path = root / "intake.json"
            release_path = root / "forward-release.json"
            recorder = _recorder()
            _complete_success(recorder)
            recorder.write(release_path)
            ledger_digest = hashlib.sha256(release_path.read_bytes()).hexdigest()
            reviewed["release_execution"]["evidence_sha256"] = ledger_digest
            reviewed = self._reseal(reviewed)
            pilot_evidence["release_execution"]["evidence_sha256"] = ledger_digest
            pilot_evidence = seal_pilot_evidence(
                {
                    key: value
                    for key, value in pilot_evidence.items()
                    if key != "integrity"
                }
            )
            inputs_path.write_text(json.dumps(pilot_inputs), encoding="utf-8")
            pilot_path.write_text(json.dumps(pilot_evidence), encoding="utf-8")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            index_path.write_text(json.dumps(self.template), encoding="utf-8")
            args = [
                "check", "--input", str(index_path),
                "--pilot-inputs", str(inputs_path),
                "--pilot-evidence", str(pilot_path),
                "--intake-manifest", str(manifest_path),
                "--release-execution-evidence", str(release_path),
            ]
            self.assertEqual(main(args), 1)
            index_path.write_text(json.dumps(reviewed), encoding="utf-8")
            self.assertEqual(main(args), 0)
            pilot_evidence["trace_set_reference"] = "pilot-trace-set:replacement-9a"
            pilot_evidence = seal_pilot_evidence(
                {key: value for key, value in pilot_evidence.items() if key != "integrity"}
            )
            pilot_path.write_text(json.dumps(pilot_evidence), encoding="utf-8")
            self.assertEqual(main(args), 2)

    def test_runbook_documents_target_drills_and_external_content_limit(self) -> None:
        text = Path("deploy/runbooks/target-intake-preflight.md").read_text(
            encoding="utf-8"
        ).casefold().replace("\n", " ")
        for expected in (
            "phase6_operations_evidence.py check",
            "page firing and resolved",
            "watchdog",
            "postgresql/redis",
            "vault restore",
            "four-role training",
            "does not verify the external evidence content",
        ):
            self.assertIn(expected, text)


if __name__ == "__main__":
    unittest.main()
