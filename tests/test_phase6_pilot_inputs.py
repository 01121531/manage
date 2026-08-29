from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from scripts.phase6_pilot_inputs import (
    INVENTORY,
    REQUIRED_ROLE_RESPONSIBILITIES,
    intake_binding_errors,
    inventory_errors,
    main,
    repository_contract_errors,
    seal_inventory,
)


class Phase6PilotInputsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.template = json.loads(INVENTORY.read_text(encoding="utf-8"))

    @staticmethod
    def _reseal(document: dict[str, object]) -> dict[str, object]:
        payload = {key: value for key, value in document.items() if key != "integrity"}
        return seal_inventory(payload)

    def _reviewed(self) -> dict[str, object]:
        document = copy.deepcopy(self.template)
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
        return self._reseal(document)

    @staticmethod
    def _manifest(inventory_sha256: str) -> dict[str, object]:
        return {
            "schema_version": 1,
            "environment": "staging",
            "production_acceptance": False,
            "requirements_sha256": "d" * 64,
            "items": [
                {
                    "id": "target_platform_inventory",
                    "status": "provided",
                    "sha256": inventory_sha256,
                }
            ],
        }

    def test_repository_template_is_closed_sealed_safe_aligned_and_gated(self) -> None:
        self.assertEqual(inventory_errors(self.template), [])
        self.assertEqual(repository_contract_errors(), [])
        self.assertTrue(self.template["synthetic"])
        self.assertEqual(self.template["inventory_status"], "pending")
        self.assertFalse(self.template["production_acceptance"])
        self.assertTrue(
            all(
                role["participant_reference"] is None
                for role in self.template["pilot_roles"].values()
            )
        )
        gate = Path("scripts/quality_gate.ps1").read_text(encoding="utf-8")
        self.assertIn("python scripts/phase6_pilot_inputs.py verify-repository", gate)

    def test_reviewed_inventory_requires_exact_four_role_roster_and_responsibilities(self) -> None:
        reviewed = self._reviewed()
        self.assertEqual(inventory_errors(reviewed), [])
        missing = copy.deepcopy(reviewed)
        missing["pilot_roles"].pop("security_auditor")
        wrong = copy.deepcopy(reviewed)
        wrong["pilot_roles"]["operator"]["responsibility"] = "administer_platform"
        duplicate = copy.deepcopy(reviewed)
        duplicate["pilot_roles"]["ops_admin"]["participant_reference"] = duplicate[
            "pilot_roles"
        ]["operator"]["participant_reference"]
        for document in (missing, wrong, duplicate):
            self.assertTrue(inventory_errors(self._reseal(document)))

    def test_references_are_opaque_typed_and_independent(self) -> None:
        reviewed = self._reviewed()
        email = copy.deepcopy(reviewed)
        email["pilot_roles"]["operator"]["participant_reference"] = "alice@example.com"
        name = copy.deepcopy(reviewed)
        name["pilot_roles"]["operator"]["participant_reference"] = "pilot-subject-ref:alice-smith"
        reused_owner = copy.deepcopy(reviewed)
        reused_owner["ownership"]["maintenance_owner_reference"] = reused_owner[
            "ownership"
        ]["target_operator_owner_reference"]
        reviewer_participant = copy.deepcopy(reviewed)
        reviewer_participant["review_reference"] = reviewer_participant["pilot_roles"][
            "operator"
        ]["participant_reference"]
        for document in (email, name, reused_owner, reviewer_participant):
            self.assertTrue(inventory_errors(self._reseal(document)))

    def test_maintenance_window_is_canonical_utc_approved_and_ordered(self) -> None:
        reviewed = self._reviewed()
        reversed_window = copy.deepcopy(reviewed)
        reversed_window["maintenance_window"]["rollback_decision_deadline"] = (
            "2026-08-27T02:30:00Z"
        )
        offset = copy.deepcopy(reviewed)
        offset["maintenance_window"]["starts_at"] = "2026-08-27T09:00:00+08:00"
        same_record = copy.deepcopy(reviewed)
        same_record["maintenance_window"]["approval_reference"] = same_record[
            "maintenance_window"
        ]["change_reference"]
        for document in (reversed_window, offset, same_record):
            self.assertTrue(inventory_errors(self._reseal(document)))

    def test_release_integrity_unknown_fields_and_sensitive_claims_fail_closed(self) -> None:
        reviewed = self._reviewed()
        bad_commit = copy.deepcopy(reviewed)
        bad_commit["bindings"]["release_commit"] = "not-a-commit"
        unknown = copy.deepcopy(reviewed)
        unknown["participant_email"] = "redacted"
        sensitive = copy.deepcopy(reviewed)
        sensitive["prohibited_content"]["contains_personal_data"] = True
        accepted = copy.deepcopy(reviewed)
        accepted["production_acceptance"] = True
        for document in (bad_commit, unknown, sensitive, accepted):
            self.assertTrue(inventory_errors(self._reseal(document)))
        tampered = copy.deepcopy(reviewed)
        tampered["environment"] = "production"
        self.assertIn("Phase 6 pilot input inventory integrity is invalid", inventory_errors(tampered))

    def test_binding_requires_same_environment_and_target_inventory(self) -> None:
        reviewed = self._reviewed()
        manifest = self._manifest(
            reviewed["bindings"]["target_platform_inventory_sha256"]
        )
        self.assertEqual(intake_binding_errors(reviewed, manifest), [])
        manifest["items"][0]["sha256"] = "e" * 64
        self.assertIn(
            "Phase 6 pilot inputs target_platform_inventory binding does not match this intake manifest",
            intake_binding_errors(reviewed, manifest),
        )
        manifest["environment"] = "production"
        self.assertIn(
            "Phase 6 pilot inputs environment does not match this intake manifest",
            intake_binding_errors(reviewed, manifest),
        )

    def test_cli_rejects_synthetic_and_distinguishes_binding_mismatch(self) -> None:
        self.assertEqual(main(["verify-repository"]), 0)
        reviewed = self._reviewed()
        manifest = self._manifest(
            reviewed["bindings"]["target_platform_inventory_sha256"]
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inventory_path = root / "pilot-inputs.json"
            manifest_path = root / "intake.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            inventory_path.write_text(json.dumps(self.template), encoding="utf-8")
            self.assertEqual(main(["check", "--input", str(inventory_path), "--intake-manifest", str(manifest_path)]), 1)
            inventory_path.write_text(json.dumps(reviewed), encoding="utf-8")
            self.assertEqual(main(["check", "--input", str(inventory_path), "--intake-manifest", str(manifest_path)]), 0)
            manifest["items"][0]["sha256"] = "e" * 64
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(main(["check", "--input", str(inventory_path), "--intake-manifest", str(manifest_path)]), 2)

    def test_runbook_documents_opaque_roster_and_input_only_limit(self) -> None:
        rendered = json.dumps(self.template, ensure_ascii=False).casefold()
        for forbidden in ("@example", "4111111111111111", "bearer ", "client_secret", "+86"):
            self.assertNotIn(forbidden, rendered)
        text = Path("deploy/runbooks/target-intake-preflight.md").read_text(encoding="utf-8").casefold().replace("\n", " ")
        for expected in (
            "phase6_pilot_inputs.py check",
            "opaque roster references",
            "rollback decision deadline",
            "does not prove that any pilot execution occurred",
        ):
            self.assertIn(expected, text)


if __name__ == "__main__":
    unittest.main()
