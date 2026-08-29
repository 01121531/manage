from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from scripts.verify_phase_acceptance_matrix import MATRIX
from scripts.verify_chapter13_defaults import DECISIONS
from scripts.verify_chapter14_mvi import CONTRACT as CHAPTER14_CONTRACT
from scripts.verify_plan_completion import (
    EXPECTED_COMPLETION_CLASSES,
    LEDGER,
    audit_errors,
    main,
    repository_entrypoint_errors,
    seal_ledger,
)


class PlanCompletionAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
        self.matrix = json.loads(MATRIX.read_text(encoding="utf-8"))

    @staticmethod
    def _reseal(document: dict[str, object]) -> dict[str, object]:
        return seal_ledger(
            {key: value for key, value in document.items() if key != "integrity"}
        )

    def test_repository_ledger_is_closed_sealed_aligned_and_gated(self) -> None:
        self.assertEqual(audit_errors(self.ledger, self.matrix), [])
        self.assertEqual(repository_entrypoint_errors(self.ledger), [])
        self.assertFalse(self.ledger["production_acceptance"])
        self.assertEqual(
            self.ledger["ledger_status"],
            "repository_and_preflight_evidence_only",
        )
        gate = Path("scripts/quality_gate.ps1").read_text(encoding="utf-8")
        self.assertIn("python scripts/verify_plan_completion.py", gate)

    def test_exact_phase_status_and_completion_class_remain_pending(self) -> None:
        self.assertEqual(
            [phase["phase"] for phase in self.ledger["phases"]],
            list(range(7)),
        )
        for phase in self.ledger["phases"]:
            number = phase["phase"]
            self.assertEqual(
                phase["completion_class"],
                EXPECTED_COMPLETION_CLASSES[number],
            )
            self.assertFalse(phase["production_acceptance"])
            self.assertIn("pending", phase["completion_class"])
            self.assertEqual(phase["target_evidence_state"], "required_external")

    def test_chapters_13_and_14_remain_external_confirmation_pending(self) -> None:
        supplemental = self.ledger["supplemental_chapters"]
        self.assertEqual(set(supplemental), {"13", "14"})
        self.assertEqual(
            supplemental["13"]["repository_status"],
            "defaults_locked_with_unvalidated_capacity",
        )
        self.assertEqual(
            supplemental["13"]["completion_class"],
            "repository_defaults_locked_external_confirmation_pending",
        )
        self.assertEqual(
            supplemental["14"]["repository_status"],
            "local_ci_rehearsal_only",
        )
        self.assertEqual(
            supplemental["14"]["completion_class"],
            "repository_mvi_rehearsal_passed_target_execution_pending",
        )
        for chapter in supplemental.values():
            self.assertFalse(chapter["production_acceptance"])
            self.assertEqual(
                chapter["external_confirmation_state"], "required_external"
            )

    def test_missing_input_state_and_matrix_digest_are_authoritative(self) -> None:
        self.assertEqual(audit_errors(self.ledger, self.matrix), [])
        states = {
            phase["phase"]: phase["missing_input_state"]
            for phase in self.ledger["phases"]
        }
        self.assertEqual(states[1], "none_declared")
        self.assertTrue(
            all(
                states[phase] == "required_external"
                for phase in (0, 2, 3, 4, 5, 6)
            )
        )
        changed_matrix = copy.deepcopy(self.matrix)
        changed_matrix["phases"][4]["missing_inputs"].append("new provider input")
        self.assertIn(
            "completion ledger matrix digest does not match the acceptance matrix",
            audit_errors(self.ledger, changed_matrix),
        )

    def test_status_or_acceptance_escalation_fails_closed(self) -> None:
        accepted = copy.deepcopy(self.ledger)
        accepted["production_acceptance"] = True
        phase_accepted = copy.deepcopy(self.ledger)
        phase_accepted["phases"][6]["production_acceptance"] = True
        promoted = copy.deepcopy(self.ledger)
        promoted["phases"][6]["repository_status"] = "repository_gate_passed"
        completed = copy.deepcopy(self.ledger)
        completed["phases"][0]["completion_class"] = "complete"
        for document in (accepted, phase_accepted, promoted, completed):
            self.assertTrue(audit_errors(self._reseal(document), self.matrix))

    def test_entrypoint_removal_extra_field_or_path_drift_fails_closed(self) -> None:
        missing_command = copy.deepcopy(self.ledger)
        missing_command["phases"][4]["gate_commands"].pop()
        unknown = copy.deepcopy(self.ledger)
        unknown["phases"][2]["notes"] = "looks complete"
        wrong_runbook = copy.deepcopy(self.ledger)
        wrong_runbook["phases"][6]["runbooks"][0] = "README.md"
        wrong_test = copy.deepcopy(self.ledger)
        wrong_test["phases"][3]["test_modules"][0] = "tests/test_app.py"
        completed_chapter = copy.deepcopy(self.ledger)
        completed_chapter["supplemental_chapters"]["14"][
            "completion_class"
        ] = "complete"
        for document in (
            missing_command,
            unknown,
            wrong_runbook,
            wrong_test,
            completed_chapter,
        ):
            self.assertTrue(audit_errors(self._reseal(document), self.matrix))

    def test_supplemental_source_digest_and_contract_drift_fail_closed(self) -> None:
        chapter13 = json.loads(DECISIONS.read_text(encoding="utf-8"))
        chapter14 = json.loads(CHAPTER14_CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(
            audit_errors(self.ledger, self.matrix, chapter13, chapter14), []
        )
        chapter13["decisions"]["capacity_basis"]["status"] = (
            "repository_gate_passed"
        )
        self.assertTrue(
            audit_errors(self.ledger, self.matrix, chapter13, chapter14)
        )
        chapter13 = json.loads(DECISIONS.read_text(encoding="utf-8"))
        chapter14["repository_status"] = "complete"
        chapter14 = seal_ledger(
            {key: value for key, value in chapter14.items() if key != "integrity"}
        )
        self.assertTrue(
            audit_errors(self.ledger, self.matrix, chapter13, chapter14)
        )

    def test_every_registered_entrypoint_exists_and_commands_are_in_quality_gate(self) -> None:
        self.assertEqual(repository_entrypoint_errors(self.ledger), [])
        missing = copy.deepcopy(self.ledger)
        missing["phases"][0]["runbooks"][0] = "deploy/runbooks/not-present.md"
        self.assertTrue(repository_entrypoint_errors(self._reseal(missing)))

    def test_integrity_and_top_level_schema_reject_tampering(self) -> None:
        tampered = copy.deepcopy(self.ledger)
        tampered["audit_scope"] = "phase_0_only"
        self.assertIn(
            "completion ledger integrity is invalid",
            audit_errors(tampered, self.matrix),
        )
        unknown = copy.deepcopy(self.ledger)
        unknown["approved"] = False
        self.assertIn(
            "completion ledger top-level schema is invalid",
            audit_errors(unknown, self.matrix),
        )

    def test_cli_verifies_repository_without_claiming_completion(self) -> None:
        self.assertEqual(main(), 0)


if __name__ == "__main__":
    unittest.main()
