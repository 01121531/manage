from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from scripts.phase6_pilot_evidence import EXECUTION_SCOPE, REQUIRED_SCENARIOS
from scripts.phase6_rehearsal import (
    SCENARIO,
    _CHECK_KEYS,
    _PERSISTENT_SURFACES,
    _RESOURCE_STATES,
)
from scripts.verify_chapter14_mvi import (
    CONTRACT,
    EXTERNAL_REQUIREMENTS,
    contract_errors,
    main,
    repository_contract_errors,
    seal_contract,
)


class Chapter14MviTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    @staticmethod
    def _reseal(document: dict[str, object]) -> dict[str, object]:
        return seal_contract(
            {key: value for key, value in document.items() if key != "integrity"}
        )

    def test_repository_contract_is_closed_sealed_aligned_and_gated(self) -> None:
        self.assertEqual(contract_errors(self.contract), [])
        self.assertEqual(repository_contract_errors(), [])
        gate = Path("scripts/quality_gate.ps1").read_text(encoding="utf-8")
        self.assertIn("python scripts/verify_chapter14_mvi.py", gate)

    def test_ci_mvi_identity_cannot_claim_target_or_production_completion(self) -> None:
        self.assertEqual(self.contract["plan_chapter"], "14")
        self.assertEqual(self.contract["repository_status"], "local_ci_rehearsal_only")
        self.assertEqual(self.contract["identity_mode"], "local_test")
        self.assertEqual(self.contract["scenario"], SCENARIO)
        self.assertTrue(self.contract["target_execution_required"])
        self.assertFalse(self.contract["production_acceptance"])

    def test_exact_nine_checks_match_rehearsal_and_target_pilot_dimensions(self) -> None:
        self.assertEqual(self.contract["checks"], sorted(_CHECK_KEYS))
        self.assertEqual(set(self.contract["checks"]), set(REQUIRED_SCENARIOS))

    def test_resource_states_and_persistent_surfaces_are_exact(self) -> None:
        self.assertEqual(self.contract["resource_states"], _RESOURCE_STATES)
        self.assertEqual(self.contract["persistent_surfaces"], _PERSISTENT_SURFACES)

    def test_external_requirements_preserve_real_target_boundary(self) -> None:
        self.assertEqual(self.contract["external_requirements"], list(EXTERNAL_REQUIREMENTS))
        self.assertEqual(EXECUTION_SCOPE["origin"], "target_environment")
        self.assertEqual(EXECUTION_SCOPE["identity_mode"], "oidc")
        self.assertEqual(
            EXECUTION_SCOPE["connector_mode"], "reviewed_real_mail_and_sub2"
        )

    def test_missing_check_resource_or_external_requirement_fails_closed(self) -> None:
        missing_check = copy.deepcopy(self.contract)
        missing_check["checks"].pop()
        wrong_resource = copy.deepcopy(self.contract)
        wrong_resource["resource_states"]["card_allocation"] = "allocated"
        missing_external = copy.deepcopy(self.contract)
        missing_external["external_requirements"].pop()
        for document in (missing_check, wrong_resource, missing_external):
            self.assertTrue(contract_errors(self._reseal(document)))

    def test_identity_escalation_unknown_field_and_tampering_fail_closed(self) -> None:
        accepted = copy.deepcopy(self.contract)
        accepted["production_acceptance"] = True
        target = copy.deepcopy(self.contract)
        target["identity_mode"] = "oidc"
        completed = copy.deepcopy(self.contract)
        completed["repository_status"] = "complete"
        unknown = copy.deepcopy(self.contract)
        unknown["approved"] = False
        for document in (accepted, target, completed, unknown):
            self.assertTrue(contract_errors(self._reseal(document)))
        tampered = copy.deepcopy(self.contract)
        tampered["scenario"] = "shorter-flow"
        self.assertIn("Chapter 14 MVI contract integrity is invalid", contract_errors(tampered))

    def test_cli_verifies_repository_without_running_or_upgrading_the_mvi(self) -> None:
        self.assertEqual(main(), 0)


if __name__ == "__main__":
    unittest.main()
