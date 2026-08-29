from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from scripts.verify_phase_acceptance_matrix import MATRIX, matrix_errors


class PhaseAcceptanceMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = json.loads(MATRIX.read_text(encoding="utf-8"))

    def test_repository_matrix_is_valid(self) -> None:
        self.assertEqual(matrix_errors(self.document), [])
        quality_gate = Path("scripts/quality_gate.ps1").read_text(encoding="utf-8")
        self.assertIn("python scripts/verify_phase_acceptance_matrix.py", quality_gate)

    def test_rejects_production_acceptance_claims(self) -> None:
        for phase in (None, 0, 6):
            mutated = copy.deepcopy(self.document)
            if phase is None:
                mutated["production_acceptance"] = True
            else:
                mutated["phases"][phase]["production_acceptance"] = True
            with self.subTest(phase=phase):
                self.assertTrue(matrix_errors(mutated))

    def test_rejects_missing_or_changed_plan_contract(self) -> None:
        mutations = []
        missing_phase = copy.deepcopy(self.document)
        missing_phase["phases"].pop(3)
        mutations.append(missing_phase)
        changed_scope = copy.deepcopy(self.document)
        changed_scope["phases"][4]["scope"] = "generic upload"
        mutations.append(changed_scope)
        blank_evidence = copy.deepcopy(self.document)
        blank_evidence["phases"][6]["target_evidence_required"] = []
        mutations.append(blank_evidence)
        extra_key = copy.deepcopy(self.document)
        extra_key["phases"][1]["approved"] = True
        mutations.append(extra_key)
        for index, mutated in enumerate(mutations):
            with self.subTest(index=index):
                self.assertTrue(matrix_errors(mutated))


if __name__ == "__main__":
    unittest.main()
