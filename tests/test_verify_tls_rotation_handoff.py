from __future__ import annotations

from pathlib import Path
import unittest

from scripts.verify_tls_rotation_handoff import HANDOFF, validate_source


class VerifyTlsRotationHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = HANDOFF.read_text(encoding="utf-8")

    def test_current_source_passes(self) -> None:
        self.assertEqual(validate_source(self.source), [])
        self.assertIn(
            "python scripts/verify_tls_rotation_handoff.py",
            Path("scripts/quality_gate.ps1").read_text(encoding="utf-8"),
        )

    def test_absence_cannot_be_promoted_to_not_committed(self) -> None:
        mutated = self.source.replace('"state": "unknown"', '"state": "not_committed"', 1)
        self.assertTrue(validate_source(mutated))

    def test_mutation_authority_is_rejected(self) -> None:
        mutated = self.source.replace(
            "started_at = clock()", "restart_kubernetes_deployment()\n        started_at = clock()", 1
        )
        self.assertTrue(validate_source(mutated))

    def test_second_identity_bound_read_is_required(self) -> None:
        mutated = self.source.replace(
            "expected_identity=stable_file_identity(first_metadata)",
            "expected_identity=None",
            1,
        )
        self.assertTrue(validate_source(mutated))


if __name__ == "__main__":
    unittest.main()
