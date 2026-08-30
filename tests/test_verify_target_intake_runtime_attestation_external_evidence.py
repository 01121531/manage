from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import verify_target_intake_runtime_attestation_external_evidence as static_gate


class RuntimeAttestationExternalEvidenceStaticTests(unittest.TestCase):
    def test_repository_static_contract_is_locked(self) -> None:
        self.assertEqual(static_gate.verify_static_contract(), [])

    def test_network_capability_mutation_is_rejected(self) -> None:
        source = static_gate.INTAKE.read_text(encoding="utf-8") + "\nimport requests\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mutated.py"
            path.write_text(source, encoding="utf-8")
            with mock.patch.object(static_gate, "INTAKE", path):
                errors = static_gate.verify_static_contract()
        self.assertTrue(any("network or subprocess" in error for error in errors), errors)

    def test_promotion_without_matrix_completion_dependency_is_rejected(self) -> None:
        source = static_gate.RELEASE.read_text(encoding="utf-8")
        promoter = source.index("  promote-verified-container-release:")
        mutated = (
            source[:promoter]
            + source[promoter:].replace(
                "    needs:\n      - verified-container-release",
                "    needs: []",
                1,
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "release.yml"
            path.write_text(mutated, encoding="utf-8")
            with mock.patch.object(static_gate, "RELEASE", path):
                errors = static_gate.verify_static_contract()
        self.assertTrue(any("order drifted" in error for error in errors), errors)

    def test_nested_policy_closure_mutation_is_rejected(self) -> None:
        source = static_gate.INTAKE.read_text(encoding="utf-8").replace(
            '_closed(value.get("provider_custody"), _POLICY_PROVIDER_FIELDS',
            'dict(value.get("provider_custody")) # ',
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mutated.py"
            path.write_text(source, encoding="utf-8")
            with mock.patch.object(static_gate, "INTAKE", path):
                errors = static_gate.verify_static_contract()
        self.assertTrue(any("boundary is missing" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
