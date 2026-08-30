from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import (
    verify_target_intake_runtime_attestation_provider_cas_evidence as static_gate,
)


class ProviderCasEvidenceStaticTests(unittest.TestCase):
    def test_repository_static_contract_is_locked(self) -> None:
        self.assertEqual(static_gate.verify_static_contract(), [])

    def test_online_or_write_capability_mutation_is_rejected(self) -> None:
        for mutation in ("\nimport requests\n", "\nPath('x').write_text('x')\n"):
            with self.subTest(mutation=mutation.strip()):
                source = static_gate.INTAKE.read_text(encoding="utf-8") + mutation
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "mutated.py"
                    path.write_text(source, encoding="utf-8")
                    with mock.patch.object(static_gate, "INTAKE", path):
                        errors = static_gate.verify_static_contract()
                self.assertTrue(
                    any("capability" in error for error in errors), errors
                )

    def test_negative_authority_marker_mutation_is_rejected(self) -> None:
        source = static_gate.INTAKE.read_text(encoding="utf-8").replace(
            "provider_native_cas_verified: bool = False",
            "provider_native_cas_verified: bool = True",
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mutated.py"
            path.write_text(source, encoding="utf-8")
            with mock.patch.object(static_gate, "INTAKE", path):
                errors = static_gate.verify_static_contract()
        self.assertTrue(any("boundary is missing" in error for error in errors), errors)

    def test_predecessor_and_raw_artifact_drift_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            predecessor = Path(directory) / "selection.json"
            predecessor.write_text("{}\n", encoding="utf-8")
            with mock.patch.object(static_gate, "SELECTION_POLICY", predecessor):
                errors = static_gate.verify_static_contract()
        self.assertTrue(any("predecessor" in error for error in errors), errors)

        with tempfile.TemporaryDirectory() as directory:
            fixture_root = Path(directory)
            for path in static_gate.SYNTHETIC_ARTIFACT_ROOT.iterdir():
                (fixture_root / path.name).write_bytes(path.read_bytes())
            first = next(fixture_root.iterdir())
            first.write_bytes(first.read_bytes() + b"tampered")
            with mock.patch.object(static_gate, "SYNTHETIC_ARTIFACT_ROOT", fixture_root):
                errors = static_gate.verify_static_contract()
        self.assertTrue(any("artifact binding" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
