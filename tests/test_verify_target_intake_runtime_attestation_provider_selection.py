from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import (
    verify_target_intake_runtime_attestation_provider_selection as static_gate,
)


class ProviderSelectionStaticTests(unittest.TestCase):
    def test_repository_static_contract_is_locked(self) -> None:
        self.assertEqual(static_gate.verify_static_contract(), [])

    def test_online_capability_mutation_is_rejected(self) -> None:
        source = static_gate.INTAKE.read_text(encoding="utf-8") + "\nimport requests\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mutated.py"
            path.write_text(source, encoding="utf-8")
            with mock.patch.object(static_gate, "INTAKE", path):
                errors = static_gate.verify_static_contract()
        self.assertTrue(any("online capability" in error for error in errors), errors)

    def test_negative_authority_marker_mutation_is_rejected(self) -> None:
        source = static_gate.INTAKE.read_text(encoding="utf-8").replace(
            "provider_custody_verified: bool = False",
            "provider_custody_verified: bool = True",
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mutated.py"
            path.write_text(source, encoding="utf-8")
            with mock.patch.object(static_gate, "INTAKE", path):
                errors = static_gate.verify_static_contract()
        self.assertTrue(any("boundary is missing" in error for error in errors), errors)

    def test_predecessor_pin_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "predecessor.json"
            path.write_text("{}\n", encoding="utf-8")
            with mock.patch.object(static_gate, "PREDECESSOR", path):
                errors = static_gate.verify_static_contract()
        self.assertTrue(any("predecessor" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
