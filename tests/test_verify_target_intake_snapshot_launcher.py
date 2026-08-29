from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest

from scripts.verify_target_intake_snapshot_launcher import ROOT, snapshot_launcher_gate_errors


FILES = (
    "scripts/target_intake_snapshot_launcher.py",
    "scripts/target_intake_source_snapshot.py",
    "scripts/target_intake_validator_contract.py",
    "scripts/target_intake_generation.py",
    "scripts/target_intake_preflight.py",
    "scripts/quality_gate.ps1",
)


class VerifyTargetIntakeSnapshotLauncherTests(unittest.TestCase):
    def _copy(self, temporary: str) -> Path:
        root = Path(temporary)
        for relative in FILES:
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        return root

    def _mutate(self, relative: str, old: str, new: str) -> list[str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._copy(temporary)
            path = root / relative
            text = path.read_text(encoding="utf-8")
            self.assertIn(old, text)
            path.write_text(text.replace(old, new, 1), encoding="utf-8")
            return snapshot_launcher_gate_errors(root)

    def test_repository_contract_passes(self) -> None:
        self.assertEqual(snapshot_launcher_gate_errors(), [])

    def test_rejects_missing_isolation_flag(self) -> None:
        self.assertTrue(self._mutate(
            "scripts/target_intake_snapshot_launcher.py", '            "-I",\n', ""
        ))

    def test_rejects_child_recursion(self) -> None:
        self.assertTrue(self._mutate(
            "scripts/target_intake_snapshot_launcher.py",
            "def _child_main(argv: Sequence[str]) -> int:\n",
            "def _child_main(argv: Sequence[str]) -> int:\n    subprocess.run([])\n",
        ))

    def test_rejects_removed_source_initializer(self) -> None:
        self.assertTrue(self._mutate(
            "scripts/target_intake_validator_contract.py",
            '    "platform/api/__init__.py",\n', "",
        ))

    def test_rejects_direct_operational_entrypoint_bypass(self) -> None:
        self.assertTrue(self._mutate(
            "scripts/target_intake_preflight.py",
            'if not argv or argv[0] != "verify-requirements":', "if False:",
        ))

    def test_rejects_quality_gate_removal(self) -> None:
        self.assertTrue(self._mutate(
            "scripts/quality_gate.ps1",
            "    python scripts/verify_target_intake_snapshot_launcher.py\n", "",
        ))


if __name__ == "__main__":
    unittest.main()
