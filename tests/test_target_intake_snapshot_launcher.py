from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts import target_intake_snapshot_launcher as launcher
from scripts.target_intake_source_snapshot import prepare_source_snapshot


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "scripts" / "target_intake_snapshot_launcher.py"
PREFLIGHT = ROOT / "scripts" / "target_intake_preflight.py"


def _launcher_command(*arguments: str) -> list[str]:
    return [
        sys.executable,
        "-I",
        "-B",
        "-S",
        "-P",
        str(LAUNCHER),
        *arguments,
    ]


class TargetIntakeSnapshotLauncherTests(unittest.TestCase):
    def test_clean_child_initializes_v6_receipt_bound_to_snapshot_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            attacker = base / "attacker"
            attacker.mkdir()
            poison_marker = base / "poisoned"
            (attacker / "sitecustomize.py").write_text(
                f"from pathlib import Path\nPath({str(poison_marker)!r}).write_text('poisoned')\n",
                encoding="utf-8",
            )
            snapshot = prepare_source_snapshot(base / "source-snapshot")
            manifest_output = base / "generation-000.json"
            receipt_output = base / "generation-000.receipt.json"
            completed = subprocess.run(
                _launcher_command(
                    "run",
                    "--snapshot",
                    str(snapshot.directory),
                    "--expected-snapshot-manifest-payload-sha256",
                    snapshot.payload_sha256,
                    "--expected-snapshot-manifest-file-sha256",
                    snapshot.file_sha256,
                    "--",
                    "init",
                    "--output",
                    str(manifest_output),
                    "--receipt-output",
                    str(receipt_output),
                    "--environment",
                    "staging",
                ),
                cwd=base,
                env={
                    **({"SYSTEMROOT": os.environ["SYSTEMROOT"]} if "SYSTEMROOT" in os.environ else {}),
                    "PYTHONPATH": str(attacker),
                    "PYTHONSTARTUP": str(attacker / "sitecustomize.py"),
                },
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("target-intake-validator-snapshot-child-ok", completed.stdout)
            self.assertIn("target-intake-validator-snapshot-launch-ok", completed.stdout)
            self.assertFalse(poison_marker.exists())
            receipt = json.loads(receipt_output.read_text(encoding="utf-8"))
            self.assertEqual(receipt["schema_version"], 6)
            self.assertEqual(receipt["kind"], "target_intake_generation_receipt_v6")
            contract = receipt["validation_context"]["validator_contract"]
            self.assertEqual(contract["schema_version"], 3)
            self.assertEqual(len(contract["source_files"]), 65)
            profile = contract["execution_profile"]
            self.assertEqual(
                profile["mode"],
                "clean_isolated_external_snapshot_subprocess_v1",
            )
            self.assertEqual(
                profile["snapshot_manifest_payload_sha256"],
                snapshot.payload_sha256,
            )
            self.assertEqual(
                profile["snapshot_manifest_file_sha256"], snapshot.file_sha256
            )
            self.assertTrue(profile["isolated"])
            self.assertTrue(profile["ignore_environment"])
            self.assertTrue(profile["no_site"])
            self.assertTrue(profile["safe_path"])
            self.assertTrue(profile["dont_write_bytecode"])
            self.assertTrue(profile["local_module_origins_rechecked"])
            self.assertTrue(profile["snapshot_pre_and_post_recheck_required"])

    def test_isolated_prepare_cli_publishes_external_snapshot_pins(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "prepared-snapshot"
            completed = subprocess.run(
                _launcher_command(
                    "prepare", "--snapshot-output", str(destination)
                ),
                cwd=Path(temporary),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn(
                "target-intake-validator-source-snapshot-prepared",
                completed.stdout,
            )
            self.assertIn("snapshot_manifest_payload_sha256=", completed.stdout)
            self.assertIn("snapshot_manifest_file_sha256=", completed.stdout)
            self.assertTrue(
                (destination / launcher.MANIFEST_FILENAME).is_file()
            )
    def test_clean_child_rejects_wrong_snapshot_pin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            snapshot = prepare_source_snapshot(base / "source-snapshot")
            completed = subprocess.run(
                _launcher_command(
                    "run",
                    "--snapshot",
                    str(snapshot.directory),
                    "--expected-snapshot-manifest-payload-sha256",
                    "0" * 64,
                    "--expected-snapshot-manifest-file-sha256",
                    snapshot.file_sha256,
                    "--",
                    "verify-requirements",
                ),
                cwd=base,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertIn("target-intake-validator-snapshot-launch-invalid", completed.stderr)

    def test_direct_script_blocks_operational_commands(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-B", str(PREFLIGHT), "init"],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(
            completed.stderr.strip(),
            "target-intake-validator-snapshot-launcher-required",
        )

    def test_parent_uses_exact_isolation_flags_and_sanitized_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            snapshot = Path(temporary).resolve() / "snapshot"
            snapshot.mkdir()
            identity = (1, 2, 1, 3, 4)
            completed = subprocess.CompletedProcess([], 0)
            with (
                mock.patch.object(
                    launcher,
                    "_read_stable_manifest",
                    side_effect=[({}, b"manifest", identity), ({}, b"manifest", identity)],
                ),
                mock.patch.object(launcher.subprocess, "run", return_value=completed) as run,
            ):
                result = launcher._run(snapshot, "a" * 64, "b" * 64, ["verify-requirements"])
            self.assertEqual(result, 0)
            command = run.call_args.args[0]
            self.assertEqual(Path(command[0]), Path(sys.executable).resolve(strict=True))
            self.assertEqual(command[1:6], ["-I", "-B", "-S", "-P", "-c"])
            self.assertEqual(run.call_args.kwargs["cwd"], snapshot)
            self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
            self.assertIs(run.call_args.kwargs["shell"], False)
            self.assertEqual(run.call_args.kwargs["timeout"], 600)
            environment = run.call_args.kwargs["env"]
            self.assertNotIn("PYTHONPATH", environment)
            self.assertNotIn("PYTHONHOME", environment)
            self.assertNotIn("PATH", environment)

    def test_parent_rejects_snapshot_inside_repository_before_read_or_launch(self) -> None:
        with (
            mock.patch.object(launcher, "_read_stable_manifest") as read_manifest,
            mock.patch.object(launcher.subprocess, "run") as run,
        ):
            result = launcher._run(
                ROOT / "synthetic-snapshot",
                "a" * 64,
                "b" * 64,
                ["verify-requirements"],
            )
        self.assertEqual(result, 1)
        read_manifest.assert_not_called()
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
