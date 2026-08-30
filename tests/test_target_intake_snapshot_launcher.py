from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import py_compile
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
    def test_missing_pycache_prefix_prevents_unchecked_hash_cache_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "cache_probe.py"
            source.write_text("VALUE = 'cache-b'\n", encoding="utf-8")
            py_compile.compile(
                str(source),
                doraise=True,
                invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
            )
            source.write_text("VALUE = 'source-a'\n", encoding="utf-8")
            program = (
                "import sys; "
                f"sys.path.insert(0, {str(base)!r}); "
                "import cache_probe; print(cache_probe.VALUE)"
            )
            cached = subprocess.run(
                [sys.executable, "-I", "-B", "-S", "-P", "-c", program],
                cwd=base,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
            prefix = base / "missing-pycache-prefix"
            redirected = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-S",
                    "-P",
                    "-X",
                    f"pycache_prefix={prefix}",
                    "-c",
                    program,
                ],
                cwd=base,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
            self.assertEqual(cached.stdout.strip(), "cache-b")
            self.assertEqual(redirected.stdout.strip(), "source-a")
            self.assertFalse(prefix.exists())

    def test_clean_child_initializes_v8_receipt_bound_to_snapshot_profile(self) -> None:
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
            self.assertEqual(receipt["schema_version"], 8)
            self.assertEqual(receipt["kind"], "target_intake_generation_receipt_v8")
            contract = receipt["validation_context"]["validator_contract"]
            self.assertEqual(contract["schema_version"], 5)
            self.assertEqual(contract["runtime_environment"]["schema_version"], 3)
            closure = contract["runtime_environment"]["distribution_closure"]
            self.assertEqual(len(closure["root_names"]), 11)
            self.assertIn("annotated-types", closure["metadata_closure_names"])
            self.assertIn("cffi", closure["loaded_owner_names"])
            self.assertIn("packaging", closure["union_names"])
            self.assertEqual(
                [item["name"] for item in contract["runtime_environment"]["distributions"]],
                closure["union_names"],
            )
            self.assertEqual(len(contract["source_files"]), 65)
            profile = contract["execution_profile"]
            self.assertEqual(
                profile["mode"],
                "clean_isolated_external_snapshot_subprocess_v2",
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
            self.assertTrue(profile["isolated_missing_pycache_prefix"])
            self.assertTrue(profile["sourceless_loaders_rejected"])
            self.assertTrue(profile["local_module_origins_rechecked"])
            self.assertTrue(profile["snapshot_pre_and_post_recheck_required"])
            self.assertRegex(
                profile["launcher_interpreter_sha256"], r"^[0-9a-f]{64}$"
            )
            self.assertTrue(profile["runtime_pre_and_post_recheck_required"])
            self.assertTrue(profile["loaded_runtime_pre_and_post_recheck_required"])
            self.assertGreater(len(profile["loaded_owner_names"]), 11)
            self.assertGreater(profile["loaded_origin_file_count"], 1)
            self.assertRegex(profile["loaded_origin_map_sha256"], r"^[0-9a-f]{64}$")
            self.assertGreater(profile["loaded_module_file_count"], 1)
            self.assertRegex(profile["loaded_module_tree_sha256"], r"^[0-9a-f]{64}$")
            self.assertGreater(profile["loaded_native_file_count"], 1)
            self.assertRegex(profile["loaded_native_tree_sha256"], r"^[0-9a-f]{64}$")

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
                mock.patch.object(
                    launcher,
                    "_read_stable_binary",
                    side_effect=[(b"python", identity), (b"python", identity)],
                ),
                mock.patch.object(
                    launcher.subprocess,
                    "run",
                    side_effect=[
                        subprocess.CompletedProcess(
                            [],
                            0,
                            stdout=json.dumps(
                                {
                                    "schema_version": 1,
                                    "kind": launcher._DISCOVERY_KIND,
                                    "owner_names": ["fastapi"],
                                    "origin_file_count": 1,
                                    "origin_map_sha256": "c" * 64,
                                }
                            ),
                            stderr="",
                        ),
                        completed,
                    ],
                ) as run,
            ):
                result = launcher._run(snapshot, "a" * 64, "b" * 64, ["verify-requirements"])
            self.assertEqual(result, 0)
            command = run.call_args_list[1].args[0]
            self.assertEqual(Path(command[0]), Path(sys.executable).resolve(strict=True))
            self.assertEqual(command[1:6], ["-I", "-B", "-S", "-P", "-X"])
            self.assertEqual(command[6], f"pycache_prefix={snapshot / launcher._PYCACHE_DIRECTORY}")
            self.assertEqual(command[7], "-c")
            self.assertEqual(command[12], hashlib.sha256(b"python").hexdigest())
            call = run.call_args_list[1]
            self.assertEqual(call.kwargs["cwd"], snapshot)
            self.assertEqual(call.kwargs["stdin"], subprocess.DEVNULL)
            self.assertIs(call.kwargs["shell"], False)
            self.assertEqual(call.kwargs["timeout"], 600)
            environment = call.kwargs["env"]
            self.assertNotIn("PYTHONPATH", environment)
            self.assertNotIn("PYTHONHOME", environment)
            self.assertNotIn("PATH", environment)

    def test_parent_rejects_same_path_interpreter_byte_drift(self) -> None:
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
                mock.patch.object(
                    launcher,
                    "_read_stable_binary",
                    side_effect=[(b"python-a", identity), (b"python-b", identity)],
                ),
                mock.patch.object(
                    launcher.subprocess,
                    "run",
                    side_effect=[
                        subprocess.CompletedProcess(
                            [],
                            0,
                            stdout=json.dumps(
                                {
                                    "schema_version": 1,
                                    "kind": launcher._DISCOVERY_KIND,
                                    "owner_names": ["fastapi"],
                                    "origin_file_count": 1,
                                    "origin_map_sha256": "c" * 64,
                                }
                            ),
                            stderr="",
                        ),
                        completed,
                    ],
                ),
            ):
                result = launcher._run(
                    snapshot,
                    "a" * 64,
                    "b" * 64,
                    ["verify-requirements"],
                )
            self.assertEqual(result, 1)

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

    def test_parent_rejects_existing_pycache_prefix_before_any_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            snapshot = Path(temporary).resolve() / "snapshot"
            snapshot.mkdir()
            (snapshot / launcher._PYCACHE_DIRECTORY).mkdir()
            identity = (1, 2, 1, 3, 4)
            with (
                mock.patch.object(
                    launcher,
                    "_read_stable_manifest",
                    return_value=({}, b"manifest", identity),
                ),
                mock.patch.object(
                    launcher,
                    "_read_stable_binary",
                    return_value=(b"python", identity),
                ),
                mock.patch.object(launcher.subprocess, "run") as run,
            ):
                result = launcher._run(
                    snapshot,
                    "a" * 64,
                    "b" * 64,
                    ["verify-requirements"],
                )
        self.assertEqual(result, 1)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
