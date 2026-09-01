import ast
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from uuid import uuid4

from platform.pool_import_execution import build_execution_event, build_execution_plan
from scripts.secure_pool_import_recovery import assess_execution_directory


ROOT = Path(__file__).resolve().parents[1]


class SecurePoolImportRecoveryTests(unittest.TestCase):
    @staticmethod
    def _plan() -> dict[str, object]:
        return build_execution_plan(
            execution_id=str(uuid4()),
            pool_type="card",
            vault_origin="https://vault.example.invalid",
            tenant_id="tenant-a",
            audience="email-platform:pool-import:test",
            ordered_manifest_digest="a" * 64,
            secret_refs=["vault://secret/cards/imports/example/0"],
            created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )

    @staticmethod
    def _publish(path: Path, value: object) -> None:
        path.write_text(
            json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
            encoding="ascii",
        )

    def test_plan_only_proves_no_vault_mutation_attempted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "execution"
            directory.mkdir()
            self._publish(directory / "plan.json", self._plan())

            result = assess_execution_directory(
                directory,
                Path(temporary) / "missing-bundle.json",
            )

            self.assertEqual(result["status"], "unwritten")
            self.assertEqual(result["phase"], "no_vault_mutation_attempted")
            self.assertEqual(result["confirmed_count"], 0)
            self.assertEqual(result["token_revocation"], "not_recorded")
            self.assertFalse(result["automatic_resume_allowed"])
            self.assertFalse(result["production_acceptance"])

    def test_revocation_intent_is_reported_without_changing_import_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "execution"
            directory.mkdir()
            plan = self._plan()
            self._publish(directory / "plan.json", plan)
            self._publish(
                directory / "token-revoke.intent.json",
                build_execution_event(
                    plan,
                    event_type="vault_token_revoke_intent",
                    index=None,
                    artifact_sha256=None,
                    occurred_at=datetime.now(timezone.utc).isoformat().replace(
                        "+00:00", "Z"
                    ),
                ),
            )

            result = assess_execution_directory(
                directory,
                Path(temporary) / "missing-bundle.json",
            )

            self.assertEqual(result["status"], "unwritten")
            self.assertEqual(result["token_revocation"], "unconfirmed")
            self.assertFalse(result["automatic_resume_allowed"])

    def test_tampering_or_unknown_inventory_never_becomes_resumable(self) -> None:
        for label in ("tampered_plan", "extra_file"):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / "execution"
                directory.mkdir()
                plan = self._plan()
                if label == "tampered_plan":
                    plan["item_count"] = 2
                self._publish(directory / "plan.json", plan)
                if label == "extra_file":
                    self._publish(directory / "operator-note.json", {"resume": True})

                result = assess_execution_directory(
                    directory,
                    Path(temporary) / "missing-bundle.json",
                )

                self.assertEqual(result["status"], "commit_unknown")
                self.assertIn(
                    result["phase"],
                    {"plan_invalid", "record_inventory_invalid"},
                )
                self.assertFalse(result["automatic_resume_allowed"])

    def test_recovery_module_has_no_mutation_or_importer_dependency(self) -> None:
        source = (ROOT / "scripts" / "secure_pool_import_recovery.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        called_names = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        } | {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }

        self.assertNotIn("scripts.secure_pool_import", imported)
        self.assertTrue(imported.isdisjoint({"subprocess", "urllib", "requests", "httpx"}))
        self.assertTrue(
            called_names.isdisjoint(
                {
                    "open",
                    "write",
                    "write_bytes",
                    "write_text",
                    "unlink",
                    "remove",
                    "rename",
                    "replace",
                    "rmdir",
                    "mkdir",
                }
            )
        )

    def test_documented_cli_entrypoints_run_directly(self) -> None:
        for relative_path in (
            "scripts/secure_pool_import.py",
            "scripts/secure_pool_import_recovery.py",
            "scripts/secure_import_vault_smoke.py",
            "scripts/secure_import_vault_canary_cleanup.py",
        ):
            with self.subTest(script=relative_path):
                result = subprocess.run(
                    [sys.executable, str(ROOT / relative_path), "--help"],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("usage:", result.stdout)


if __name__ == "__main__":
    unittest.main()
