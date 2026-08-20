import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "postgres_maintenance.py"
SPEC = importlib.util.spec_from_file_location("postgres_maintenance", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
postgres_maintenance = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = postgres_maintenance
SPEC.loader.exec_module(postgres_maintenance)


class PostgresMaintenanceTests(unittest.TestCase):
    def test_command_builders_keep_database_name_safe(self) -> None:
        backup = postgres_maintenance.backup_command()
        self.assertIn('pg_dump -Fc --no-owner --no-privileges', backup[-1])
        restore = postgres_maintenance.restore_command(target_db="email_platform_restore")
        self.assertIn('pg_restore --clean --if-exists', restore[-1])
        self.assertIn('"email_platform_restore"', restore[-1])
        with self.assertRaises(ValueError):
            postgres_maintenance.restore_command(target_db="bad-name;rm -rf")

    def test_backup_and_restore_use_subprocess_with_expected_commands(self) -> None:
        calls: list[list[str]] = []

        def fake_run(command, check, stdout=None, stdin=None):
            calls.append(list(command))
            if stdout is not None:
                stdout.write(b"custom-backup")
            if stdin is not None:
                self.assertEqual(stdin.read(), b"custom-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            backup_path = Path(temp_dir) / "snapshot.dump"
            with mock.patch("subprocess.run", side_effect=fake_run):
                result = postgres_maintenance.run_backup(backup_path)
                self.assertEqual(result.size_bytes, len(b"custom-backup"))
                postgres_maintenance.run_restore(
                    backup_path, target_db="email_platform_restore"
                )

        self.assertEqual(len(calls), 2)
        self.assertIn("pg_dump", " ".join(calls[0]))
        self.assertIn("pg_restore", " ".join(calls[1]))

    def test_drill_creates_and_cleans_scratch_database(self) -> None:
        calls: list[list[str]] = []

        def fake_run(command, check, stdout=None, stdin=None):
            calls.append(list(command))
            if stdout is not None:
                stdout.write(b"snapshot")
            if stdin is not None:
                self.assertEqual(stdin.read(), b"snapshot")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            backup_path = Path(temp_dir) / "drill.dump"
            with mock.patch("subprocess.run", side_effect=fake_run):
                result, scratch_db = postgres_maintenance.run_drill(
                    backup_path, scratch_db="email_platform_restore_drill"
                )

        self.assertEqual(scratch_db, "email_platform_restore_drill")
        self.assertEqual(result.path, backup_path)
        rendered = [" ".join(command) for command in calls]
        self.assertTrue(any("createdb" in line for line in rendered))
        self.assertTrue(any("pg_restore" in line for line in rendered))
        self.assertTrue(any("psql" in line for line in rendered))
        self.assertTrue(any("dropdb" in line for line in rendered))


if __name__ == "__main__":
    unittest.main()
