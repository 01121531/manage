import importlib.util
import json
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


RELEASE_BINDING = {
    "release_tag": "v1.2.3",
    "release_commit": "a" * 40,
    "migration_head": "0014_audit_evidence_fields",
    "container_manifest_sha256": "b" * 64,
}


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

        def fake_run(command, check, stdout=None, stdin=None, **kwargs):
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

        def fake_run(command, check, stdout=None, stdin=None, **kwargs):
            calls.append(list(command))
            if stdout is not None:
                stdout.write(b"snapshot")
            if stdin is not None:
                self.assertEqual(stdin.read(), b"snapshot")
            return subprocess.CompletedProcess(command, 0, stdout="3\n")

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

    def test_bundle_contains_and_verifies_both_databases(self) -> None:
        calls: list[list[str]] = []

        def fake_run(command, check, stdout=None, stdin=None, **kwargs):
            calls.append(list(command))
            rendered = " ".join(command)
            if stdout is not None:
                payload = b"keycloak-backup" if '"keycloak"' in rendered else b"platform-backup"
                stdout.write(payload)
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=fake_run):
                result = postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                )

            verified = postgres_maintenance.verify_bundle(bundle_dir)
            self.assertEqual(set(verified), {"platform", "keycloak"})
            self.assertEqual(verified["platform"]["database"], "email_platform")
            self.assertEqual(verified["keycloak"]["database"], "keycloak")
            self.assertTrue(result.manifest_path.exists())

            (bundle_dir / "keycloak.dump").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "size mismatch|hash mismatch"):
                postgres_maintenance.verify_bundle(bundle_dir)

        dumps = [" ".join(command) for command in calls if "pg_dump" in " ".join(command)]
        self.assertEqual(len(dumps), 2)
        self.assertTrue(any('"email_platform"' in command for command in dumps))
        self.assertTrue(any('"keycloak"' in command for command in dumps))

    def test_release_bound_bundle_uses_schema_v2_and_verifies_binding(self) -> None:
        def fake_run(command, check, stdout=None, **kwargs):
            if stdout is not None:
                stdout.write(b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=fake_run):
                postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                    **RELEASE_BINDING,
                )

            manifest = json.loads(
                (bundle_dir / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["schema_version"], 2)
            for field, expected in RELEASE_BINDING.items():
                self.assertEqual(manifest[field], expected)
            self.assertEqual(
                postgres_maintenance.verify_bundle_release_binding(
                    bundle_dir, **RELEASE_BINDING
                ),
                RELEASE_BINDING,
            )

    def test_release_binding_requires_all_fields_before_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch("subprocess.run") as run:
                with self.assertRaisesRegex(
                    ValueError, "release binding requires all four fields"
                ):
                    postgres_maintenance.backup_bundle(
                        Path(temp_dir) / "bundle",
                        platform_db="email_platform",
                        keycloak_db="keycloak",
                        release_tag=RELEASE_BINDING["release_tag"],
                    )
                run.assert_not_called()

    def test_verify_rejects_incomplete_or_malformed_v2_binding(self) -> None:
        def fake_run(command, check, stdout=None, **kwargs):
            if stdout is not None:
                stdout.write(b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            manifest_path = bundle_dir / "manifest.json"
            with mock.patch("subprocess.run", side_effect=fake_run):
                postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                    **RELEASE_BINDING,
                )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest.pop("migration_head")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "requires all release binding fields"):
                postgres_maintenance.verify_bundle(bundle_dir)

            manifest["migration_head"] = RELEASE_BINDING["migration_head"]
            manifest["release_commit"] = "not-a-commit"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid release commit"):
                postgres_maintenance.verify_bundle(bundle_dir)

    def test_release_binding_check_rejects_v1_and_mismatch(self) -> None:
        def fake_run(command, check, stdout=None, **kwargs):
            if stdout is not None:
                stdout.write(b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            legacy = root / "legacy"
            bound = root / "bound"
            with mock.patch("subprocess.run", side_effect=fake_run):
                postgres_maintenance.backup_bundle(
                    legacy,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                )
                postgres_maintenance.backup_bundle(
                    bound,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                    **RELEASE_BINDING,
                )

            self.assertEqual(
                set(postgres_maintenance.verify_bundle(legacy)),
                {"platform", "keycloak"},
            )
            with self.assertRaisesRegex(ValueError, "not release-bound"):
                postgres_maintenance.verify_bundle_release_binding(
                    legacy, **RELEASE_BINDING
                )
            mismatched = dict(RELEASE_BINDING)
            mismatched["release_tag"] = "v1.2.4"
            with self.assertRaisesRegex(ValueError, "release binding mismatch: release_tag"):
                postgres_maintenance.verify_bundle_release_binding(
                    bound, **mismatched
                )

    def test_bundle_manifest_rejects_unknown_fields_and_naive_timestamp(self) -> None:
        def fake_run(command, check, stdout=None, **kwargs):
            if stdout is not None:
                stdout.write(b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=fake_run):
                postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                    **RELEASE_BINDING,
                )
            manifest_path = bundle_dir / "manifest.json"
            original = json.loads(manifest_path.read_text(encoding="utf-8"))

            tampered = dict(original)
            tampered["notes"] = "not part of the closed evidence schema"
            manifest_path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unexpected fields"):
                postgres_maintenance.verify_bundle(bundle_dir)

            tampered = json.loads(json.dumps(original))
            tampered["databases"]["platform"]["notes"] = "unexpected"
            manifest_path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unexpected manifest entry fields"):
                postgres_maintenance.verify_bundle(bundle_dir)

            tampered = dict(original)
            tampered["created_at"] = "2026-08-20T12:00:00"
            manifest_path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "creation time"):
                postgres_maintenance.verify_bundle(bundle_dir)

    def test_restore_bundle_verifies_integrity_before_restoring_both_databases(self) -> None:
        calls: list[list[str]] = []

        def fake_run(command, check, stdout=None, stdin=None, **kwargs):
            calls.append(list(command))
            if stdout is not None:
                stdout.write(b"database-backup")
            if stdin is not None:
                self.assertEqual(stdin.read(), b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=fake_run):
                postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                )
                postgres_maintenance.restore_bundle(
                    bundle_dir,
                    platform_target_db="email_platform_restore",
                    keycloak_target_db="keycloak_restore",
                )

        restores = [
            " ".join(command) for command in calls if "pg_restore" in " ".join(command)
        ]
        self.assertEqual(len(restores), 2)
        self.assertTrue(any('"email_platform_restore"' in command for command in restores))
        self.assertTrue(any('"keycloak_restore"' in command for command in restores))

    def test_release_bound_restore_rechecks_binding_before_each_database(self) -> None:
        def fake_run(command, check, stdout=None, stdin=None, **kwargs):
            if stdout is not None:
                stdout.write(b"database-backup")
            if stdin is not None:
                self.assertEqual(stdin.read(), b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=fake_run):
                postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                    **RELEASE_BINDING,
                )
                with mock.patch.object(
                    postgres_maintenance,
                    "verify_bundle_release_binding",
                    wraps=postgres_maintenance.verify_bundle_release_binding,
                ) as verify_binding:
                    postgres_maintenance.restore_bundle(
                        bundle_dir,
                        platform_target_db="email_platform_restore",
                        keycloak_target_db="keycloak_restore",
                        **RELEASE_BINDING,
                    )
            self.assertEqual(verify_binding.call_count, 2)

    def test_release_bound_restore_rejects_mismatch_before_restore(self) -> None:
        def fake_backup(command, check, stdout=None, **kwargs):
            if stdout is not None:
                stdout.write(b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=fake_backup):
                postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                    **RELEASE_BINDING,
                )
            mismatched = dict(RELEASE_BINDING)
            mismatched["container_manifest_sha256"] = "c" * 64
            with mock.patch("subprocess.run") as run:
                with self.assertRaisesRegex(
                    ValueError,
                    "release binding mismatch: container_manifest_sha256",
                ):
                    postgres_maintenance.restore_bundle(
                        bundle_dir,
                        platform_target_db="email_platform_restore",
                        keycloak_target_db="keycloak_restore",
                        **mismatched,
                    )
                run.assert_not_called()
            with mock.patch("subprocess.run") as run:
                with self.assertRaisesRegex(
                    ValueError, "release binding requires all four fields"
                ):
                    postgres_maintenance.restore_bundle(
                        bundle_dir,
                        platform_target_db="email_platform_restore",
                        keycloak_target_db="keycloak_restore",
                        release_tag=RELEASE_BINDING["release_tag"],
                    )
                run.assert_not_called()

    def test_bundle_cli_parses_release_binding_for_generation_and_restore(self) -> None:
        parser = postgres_maintenance.build_parser()
        flags = [
            "--release-tag",
            RELEASE_BINDING["release_tag"],
            "--release-commit",
            RELEASE_BINDING["release_commit"],
            "--migration-head",
            RELEASE_BINDING["migration_head"],
            "--container-manifest-sha256",
            RELEASE_BINDING["container_manifest_sha256"],
        ]
        for command in ("backup-bundle", "drill-bundle", "restore-bundle"):
            directory_flag = (
                "--input-dir" if command == "restore-bundle" else "--output-dir"
            )
            args = parser.parse_args([command, directory_flag, "bundle", *flags])
            for field, expected in RELEASE_BINDING.items():
                self.assertEqual(getattr(args, field), expected)

    def test_failed_bundle_refresh_invalidates_old_manifest(self) -> None:
        call_count = 0

        def successful_run(command, check, stdout=None, **kwargs):
            if stdout is not None:
                stdout.write(b"database-backup")
            return subprocess.CompletedProcess(command, 0)

        def failing_run(command, check, stdout=None, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise subprocess.CalledProcessError(1, command)
            if stdout is not None:
                stdout.write(b"replacement-backup")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            bundle_dir = Path(temp_dir) / "bundle"
            with mock.patch("subprocess.run", side_effect=successful_run):
                postgres_maintenance.backup_bundle(
                    bundle_dir,
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                )
            self.assertTrue((bundle_dir / "manifest.json").exists())

            with mock.patch("subprocess.run", side_effect=failing_run):
                with self.assertRaises(subprocess.CalledProcessError):
                    postgres_maintenance.backup_bundle(
                        bundle_dir,
                        platform_db="email_platform",
                        keycloak_db="keycloak",
                    )

            self.assertFalse((bundle_dir / "manifest.json").exists())
            with self.assertRaisesRegex(ValueError, "invalid backup manifest"):
                postgres_maintenance.verify_bundle(bundle_dir)

    def test_bundle_drill_compares_nonzero_source_and_restored_table_counts(self) -> None:
        calls: list[list[str]] = []

        def fake_run(command, check, stdout=None, stdin=None, **kwargs):
            calls.append(list(command))
            rendered = " ".join(command)
            if stdout is not None:
                stdout.write(b"database-backup")
            if "psql" in rendered:
                return subprocess.CompletedProcess(command, 0, stdout="4\n")
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch("subprocess.run", side_effect=fake_run):
                drill = postgres_maintenance.drill_bundle(
                    Path(temp_dir) / "bundle",
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                    platform_scratch_db="email_platform_restore_drill",
                    keycloak_scratch_db="keycloak_restore_drill",
                    **RELEASE_BINDING,
                )
            manifest = json.loads(
                drill.bundle.manifest_path.read_text(encoding="utf-8")
            )

        self.assertEqual(manifest["schema_version"], 2)
        self.assertEqual(manifest["release_tag"], RELEASE_BINDING["release_tag"])
        self.assertEqual(
            set(drill.critical_row_counts["platform"]),
            {"users", "devices", "audit_events"},
        )
        self.assertEqual(
            set(drill.critical_row_counts["keycloak"]),
            {"realm", "user_entity", "credential"},
        )
        self.assertEqual(
            drill.critical_row_counts["keycloak"]["credential"],
            {"source": 4, "restored": 4},
        )

        rendered = [" ".join(command) for command in calls]
        self.assertEqual(sum("pg_dump" in line for line in rendered), 2)
        self.assertEqual(sum("pg_restore" in line for line in rendered), 2)
        self.assertEqual(sum("createdb" in line for line in rendered), 2)
        self.assertEqual(sum("dropdb" in line for line in rendered), 2)
        self.assertEqual(sum("psql" in line for line in rendered), 16)

    def test_bundle_drill_rejects_critical_row_count_mismatch(self) -> None:
        def fake_run(command, check, stdout=None, stdin=None, **kwargs):
            rendered = " ".join(command)
            if stdout is not None:
                stdout.write(b"database-backup")
            if "psql" in rendered:
                row_count = "5\n"
                if (
                    'keycloak_restore_drill' in rendered
                    and 'public."credential"' in rendered
                ):
                    row_count = "4\n"
                return subprocess.CompletedProcess(command, 0, stdout=row_count)
            return subprocess.CompletedProcess(command, 0)

        with tempfile.TemporaryDirectory() as temp_dir:
            with mock.patch("subprocess.run", side_effect=fake_run):
                with self.assertRaisesRegex(
                    ValueError,
                    r"restored row count mismatch: keycloak\.credential source=5 restored=4",
                ):
                    postgres_maintenance.drill_bundle(
                        Path(temp_dir) / "bundle",
                        platform_db="email_platform",
                        keycloak_db="keycloak",
                        platform_scratch_db="email_platform_restore_drill",
                        keycloak_scratch_db="keycloak_restore_drill",
                    )

    def test_critical_row_count_rejects_unknown_table_and_invalid_output(self) -> None:
        with self.assertRaisesRegex(ValueError, "disaster-recovery whitelist"):
            postgres_maintenance.count_rows_command(
                target_db="email_platform",
                table="unreviewed_table",
            )
        with mock.patch(
            "subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, stdout="not-an-integer\n"),
        ):
            with self.assertRaisesRegex(ValueError, "invalid row count"):
                postgres_maintenance.count_rows(
                    target_db="email_platform",
                    table="users",
                )

    def test_table_count_rejects_empty_database(self) -> None:
        with mock.patch(
            "subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, stdout="0\n"),
        ):
            with self.assertRaisesRegex(ValueError, "no public tables"):
                postgres_maintenance.count_tables(target_db="empty_restore")


if __name__ == "__main__":
    unittest.main()
