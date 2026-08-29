import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from scripts import audit_archive
from scripts import backup_output_policy
from scripts import postgres_maintenance
from scripts import redis_maintenance
from scripts import vault_maintenance
from scripts.verify_backup_tools import audit_archive_contract_errors


class BundleRollbackDiagnosticsTests(unittest.TestCase):
    def test_claim_identity_rejects_replaced_ordinary_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            claim = backup_output_policy.create_write_once_directory(root / "bundle")
            original = root / "original-claim"
            claim.path.rename(original)
            claim.path.mkdir()
            sentinel = claim.path / "operator-owned.txt"
            sentinel.write_text("keep", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "replaced backup output directory"):
                backup_output_policy.cleanup_created_directory(claim)

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")
            self.assertTrue(original.is_dir())

    def test_failed_cleanup_preserves_primary_and_uses_fixed_note(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            claim = backup_output_policy.create_write_once_directory(
                Path(temp_dir) / "bundle"
            )
            primary = RuntimeError("PRIMARY_PATH_SECRET")
            with mock.patch.object(
                backup_output_policy,
                "cleanup_created_directory",
                side_effect=PermissionError("CLEANUP_PATH_SECRET"),
            ):
                cleaned = backup_output_policy.cleanup_created_directory_after_failure(
                    claim, primary
                )

            self.assertFalse(cleaned)
            self.assertEqual(
                primary.__notes__,
                [backup_output_policy.CLEANUP_UNCONFIRMED_NOTE],
            )
            self.assertNotIn("CLEANUP_PATH_SECRET", " ".join(primary.__notes__))
            self.assertTrue(claim.path.is_dir())

    def test_missing_claim_is_already_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            claim = backup_output_policy.create_write_once_directory(
                Path(temp_dir) / "bundle"
            )
            claim.path.rmdir()
            backup_output_policy.cleanup_created_directory(claim)

    def test_claimed_temporary_cleanup_cannot_replace_primary_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temporary = Path(temp_dir) / ".artifact.tmp"
            temporary.write_bytes(b"partial")
            with mock.patch.object(
                backup_output_policy.Path,
                "unlink",
                side_effect=PermissionError("LOCAL_CLEANUP_PATH_SECRET"),
            ):
                backup_output_policy.discard_claimed_temporary_file(temporary)
            self.assertTrue(temporary.exists())

    def test_outer_owners_preserve_primary_when_recursive_cleanup_fails(self) -> None:
        primary = RuntimeError("PRIMARY_FAILURE_SECRET")
        start = datetime(2026, 8, 27, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 8, 27, 1, 0, tzinfo=timezone.utc)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cases = (
                (
                    "postgres",
                    root / "postgres",
                    mock.patch.multiple(
                        postgres_maintenance,
                        _validate_production_docker_environment=mock.DEFAULT,
                        load_key_file=mock.Mock(return_value=b"k" * 32),
                    ),
                    mock.patch.object(
                        postgres_maintenance,
                        "backup_database",
                        side_effect=primary,
                    ),
                    lambda output: postgres_maintenance.backup_bundle(
                        output,
                        key_file=root / "key",
                        platform_db="platform",
                        keycloak_db="keycloak",
                    ),
                ),
                (
                    "vault",
                    root / "vault",
                    mock.patch.object(
                        vault_maintenance,
                        "_snapshot_binding_inputs",
                        side_effect=primary,
                    ),
                    mock.patch.object(vault_maintenance, "_snapshot_request_inputs"),
                    lambda output: vault_maintenance.create_snapshot(
                        output,
                        address="https://vault.example",
                        token_file=root / "token",
                        manifest_key_file=root / "key",
                        recovery_set="r1",
                        postgres_manifest=root / "manifest",
                        ca_file=root / "ca",
                    ),
                ),
                (
                    "audit",
                    root / "audit",
                    mock.patch.object(
                        audit_archive,
                        "_archive_events_in_claimed_directory",
                        side_effect=primary,
                    ),
                    mock.patch.object(audit_archive, "load_key_file"),
                    lambda output: audit_archive.archive_events(
                        output,
                        engine=mock.Mock(),
                        key_file=root / "key",
                        tenant_id="tenant",
                        created_from=start,
                        created_to=end,
                        tool_source_commit="a" * 40,
                    ),
                ),
            )
            for label, output, first_patch, second_patch, operation in cases:
                primary.__notes__ = []
                with self.subTest(owner=label), first_patch, second_patch, mock.patch.object(
                    backup_output_policy,
                    "cleanup_created_directory",
                    side_effect=PermissionError("SECONDARY_CLEANUP_SECRET"),
                ):
                    with self.assertRaises(RuntimeError) as raised:
                        operation(output)
                self.assertIs(raised.exception, primary)
                self.assertEqual(
                    primary.__notes__,
                    [backup_output_policy.CLEANUP_UNCONFIRMED_NOTE],
                )
                self.assertTrue(output.is_dir())

    def test_maintenance_cli_failures_are_fixed_and_redacted(self) -> None:
        cases = (
            (
                "postgres",
                postgres_maintenance,
                "backup_bundle",
                [
                    "backup-bundle",
                    "--output-dir", "OUTPUT_PATH_SECRET",
                    "--key-file", "KEY_PATH_SECRET",
                    "--platform-db", "platform",
                    "--keycloak-db", "keycloak",
                ],
                "postgres-maintenance-error: backup-bundle failed\n",
            ),
            (
                "redis",
                redis_maintenance,
                "backup_release",
                [
                    "backup-release",
                    "--output-dir", "OUTPUT_PATH_SECRET",
                    "--key-file", "KEY_PATH_SECRET",
                    "--release-tag", "v1.0.0",
                    "--release-commit", "a" * 40,
                    "--migration-head", "0001_initial",
                    "--container-manifest-sha256", "b" * 64,
                    "--postgres-manifest", "POSTGRES_PATH_SECRET",
                    "--recovery-set", "r1",
                ],
                "redis-maintenance-error: backup-release failed\n",
            ),
            (
                "vault",
                vault_maintenance,
                "create_snapshot",
                [
                    "backup",
                    "--output-dir", "OUTPUT_PATH_SECRET",
                    "--address", "https://vault.example",
                    "--token-file", "TOKEN_PATH_SECRET",
                    "--manifest-key-file", "KEY_PATH_SECRET",
                    "--recovery-set", "r1",
                    "--postgres-manifest", "POSTGRES_PATH_SECRET",
                    "--ca-file", "CA_PATH_SECRET",
                ],
                "vault-maintenance-error: backup failed\n",
            ),
        )
        for label, module, operation_name, argv, expected in cases:
            for cleanup_unconfirmed in (False, True):
                error = RuntimeError("RAW_EXCEPTION_AND_PATH_SECRET")
                if cleanup_unconfirmed:
                    error.add_note(backup_output_policy.CLEANUP_UNCONFIRMED_NOTE)
                stdout = io.StringIO()
                stderr = io.StringIO()
                with self.subTest(
                    tool=label,
                    cleanup_unconfirmed=cleanup_unconfirmed,
                ), mock.patch.object(
                    module, operation_name, side_effect=error
                ), redirect_stdout(stdout), redirect_stderr(stderr):
                    result = module.main(argv)
                rendered_expected = expected
                if cleanup_unconfirmed:
                    rendered_expected = (
                        expected.rstrip("\n")
                        + "; "
                        + backup_output_policy.CLEANUP_UNCONFIRMED_NOTE
                        + "\n"
                    )
                self.assertEqual(result, 1)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), rendered_expected)
                rendered = stdout.getvalue() + stderr.getvalue()
                self.assertNotIn("SECRET", rendered)

    def test_redis_cli_restart_failure_is_fixed_and_redacted(self) -> None:
        error = redis_maintenance.RedisBackupFatalError("INTERNAL_RESTART_SECRET")
        error.add_note(backup_output_policy.CLEANUP_UNCONFIRMED_NOTE)
        stdout = io.StringIO()
        stderr = io.StringIO()
        argv = [
            "backup-release",
            "--output-dir", "OUTPUT_PATH_SECRET",
            "--key-file", "KEY_PATH_SECRET",
            "--release-tag", "v1.0.0",
            "--release-commit", "a" * 40,
            "--migration-head", "0001_initial",
            "--container-manifest-sha256", "b" * 64,
            "--postgres-manifest", "POSTGRES_PATH_SECRET",
            "--recovery-set", "r1",
        ]
        with mock.patch.object(
            redis_maintenance,
            "backup_release",
            side_effect=error,
        ), redirect_stdout(stdout), redirect_stderr(stderr):
            result = redis_maintenance.main(argv)
        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            "redis-maintenance-error: Redis restart could not be confirmed; "
            "backup output cleanup could not be confirmed\n",
        )
        self.assertNotIn("SECRET", stderr.getvalue())

    def test_cli_does_not_swallow_process_control_exceptions(self) -> None:
        with mock.patch.object(
            postgres_maintenance,
            "backup_bundle",
            side_effect=KeyboardInterrupt,
        ), self.assertRaises(KeyboardInterrupt):
            postgres_maintenance.main(
                [
                    "backup-bundle",
                    "--output-dir", "output",
                    "--key-file", "key",
                    "--platform-db", "platform",
                    "--keycloak-db", "keycloak",
                ]
            )

    def test_all_verifiers_reject_extra_leaf_before_sensitive_processing(self) -> None:
        start = datetime(2026, 8, 27, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 8, 27, 1, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            postgres_dir = root / "postgres"
            postgres_dir.mkdir()
            for name in postgres_maintenance.BACKUP_BUNDLE_LEAVES:
                (postgres_dir / name).write_bytes(b"placeholder")
            (postgres_dir / ".operator.tmp").write_bytes(b"extra")
            with mock.patch.object(
                postgres_maintenance,
                "load_key_file",
                side_effect=AssertionError("secret access reached"),
            ) as secret, self.assertRaisesRegex(ValueError, "leaf set"):
                postgres_maintenance.verify_bundle(postgres_dir, key_file=root / "key")
            secret.assert_not_called()

            redis_dir = root / "redis"
            redis_dir.mkdir()
            for name in redis_maintenance.BACKUP_BUNDLE_LEAVES:
                (redis_dir / name).write_bytes(b"placeholder")
            (redis_dir / ".operator.tmp").write_bytes(b"extra")
            with mock.patch.object(
                redis_maintenance,
                "load_key_file",
                side_effect=AssertionError("secret access reached"),
            ) as secret, self.assertRaisesRegex(ValueError, "leaf set"):
                redis_maintenance.verify_release_backup(
                    redis_dir,
                    key_file=root / "key",
                    release_tag="v1.0.0",
                    release_commit="a" * 40,
                    migration_head="0001_initial",
                    container_manifest_sha256="b" * 64,
                    postgres_manifest_sha256="c" * 64,
                    recovery_set="r1",
                )
            secret.assert_not_called()

            vault_dir = root / "vault"
            vault_dir.mkdir()
            for name in vault_maintenance.BACKUP_BUNDLE_LEAVES:
                (vault_dir / name).write_bytes(b"placeholder")
            (vault_dir / ".operator.tmp").write_bytes(b"extra")
            with mock.patch.object(
                vault_maintenance,
                "_snapshot_binding_inputs",
                side_effect=AssertionError("secret access reached"),
            ) as secret, self.assertRaisesRegex(ValueError, "leaf set"):
                vault_maintenance.verify_snapshot(
                    vault_dir,
                    manifest_key_file=root / "key",
                    recovery_set="r1",
                    postgres_manifest=root / "manifest",
                )
            secret.assert_not_called()

            audit_dir = root / "audit"
            audit_dir.mkdir()
            for name in (audit_archive.ARTIFACT_NAME, audit_archive.MANIFEST_NAME):
                (audit_dir / name).write_bytes(b"placeholder")
            (audit_dir / ".operator.tmp").write_bytes(b"extra")
            with mock.patch.object(
                audit_archive,
                "_read_manifest",
                side_effect=AssertionError("manifest processing reached"),
            ) as manifest, self.assertRaisesRegex(
                audit_archive.AuditArchiveError, "leaf set"
            ):
                audit_archive.verify_archive(
                    audit_dir,
                    key_file=root / "key",
                    expected_tenant_id="tenant",
                    expected_created_from=start,
                    expected_created_to=end,
                )
            manifest.assert_not_called()

    def test_audit_exact_leaf_mutation_is_rejected(self) -> None:
        source = Path(audit_archive.__file__).read_text(encoding="utf-8")
        changed = source.replace(
            "        identities = require_exact_regular_files(\n"
            "            directory,\n"
            "            frozenset({ARTIFACT_NAME, MANIFEST_NAME}),\n"
            "        )",
            "        pass",
            1,
        )
        self.assertNotEqual(changed, source)
        self.assertTrue(
            audit_archive_contract_errors(
                audit_archive,
                changed,
                backup_output_policy,
            )
        )
        identity_mutations = (
            source.replace(
                "expected_identity=identities[MANIFEST_NAME]",
                "expected_identity=None",
                1,
            ),
            source.replace(
                "expected_identity=identities[ARTIFACT_NAME]",
                "expected_identity=None",
                1,
            ),
            source.replace(
                "    if require_exact_regular_files(\n"
                "        directory,\n"
                "        frozenset({ARTIFACT_NAME, MANIFEST_NAME}),\n"
                "    ) != identities:\n"
                "        raise AuditArchiveError(\"archive directory changed during verification\")\n",
                "",
                1,
            ),
        )
        for changed in identity_mutations:
            with self.subTest(contract="audit stable leaf identity"):
                self.assertNotEqual(changed, source)
                self.assertTrue(
                    audit_archive_contract_errors(
                        audit_archive,
                        changed,
                        backup_output_policy,
                    )
                )


if __name__ == "__main__":
    unittest.main()
