import inspect
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import audit_archive
from scripts import backup_output_policy
from scripts import deploy_release_evidence
from scripts import phase6_rehearsal
from scripts import postgres_maintenance
from scripts import redis_maintenance
from scripts import rollback_release_evidence
from scripts import rolling_release_evidence
from scripts import training_evidence
from scripts import vault_maintenance


class _SuccessfulProcess:
    def __init__(self) -> None:
        self.stdout = io.BytesIO(b"plaintext-backup")

    def wait(self) -> int:
        return 0

    def kill(self) -> None:
        pass


class BundleCommitCleanupBoundaryTests(unittest.TestCase):
    def test_standalone_commit_remains_successful_when_private_name_cleanup_fails(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            temporary = root / ".evidence.json.private.tmp"
            output = root / "evidence.json"
            temporary.write_bytes(b"committed-evidence")
            with mock.patch.object(
                backup_output_policy.Path,
                "unlink",
                side_effect=PermissionError("cleanup-failed"),
            ):
                backup_output_policy.publish_write_once_file(temporary, output)

            self.assertEqual(output.read_bytes(), b"committed-evidence")
            self.assertTrue(temporary.exists())
            self.assertTrue(temporary.samefile(output))

    def test_bundle_commit_reports_private_name_cleanup_failure(self) -> None:
        publisher = getattr(
            backup_output_policy,
            "publish_bundle_write_once_file",
            None,
        )
        self.assertTrue(callable(publisher))
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            temporary = root / ".artifact.private.tmp"
            output = root / "artifact.enc"
            temporary.write_bytes(b"encrypted-artifact")
            with (
                mock.patch.object(
                    backup_output_policy.Path,
                    "unlink",
                    side_effect=PermissionError("cleanup-failed"),
                ),
                self.assertRaisesRegex(PermissionError, "cleanup-failed"),
            ):
                publisher(temporary, output)

            self.assertEqual(output.read_bytes(), b"encrypted-artifact")
            self.assertTrue(temporary.exists())
            self.assertTrue(temporary.samefile(output))

    def test_claimed_bundle_rolls_back_after_committed_cleanup_failure(self) -> None:
        def backup_result(path: Path, *, logical_name: str, **_kwargs):
            path.write_bytes(f"encrypted-{logical_name}".encode("ascii"))
            return postgres_maintenance.BackupResult(
                path=path,
                sha256=("1" if logical_name == "platform" else "2") * 64,
                size_bytes=18,
                key_id=f"key-{logical_name}",
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "postgres-bundle"
            with (
                mock.patch.object(
                    postgres_maintenance,
                    "_validate_production_docker_environment",
                ),
                mock.patch.object(
                    postgres_maintenance,
                    "load_key_file",
                    return_value=b"k" * 32,
                ),
                mock.patch.object(
                    postgres_maintenance,
                    "backup_database",
                    side_effect=backup_result,
                ),
                mock.patch.object(
                    backup_output_policy.Path,
                    "unlink",
                    side_effect=PermissionError("cleanup-failed"),
                ),
                self.assertRaisesRegex(PermissionError, "cleanup-failed"),
            ):
                postgres_maintenance.backup_bundle(
                    output,
                    key_file=Path(temp_dir) / "unused.key",
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                )

            self.assertFalse(output.exists())

    def test_artifact_commit_error_is_primary_and_rolls_back_the_bundle(self) -> None:
        def encrypt(_source, destination, _key, **_kwargs) -> None:
            destination.write(b"encrypted-backup")

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "postgres-bundle"
            with (
                mock.patch.object(
                    postgres_maintenance,
                    "_validate_production_docker_environment",
                ),
                mock.patch.object(
                    postgres_maintenance,
                    "load_key_file",
                    return_value=b"k" * 32,
                ),
                mock.patch.object(
                    postgres_maintenance,
                    "backup_command",
                    return_value=["pg_dump"],
                ),
                mock.patch.object(
                    postgres_maintenance.subprocess,
                    "Popen",
                    return_value=_SuccessfulProcess(),
                ),
                mock.patch.object(
                    postgres_maintenance,
                    "encrypt_stream",
                    side_effect=encrypt,
                ),
                mock.patch.object(
                    backup_output_policy.Path,
                    "unlink",
                    side_effect=(
                        PermissionError("commit-cleanup-failed"),
                        PermissionError("secondary-cleanup-failed"),
                    ),
                ) as unlink,
                self.assertRaisesRegex(PermissionError, "commit-cleanup-failed"),
            ):
                postgres_maintenance.backup_bundle(
                    output,
                    key_file=Path(temp_dir) / "unused.key",
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                )

            self.assertEqual(unlink.call_count, 1)
            self.assertFalse(output.exists())

    def test_only_claimed_bundle_writers_use_the_strict_publisher(self) -> None:
        strict_call = "publish_bundle_write_once_file("
        postgres_database = inspect.getsource(postgres_maintenance.backup_database)
        postgres_bundle = inspect.getsource(postgres_maintenance.backup_bundle)
        redis_archive = inspect.getsource(redis_maintenance._write_encrypted_archive)
        redis_bundle = inspect.getsource(redis_maintenance.backup_release)
        vault_bundle = inspect.getsource(vault_maintenance.create_snapshot)
        audit_bundle = inspect.getsource(
            audit_archive._archive_events_in_claimed_directory
        )

        self.assertIn("_bundle_owned", postgres_database)
        self.assertIn(strict_call, postgres_database)
        self.assertIn("_bundle_owned=True", postgres_bundle)
        self.assertIn(strict_call, postgres_bundle)
        self.assertIn(strict_call, redis_archive)
        self.assertIn(strict_call, redis_bundle)
        self.assertEqual(vault_bundle.count(strict_call), 2)
        self.assertEqual(audit_bundle.count(strict_call), 2)

        for module, writer in (
            (phase6_rehearsal, phase6_rehearsal.write_evidence),
            (
                deploy_release_evidence,
                deploy_release_evidence.DeploymentReleaseEvidenceRecorder.write,
            ),
            (
                rollback_release_evidence,
                rollback_release_evidence.RollbackReleaseEvidenceRecorder.write,
            ),
            (
                rolling_release_evidence,
                rolling_release_evidence.RollingReleaseEvidenceRecorder.write,
            ),
            (training_evidence, training_evidence._write_evidence),
        ):
            with self.subTest(module=module.__name__):
                source = inspect.getsource(writer)
                self.assertIn("publish_write_once_file(", source)
                self.assertNotIn(strict_call, source)


if __name__ == "__main__":
    unittest.main()
