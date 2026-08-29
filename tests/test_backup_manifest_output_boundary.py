import inspect
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from scripts import backup_output_policy
from scripts import postgres_maintenance
from scripts import redis_maintenance
from scripts import vault_maintenance


FIXED_TIME = datetime(2026, 8, 27, 12, 0, tzinfo=timezone.utc)
RELEASE = {
    "release_tag": "v1.2.3",
    "release_commit": "a" * 40,
    "migration_head": "0028_access_token_revocations",
    "container_manifest_sha256": "b" * 64,
}


class _FixedDatetime:
    @classmethod
    def now(cls, zone):
        if zone is not timezone.utc:
            raise AssertionError("UTC timestamp required")
        return FIXED_TIME


class BackupManifestOutputBoundaryTests(unittest.TestCase):
    @staticmethod
    def _stage_to_known_file(path: Path, raw: bytes) -> Path:
        temporary = path.parent / ".captured-manifest.tmp"
        temporary.write_bytes(raw)
        return temporary

    @staticmethod
    def _postgres_result(path: Path, *, logical_name: str, **_kwargs):
        marker = "1" if logical_name == "platform" else "2"
        return postgres_maintenance.BackupResult(
            path=path,
            sha256=marker * 64,
            size_bytes=17,
            key_id=f"key-{logical_name}",
        )

    @staticmethod
    def _vault_patches(root: Path, payload: dict[str, object]):
        def download(path: Path, **_kwargs) -> None:
            path.write_bytes(b"raft-snapshot")

        return (
            mock.patch.object(
                vault_maintenance,
                "_snapshot_binding_inputs",
                return_value=("release-v1.2.3", "c" * 64, b"m" * 32),
            ),
            mock.patch.object(
                vault_maintenance,
                "_snapshot_request_inputs",
                return_value=("https://vault.invalid", "token", root / "ca.pem", None),
            ),
            mock.patch.object(vault_maintenance, "_download_snapshot", side_effect=download),
            mock.patch.object(vault_maintenance, "_inspect_snapshot"),
            mock.patch.object(vault_maintenance, "_manifest_payload", return_value=payload),
        )

    def test_shared_stager_uses_unique_same_directory_fsynced_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "manifest.json"
            with mock.patch.object(
                backup_output_policy.os,
                "fsync",
                wraps=os.fsync,
            ) as fsync:
                first = backup_output_policy.write_fsynced_temporary_bytes(
                    output, b"first"
                )
                second = backup_output_policy.write_fsynced_temporary_bytes(
                    output, b"second"
                )

            self.assertNotEqual(first, second)
            self.assertEqual((first.parent, second.parent), (root, root))
            self.assertEqual((first.read_bytes(), second.read_bytes()), (b"first", b"second"))
            self.assertEqual(fsync.call_count, 2)

    def test_shared_stager_cleans_partial_file_when_fsync_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with mock.patch.object(
                backup_output_policy.os,
                "fsync",
                side_effect=OSError("fsync-private-detail"),
            ), self.assertRaisesRegex(OSError, "fsync-private-detail"):
                backup_output_policy.write_fsynced_temporary_bytes(
                    root / "manifest.json", b"partial"
                )
            self.assertEqual(list(root.iterdir()), [])

    def test_shared_stager_cleanup_failure_does_not_mask_original_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with (
                mock.patch.object(
                    backup_output_policy.os,
                    "fsync",
                    side_effect=OSError("fsync-private-detail"),
                ),
                mock.patch.object(
                    backup_output_policy.Path,
                    "unlink",
                    side_effect=PermissionError("cleanup-private-detail"),
                ),
                self.assertRaisesRegex(OSError, "fsync-private-detail"),
            ):
                backup_output_policy.write_fsynced_temporary_bytes(
                    root / "manifest.json", b"partial"
                )

    def test_vault_manifest_hmac_canonical_bytes_remain_stable(self) -> None:
        payload = {
            "schema_version": 2,
            "created_at": FIXED_TIME.isoformat(),
            "artifact": "vault.snap",
            "size_bytes": 13,
            "sha256": "d" * 64,
            "recovery_set": "release-v1.2.3",
            "postgres_manifest_sha256": "c" * 64,
        }
        self.assertEqual(
            vault_maintenance._manifest_hmac_sha256(payload, b"m" * 32),
            "0d342aa6744158928008a6dae62506f1d028a04b61733f4df92bfd5a6d0050f1",
        )

    def test_postgres_manifest_delegates_exact_release_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "postgres-bundle"
            with (
                mock.patch.object(postgres_maintenance, "_validate_production_docker_environment"),
                mock.patch.object(
                    postgres_maintenance,
                    "backup_database",
                    side_effect=self._postgres_result,
                ),
                mock.patch.object(postgres_maintenance, "load_key_file", return_value=b"k" * 32),
                mock.patch.object(
                    postgres_maintenance,
                    "_manifest_hmac_sha256",
                    return_value="f" * 64,
                ),
                mock.patch.object(postgres_maintenance, "datetime", _FixedDatetime),
                mock.patch.object(
                    postgres_maintenance,
                    "write_fsynced_temporary_bytes",
                    create=True,
                    side_effect=self._stage_to_known_file,
                ) as stage,
                mock.patch.object(
                    postgres_maintenance,
                    "publish_bundle_write_once_file",
                    wraps=backup_output_policy.publish_bundle_write_once_file,
                ) as publish,
            ):
                result = postgres_maintenance.backup_bundle(
                    output,
                    key_file=Path(temp_dir) / "backup.key",
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                    **RELEASE,
                )

            manifest = json.loads(result.manifest_path.read_bytes())
            expected = (
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
            ).encode("utf-8")
            stage.assert_called_once_with(result.manifest_path, expected)
            publish.assert_called_once_with(
                result.manifest_path.parent / ".captured-manifest.tmp",
                result.manifest_path,
            )
            self.assertEqual(result.manifest_path.read_bytes(), expected)
            self.assertEqual(manifest["manifest_hmac_sha256"], "f" * 64)

    def test_postgres_staging_failure_removes_claimed_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "postgres-bundle"
            with (
                mock.patch.object(postgres_maintenance, "_validate_production_docker_environment"),
                mock.patch.object(
                    postgres_maintenance,
                    "load_key_file",
                    return_value=b"k" * 32,
                ),
                mock.patch.object(
                    postgres_maintenance,
                    "backup_database",
                    side_effect=self._postgres_result,
                ),
                mock.patch.object(
                    postgres_maintenance,
                    "write_fsynced_temporary_bytes",
                    create=True,
                    side_effect=OSError("stage-failed"),
                ),
                self.assertRaisesRegex(OSError, "stage-failed"),
            ):
                postgres_maintenance.backup_bundle(
                    output,
                    key_file=Path(temp_dir) / "backup.key",
                    platform_db="email_platform",
                    keycloak_db="keycloak",
                )
            self.assertFalse(output.exists())

    def test_redis_manifest_keeps_exact_bytes_and_hard_link_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "redis-bundle"

            def write_archive(path: Path, _key: bytes) -> None:
                path.write_bytes(b"encrypted-redis")

            with (
                mock.patch.object(redis_maintenance, "_validate_production_docker_environment"),
                mock.patch.object(redis_maintenance, "_postgres_manifest_sha256", return_value="c" * 64),
                mock.patch.object(redis_maintenance, "load_key_file", return_value=b"r" * 32),
                mock.patch.object(redis_maintenance, "_redis_is_running", return_value=False),
                mock.patch.object(redis_maintenance, "_write_encrypted_archive", side_effect=write_archive),
                mock.patch.object(redis_maintenance, "_hash_file", return_value=("d" * 64, 15)),
                mock.patch.object(redis_maintenance, "_manifest_hmac_sha256", return_value="e" * 64),
                mock.patch.object(redis_maintenance, "datetime", _FixedDatetime),
                mock.patch.object(
                    redis_maintenance,
                    "write_fsynced_temporary_bytes",
                    create=True,
                    side_effect=self._stage_to_known_file,
                ) as stage,
                mock.patch.object(
                    redis_maintenance,
                    "publish_bundle_write_once_file",
                    wraps=backup_output_policy.publish_bundle_write_once_file,
                ) as publish,
            ):
                manifest_path = redis_maintenance.backup_release(
                    output,
                    key_file=Path(temp_dir) / "redis.key",
                    postgres_manifest=Path(temp_dir) / "postgres-manifest.json",
                    recovery_set="release-v1.2.3",
                    **RELEASE,
                )

            manifest = json.loads(manifest_path.read_bytes())
            expected = (
                json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            stage.assert_called_once_with(manifest_path, expected)
            temporary = manifest_path.parent / ".captured-manifest.tmp"
            publish.assert_called_once_with(temporary, manifest_path)
            self.assertEqual(manifest_path.read_bytes(), expected)

    def test_redis_staging_failure_rolls_back_and_restores_running_service(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "redis-bundle"

            def write_archive(path: Path, _key: bytes) -> None:
                path.write_bytes(b"encrypted-redis")

            with (
                mock.patch.object(redis_maintenance, "_validate_production_docker_environment"),
                mock.patch.object(redis_maintenance, "_postgres_manifest_sha256", return_value="c" * 64),
                mock.patch.object(redis_maintenance, "load_key_file", return_value=b"r" * 32),
                mock.patch.object(redis_maintenance, "_redis_is_running", side_effect=(True, False)),
                mock.patch.object(redis_maintenance.subprocess, "run"),
                mock.patch.object(redis_maintenance, "_write_encrypted_archive", side_effect=write_archive),
                mock.patch.object(redis_maintenance, "_hash_file", return_value=("d" * 64, 15)),
                mock.patch.object(redis_maintenance, "_manifest_hmac_sha256", return_value="e" * 64),
                mock.patch.object(
                    redis_maintenance,
                    "write_fsynced_temporary_bytes",
                    create=True,
                    side_effect=OSError("stage-failed"),
                ),
                mock.patch.object(redis_maintenance, "_restore_running_redis_after_backup") as restore,
                self.assertRaisesRegex(OSError, "stage-failed"),
            ):
                redis_maintenance.backup_release(
                    output,
                    key_file=Path(temp_dir) / "redis.key",
                    postgres_manifest=Path(temp_dir) / "postgres-manifest.json",
                    recovery_set="release-v1.2.3",
                    **RELEASE,
                )
            restore.assert_called_once_with()
            self.assertFalse(output.exists())

    def test_vault_manifest_delegates_exact_signed_bytes(self) -> None:
        payload = {
            "schema_version": 2,
            "created_at": FIXED_TIME.isoformat(),
            "artifact": "vault.snap",
            "size_bytes": 13,
            "sha256": "d" * 64,
            "recovery_set": "release-v1.2.3",
            "postgres_manifest_sha256": "c" * 64,
            "manifest_hmac_sha256": "e" * 64,
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "vault-bundle"
            patches = self._vault_patches(root, payload)
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                patches[4],
                mock.patch.object(
                    vault_maintenance,
                    "write_fsynced_temporary_bytes",
                    create=True,
                    side_effect=self._stage_to_known_file,
                ) as stage,
                mock.patch.object(
                    vault_maintenance,
                    "publish_bundle_write_once_file",
                    wraps=backup_output_policy.publish_bundle_write_once_file,
                    create=True,
                ) as publish,
            ):
                manifest_path = vault_maintenance.create_snapshot(
                    output,
                    address="https://vault.invalid",
                    token_file=root / "token",
                    manifest_key_file=root / "manifest.key",
                    recovery_set="release-v1.2.3",
                    postgres_manifest=root / "postgres-manifest.json",
                    ca_file=root / "ca.pem",
                )

            expected = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            )
            stage.assert_called_once_with(manifest_path, expected)
            self.assertEqual(publish.call_count, 2)
            snapshot_temporary, snapshot_output = publish.call_args_list[0].args
            self.assertEqual(snapshot_temporary.parent, manifest_path.parent)
            self.assertEqual(
                snapshot_output,
                manifest_path.parent / vault_maintenance.SNAPSHOT_NAME,
            )
            self.assertEqual(
                publish.call_args_list[1].args,
                (
                    manifest_path.parent / ".captured-manifest.tmp",
                    manifest_path,
                ),
            )
            self.assertEqual(manifest_path.read_bytes(), expected)

    def test_vault_staging_failure_removes_snapshot_bundle(self) -> None:
        payload = {"manifest_hmac_sha256": "e" * 64}
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "vault-bundle"
            patches = self._vault_patches(root, payload)
            with (
                patches[0],
                patches[1],
                patches[2],
                patches[3],
                patches[4],
                mock.patch.object(
                    vault_maintenance,
                    "write_fsynced_temporary_bytes",
                    create=True,
                    side_effect=OSError("stage-failed"),
                ),
                self.assertRaisesRegex(OSError, "stage-failed"),
            ):
                vault_maintenance.create_snapshot(
                    output,
                    address="https://vault.invalid",
                    token_file=root / "token",
                    manifest_key_file=root / "manifest.key",
                    recovery_set="release-v1.2.3",
                    postgres_manifest=root / "postgres-manifest.json",
                    ca_file=root / "ca.pem",
                )
            self.assertFalse(output.exists())

    def test_manifest_producers_have_no_direct_text_write(self) -> None:
        for module, function in (
            (postgres_maintenance, postgres_maintenance.backup_bundle),
            (redis_maintenance, redis_maintenance.backup_release),
            (vault_maintenance, vault_maintenance.create_snapshot),
        ):
            with self.subTest(module=module.__name__):
                source = inspect.getsource(function)
                self.assertNotIn(".write_text(", source)
                self.assertIn("write_fsynced_temporary_bytes(", source)
                self.assertIn("publish_bundle_write_once_file(", source)


if __name__ == "__main__":
    unittest.main()
