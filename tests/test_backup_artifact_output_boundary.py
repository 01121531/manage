import inspect
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import audit_archive
from scripts import backup_output_policy
from scripts import postgres_maintenance
from scripts import redis_maintenance
from scripts import vault_maintenance


_REAL_FSYNC = os.fsync


class _SuccessfulProcess:
    def __init__(self) -> None:
        self.stdout = io.BytesIO(b"plaintext-backup")
        self.returncode: int | None = None

    def wait(self) -> int:
        self.returncode = 0
        return 0

    def kill(self) -> None:
        self.returncode = -9


class _SnapshotResponse:
    status = 200

    def __init__(self) -> None:
        self._chunks = iter((b"raft-", b"snapshot", b""))

    def read(self, _size: int = -1) -> bytes:
        return next(self._chunks)


class _SnapshotConnection:
    def __init__(self) -> None:
        self.response = _SnapshotResponse()
        self.closed = False

    def request(self, *_args, **_kwargs) -> None:
        pass

    def getresponse(self) -> _SnapshotResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


def _write_encrypted(_source, destination, _key, **_kwargs) -> None:
    destination.write(b"encrypted-backup")


class BackupArtifactOutputBoundaryTests(unittest.TestCase):
    def test_large_artifact_sources_require_fsync_and_write_once_publication(self) -> None:
        postgres_source = inspect.getsource(postgres_maintenance.backup_database)
        redis_source = inspect.getsource(redis_maintenance._write_encrypted_archive)
        vault_download_source = inspect.getsource(vault_maintenance._download_snapshot)
        vault_create_source = inspect.getsource(vault_maintenance.create_snapshot)

        for label, source in (
            ("postgres", postgres_source),
            ("redis", redis_source),
            ("vault", vault_download_source),
        ):
            with self.subTest(label=label):
                self.assertIn("stream.flush()" if label != "redis" else "destination.flush()", source)
                self.assertIn(
                    "os.fsync(stream.fileno())"
                    if label != "redis"
                    else "os.fsync(destination.fileno())",
                    source,
                )

        self.assertIn(
            "publish_bundle_write_once_file(publishing_path, snapshot_path)",
            vault_create_source,
        )
        self.assertNotIn("os.replace(temporary_path, snapshot_path)", vault_create_source)

    def test_postgres_artifact_is_fsynced_before_hard_link_commit(self) -> None:
        events: list[str] = []

        def fsync(file_descriptor: int) -> None:
            events.append("fsync")
            _REAL_FSYNC(file_descriptor)

        def publish(temporary_path: Path, output_path: Path) -> None:
            events.append("publish")
            backup_output_policy.publish_write_once_file(temporary_path, output_path)

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "postgres.dump.enc"
            with (
                mock.patch.object(postgres_maintenance, "_validate_production_docker_environment"),
                mock.patch.object(postgres_maintenance, "load_key_file", return_value=b"k" * 32),
                mock.patch.object(postgres_maintenance, "backup_command", return_value=["pg_dump"]),
                mock.patch.object(postgres_maintenance.subprocess, "Popen", return_value=_SuccessfulProcess()),
                mock.patch.object(postgres_maintenance, "encrypt_stream", side_effect=_write_encrypted),
                mock.patch.object(postgres_maintenance.os, "fsync", side_effect=fsync),
                mock.patch.object(postgres_maintenance, "publish_write_once_file", side_effect=publish),
            ):
                result = postgres_maintenance.backup_database(
                    output,
                    key_file=Path(temp_dir) / "unused.key",
                )

            self.assertEqual(events, ["fsync", "publish"])
            self.assertEqual(result.path.read_bytes(), b"encrypted-backup")
            self.assertEqual(list(Path(temp_dir).glob(".*.tmp")), [])

    def test_postgres_hashes_the_staged_inode_before_publication(self) -> None:
        source = inspect.getsource(postgres_maintenance.backup_database)
        publish_index = source.index(
            "publish_write_once_file(temporary_path, path)"
        )
        self.assertLess(source.index("digest = hashlib.sha256()"), publish_index)
        self.assertLess(source.index("stream.seek(0)"), publish_index)
        self.assertNotIn('with path.open("rb")', source)

    def test_postgres_artifact_fsync_failure_publishes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "postgres.dump.enc"
            with (
                mock.patch.object(postgres_maintenance, "_validate_production_docker_environment"),
                mock.patch.object(postgres_maintenance, "load_key_file", return_value=b"k" * 32),
                mock.patch.object(postgres_maintenance, "backup_command", return_value=["pg_dump"]),
                mock.patch.object(postgres_maintenance.subprocess, "Popen", return_value=_SuccessfulProcess()),
                mock.patch.object(postgres_maintenance, "encrypt_stream", side_effect=_write_encrypted),
                mock.patch.object(postgres_maintenance.os, "fsync", side_effect=OSError("fsync-failed")),
                mock.patch.object(postgres_maintenance, "publish_write_once_file") as publish,
                self.assertRaisesRegex(OSError, "fsync-failed"),
            ):
                postgres_maintenance.backup_database(
                    output,
                    key_file=root / "unused.key",
                )

            publish.assert_not_called()
            self.assertEqual(list(root.iterdir()), [])

    def test_redis_artifact_is_fsynced_before_hard_link_commit(self) -> None:
        events: list[str] = []

        def fsync(file_descriptor: int) -> None:
            events.append("fsync")
            _REAL_FSYNC(file_descriptor)

        def publish(temporary_path: Path, output_path: Path) -> None:
            events.append("publish")
            backup_output_policy.publish_write_once_file(temporary_path, output_path)

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "redis.tar.enc"
            with (
                mock.patch.object(redis_maintenance, "_archive_command", return_value=["tar"]),
                mock.patch.object(redis_maintenance.subprocess, "Popen", return_value=_SuccessfulProcess()),
                mock.patch.object(redis_maintenance, "encrypt_stream", side_effect=_write_encrypted),
                mock.patch.object(redis_maintenance.os, "fsync", side_effect=fsync),
                mock.patch.object(
                    redis_maintenance,
                    "publish_bundle_write_once_file",
                    side_effect=publish,
                ),
            ):
                redis_maintenance._write_encrypted_archive(output, b"r" * 32)

            self.assertEqual(events, ["fsync", "publish"])
            self.assertEqual(output.read_bytes(), b"encrypted-backup")
            self.assertEqual(list(Path(temp_dir).glob(".*.tmp")), [])

    def test_redis_artifact_fsync_failure_publishes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "redis.tar.enc"
            with (
                mock.patch.object(redis_maintenance, "_archive_command", return_value=["tar"]),
                mock.patch.object(redis_maintenance.subprocess, "Popen", return_value=_SuccessfulProcess()),
                mock.patch.object(redis_maintenance, "encrypt_stream", side_effect=_write_encrypted),
                mock.patch.object(redis_maintenance.os, "fsync", side_effect=OSError("fsync-failed")),
                mock.patch.object(
                    redis_maintenance,
                    "publish_bundle_write_once_file",
                ) as publish,
                self.assertRaisesRegex(OSError, "fsync-failed"),
            ):
                redis_maintenance._write_encrypted_archive(output, b"r" * 32)

            publish.assert_not_called()
            self.assertEqual(list(root.iterdir()), [])

    def test_redis_artifact_fsync_failure_rolls_back_and_restores_service(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "redis-bundle"
            with (
                mock.patch.object(redis_maintenance, "_validate_production_docker_environment"),
                mock.patch.object(redis_maintenance, "_release_binding", return_value={}),
                mock.patch.object(redis_maintenance, "_require_recovery_set", return_value="release-v1"),
                mock.patch.object(redis_maintenance, "_postgres_manifest_sha256", return_value="c" * 64),
                mock.patch.object(redis_maintenance, "load_key_file", return_value=b"r" * 32),
                mock.patch.object(redis_maintenance, "_redis_is_running", side_effect=(True, False)),
                mock.patch.object(redis_maintenance.subprocess, "run"),
                mock.patch.object(redis_maintenance, "_archive_command", return_value=["tar"]),
                mock.patch.object(redis_maintenance.subprocess, "Popen", return_value=_SuccessfulProcess()),
                mock.patch.object(redis_maintenance, "encrypt_stream", side_effect=_write_encrypted),
                mock.patch.object(redis_maintenance.os, "fsync", side_effect=OSError("fsync-failed")),
                mock.patch.object(redis_maintenance, "_restore_running_redis_after_backup") as restore,
                self.assertRaisesRegex(OSError, "fsync-failed"),
            ):
                redis_maintenance.backup_release(
                    output,
                    key_file=root / "unused.key",
                    release_tag="v1.2.3",
                    release_commit="a" * 40,
                    migration_head="0028_operational_policy_governance",
                    container_manifest_sha256="b" * 64,
                    postgres_manifest=root / "postgres-manifest.json",
                    recovery_set="release-v1",
                )

            restore.assert_called_once_with()
            self.assertFalse(output.exists())

    def test_vault_download_fsyncs_exact_streamed_bytes(self) -> None:
        connection = _SnapshotConnection()
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "vault.snap.tmp"
            with (
                mock.patch.object(vault_maintenance, "_open_connection", return_value=connection),
                mock.patch.object(vault_maintenance.os, "fsync", wraps=_REAL_FSYNC) as fsync,
            ):
                vault_maintenance._download_snapshot(
                    output,
                    address="https://vault.invalid",
                    token="token",
                    ca_file=None,
                    namespace=None,
                )

            self.assertEqual(output.read_bytes(), b"raft-snapshot")
            fsync.assert_called_once()
            self.assertTrue(connection.closed)

    def test_vault_snapshot_fsync_failure_rolls_back_claimed_bundle(self) -> None:
        connection = _SnapshotConnection()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "vault-bundle"
            with (
                mock.patch.object(
                    vault_maintenance,
                    "_snapshot_binding_inputs",
                    return_value=("release-v1.2.3", "c" * 64, b"m" * 32),
                ),
                mock.patch.object(
                    vault_maintenance,
                    "_snapshot_request_inputs",
                    return_value=("https://vault.invalid", "token", None, None),
                ),
                mock.patch.object(vault_maintenance, "_open_connection", return_value=connection),
                mock.patch.object(vault_maintenance.os, "fsync", side_effect=OSError("fsync-failed")),
                mock.patch.object(vault_maintenance, "_inspect_snapshot") as inspect_snapshot,
                self.assertRaisesRegex(ValueError, "^Vault snapshot request failed$"),
            ):
                vault_maintenance.create_snapshot(
                    output,
                    address="https://vault.invalid",
                    token_file=root / "token",
                    manifest_key_file=root / "manifest.key",
                    recovery_set="release-v1.2.3",
                    postgres_manifest=root / "postgres-manifest.json",
                )

            inspect_snapshot.assert_not_called()
            self.assertFalse(output.exists())

    def test_vault_snapshot_racing_leaf_wins_and_bundle_rolls_back(self) -> None:
        def download(path: Path, **_kwargs) -> None:
            path.write_bytes(b"raft-snapshot")

        def publish(temporary_path: Path, output_path: Path) -> None:
            if output_path.name == vault_maintenance.SNAPSHOT_NAME:
                output_path.write_bytes(b"racing-leaf")
            backup_output_policy.publish_write_once_file(temporary_path, output_path)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = root / "vault-bundle"
            with (
                mock.patch.object(
                    vault_maintenance,
                    "_snapshot_binding_inputs",
                    return_value=("release-v1.2.3", "c" * 64, b"m" * 32),
                ),
                mock.patch.object(
                    vault_maintenance,
                    "_snapshot_request_inputs",
                    return_value=("https://vault.invalid", "token", None, None),
                ),
                mock.patch.object(vault_maintenance, "_download_snapshot", side_effect=download),
                mock.patch.object(vault_maintenance, "_inspect_snapshot"),
                mock.patch.object(
                    vault_maintenance,
                    "publish_bundle_write_once_file",
                    side_effect=publish,
                ),
                self.assertRaises(FileExistsError),
            ):
                vault_maintenance.create_snapshot(
                    output,
                    address="https://vault.invalid",
                    token_file=root / "token",
                    manifest_key_file=root / "manifest.key",
                    recovery_set="release-v1.2.3",
                    postgres_manifest=root / "postgres-manifest.json",
                )

            self.assertFalse(output.exists())

    def test_audit_archive_already_has_stream_durability_and_write_once_commit(self) -> None:
        source = inspect.getsource(audit_archive._archive_events_in_claimed_directory)
        self.assertIn("destination.flush()", source)
        self.assertIn("os.fsync(destination.fileno())", source)
        self.assertGreaterEqual(source.count("publish_bundle_write_once_file("), 2)
        self.assertNotIn("os.replace(", source)


if __name__ == "__main__":
    unittest.main()
