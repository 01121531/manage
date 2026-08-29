import hashlib
import hmac
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from scripts.backup_crypto import ALGORITHM, FORMAT_VERSION, encrypt_stream, key_id
from scripts import backup_output_policy


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "redis_maintenance.py"
SPEC = importlib.util.spec_from_file_location("redis_maintenance", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
redis_maintenance = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = redis_maintenance
SPEC.loader.exec_module(redis_maintenance)


KEY = b"r" * 32
WRONG_KEY = b"w" * 32
RELEASE = {
    "release_tag": "v2.3.4",
    "release_commit": "a" * 40,
    "migration_head": "0018_access_token_revocations",
    "container_manifest_sha256": "b" * 64,
}
RECOVERY_SET = "pilot-2026-08-21"
POSTGRES_MANIFEST_BYTES = b'{"verified":"postgres-release-manifest"}\n'
POSTGRES_MANIFEST_SHA256 = hashlib.sha256(POSTGRES_MANIFEST_BYTES).hexdigest()
MANIFEST_HKDF_INFO = b"email-platform/redis-backup-manifest/v1/hmac-sha256"


class _NonClosingBytesIO(io.BytesIO):
    def close(self) -> None:
        pass


class _ArchiveProcess:
    def __init__(self, command, *, payload: bytes, stdout=None, **kwargs):
        self.command = list(command)
        self.stdout = io.BytesIO(payload) if stdout is subprocess.PIPE else None
        self.returncode: int | None = None

    def wait(self) -> int:
        self.returncode = 0
        return 0

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9


class _FailingArchiveProcess(_ArchiveProcess):
    def wait(self) -> int:
        self.returncode = 7
        return 7


class _RestoreProcess:
    instances: list["_RestoreProcess"] = []

    def __init__(self, command, *, stdin=None, **kwargs):
        self.command = list(command)
        self.stdin = _NonClosingBytesIO() if stdin is subprocess.PIPE else None
        self.returncode: int | None = None
        self.instances.append(self)

    def wait(self) -> int:
        self.returncode = 0
        return 0

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9


def _tar_bytes(*, member_name: str = "appendonlydir/appendonly.aof.1.base.rdb", symlink: bool = False) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        entry = tarfile.TarInfo(member_name)
        if symlink:
            entry.type = tarfile.SYMTYPE
            entry.linkname = "../outside"
            entry.size = 0
            archive.addfile(entry)
        else:
            payload = b"redis-aof-and-rdb-volume-state"
            entry.size = len(payload)
            archive.addfile(entry, io.BytesIO(payload))
    return output.getvalue()


def _canonical_manifest_bytes(manifest: dict[str, object]) -> bytes:
    return json.dumps(
        {
            key: value
            for key, value in manifest.items()
            if key != "manifest_hmac_sha256"
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _manifest_hmac(manifest: dict[str, object], key: bytes = KEY) -> str:
    mac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=MANIFEST_HKDF_INFO,
    ).derive(key)
    return hmac.new(mac_key, _canonical_manifest_bytes(manifest), hashlib.sha256).hexdigest()


class RedisMaintenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        _RestoreProcess.instances.clear()

    def _write_postgres_manifest(self, parent: Path) -> Path:
        path = parent / "postgres-manifest.json"
        path.write_bytes(POSTGRES_MANIFEST_BYTES)
        return path

    def _write_bundle(
        self,
        directory: Path,
        *,
        archive: bytes | None = None,
        key: bytes = KEY,
    ) -> dict[str, object]:
        directory.mkdir()
        artifact = directory / "redis-data.tar.enc"
        with artifact.open("wb") as destination:
            encrypt_stream(
                io.BytesIO(archive or _tar_bytes()),
                destination,
                key,
                logical_name="redis-data",
                source_database="redis-data",
            )
        artifact_bytes = artifact.read_bytes()
        manifest: dict[str, object] = {
            "schema_version": 1,
            "created_at": "2026-08-21T12:00:00+00:00",
            "artifact": "redis-data.tar.enc",
            "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
            "size_bytes": len(artifact_bytes),
            "algorithm": ALGORITHM,
            "format_version": FORMAT_VERSION,
            "key_id": key_id(key),
            **RELEASE,
            "postgres_manifest_sha256": POSTGRES_MANIFEST_SHA256,
            "recovery_set": RECOVERY_SET,
        }
        manifest["manifest_hmac_sha256"] = _manifest_hmac(manifest, key)
        (directory / "redis-manifest.json").write_text(
            json.dumps(manifest, sort_keys=True), encoding="utf-8"
        )
        return manifest

    def _verify(self, directory: Path, **overrides: object):
        arguments = {
            "key_file": directory.parent / "redis.key",
            **RELEASE,
            "postgres_manifest_sha256": POSTGRES_MANIFEST_SHA256,
            "recovery_set": RECOVERY_SET,
        }
        arguments.update(overrides)
        return redis_maintenance.verify_release_backup(directory, **arguments)

    def _restore(self, directory: Path, **overrides: object) -> None:
        arguments = {
            "key_file": directory.parent / "redis.key",
            **RELEASE,
            "postgres_manifest_sha256": POSTGRES_MANIFEST_SHA256,
            "recovery_set": RECOVERY_SET,
            "confirm_release_tag": RELEASE["release_tag"],
        }
        arguments.update(overrides)
        redis_maintenance.restore_release(directory, **arguments)

    def test_backup_streams_stdout_directly_to_an_encrypted_release_bundle(self) -> None:
        archive = _tar_bytes()
        processes: list[_ArchiveProcess] = []

        def popen(command, **kwargs):
            process = _ArchiveProcess(command, payload=archive, **kwargs)
            processes.append(process)
            return process

        def run(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, stdout="")

        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            postgres_manifest = self._write_postgres_manifest(parent)
            output = parent / "redis-release"
            with (
                mock.patch.object(redis_maintenance, "load_key_file", return_value=KEY),
                mock.patch.object(redis_maintenance.subprocess, "run", side_effect=run) as run_mock,
                mock.patch.object(redis_maintenance.subprocess, "Popen", side_effect=popen),
            ):
                manifest_path = redis_maintenance.backup_release(
                    output,
                    key_file=parent / "redis.key",
                    postgres_manifest=postgres_manifest,
                    recovery_set=RECOVERY_SET,
                    **RELEASE,
                )

            self.assertEqual(manifest_path, output / "redis-manifest.json")
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {"redis-data.tar.enc", "redis-manifest.json"},
            )
            encrypted = (output / "redis-data.tar.enc").read_bytes()
            self.assertNotIn(b"redis-aof-and-rdb-volume-state", encrypted)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["postgres_manifest_sha256"], POSTGRES_MANIFEST_SHA256)
            self.assertEqual(manifest["key_id"], key_id(KEY))
            self.assertEqual(len(processes), 1)
            command_text = " ".join(processes[0].command)
            self.assertIn(str(ROOT / "docker-compose.yml"), command_text)
            self.assertIn("redis", processes[0].command)
            self.assertIn("/data", command_text)
            self.assertNotIn(str(parent / "redis.key"), command_text)
            self.assertNotIn(KEY.decode("ascii"), command_text)
            run_mock.assert_called_once_with(
                redis_maintenance._status_command(),
                check=True,
                capture_output=True,
                text=True,
            )

    def test_compose_commands_pin_the_production_project_identity(self) -> None:
        expected_prefix = [
            "docker",
            "compose",
            "--project-directory",
            str(ROOT),
            "--env-file",
            str(ROOT / ".env"),
            "--project-name",
            "email-platform",
            "--file",
            str(ROOT / "docker-compose.yml"),
        ]
        commands = (
            redis_maintenance._stop_command(),
            redis_maintenance._start_command(),
            redis_maintenance._status_command(),
            redis_maintenance._health_command(),
            redis_maintenance._archive_command(),
            redis_maintenance._restore_command(),
        )

        for command in commands:
            self.assertEqual(command[: len(expected_prefix)], expected_prefix)
        self.assertEqual(
            redis_maintenance._start_command()[len(expected_prefix) :],
            ["up", "-d", "--no-build", "--pull", "never", "redis"],
        )
        self.assertEqual(
            redis_maintenance._health_command()[len(expected_prefix) :],
            ["exec", "-T", "redis", "/usr/local/bin/redis-healthcheck"],
        )

    def test_docker_environment_fails_before_backup_and_restore_access(self) -> None:
        variables = (
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
            "DOCKER_CONFIG",
            "DOCKER_TLS",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
        )
        for name in variables:
            for value in ("1", "0", "", "operator-decoy"):
                with self.subTest(operation="backup", name=name, value=value):
                    with (
                        mock.patch.dict(os.environ, {name: value}),
                        mock.patch.object(
                            redis_maintenance,
                            "create_write_once_directory",
                            side_effect=AssertionError("output claim was reached"),
                        ) as output_claim,
                        mock.patch.object(redis_maintenance, "load_key_file") as load_key,
                        mock.patch.object(redis_maintenance.subprocess, "run") as run,
                        mock.patch.object(redis_maintenance.subprocess, "Popen") as popen,
                    ):
                        with self.assertRaisesRegex(
                            RuntimeError,
                            "^production backup Docker environment preflight failed$",
                        ):
                            redis_maintenance.backup_release(
                                "unused-backup",
                                key_file="unused.key",
                                postgres_manifest="unused-manifest.json",
                                recovery_set=RECOVERY_SET,
                                **RELEASE,
                            )
                    output_claim.assert_not_called()
                    load_key.assert_not_called()
                    run.assert_not_called()
                    popen.assert_not_called()

                with self.subTest(operation="restore", name=name, value=value):
                    with (
                        mock.patch.dict(os.environ, {name: value}),
                        mock.patch.object(
                            redis_maintenance,
                            "_verify_release_backup_details",
                            side_effect=AssertionError("manifest verifier was reached"),
                        ) as verify,
                        mock.patch.object(redis_maintenance, "load_key_file") as load_key,
                        mock.patch.object(redis_maintenance.subprocess, "run") as run,
                        mock.patch.object(redis_maintenance.subprocess, "Popen") as popen,
                    ):
                        with self.assertRaisesRegex(
                            RuntimeError,
                            "^production backup Docker environment preflight failed$",
                        ):
                            redis_maintenance.restore_release(
                                "unused-backup",
                                key_file="unused.key",
                                recovery_set=RECOVERY_SET,
                                confirm_release_tag=RELEASE["release_tag"],
                                postgres_manifest_sha256=POSTGRES_MANIFEST_SHA256,
                                **RELEASE,
                            )
                    verify.assert_not_called()
                    load_key.assert_not_called()
                    run.assert_not_called()
                    popen.assert_not_called()

    def test_existing_output_directory_refuses_key_and_docker_access(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            postgres_manifest = self._write_postgres_manifest(parent)
            output = parent / "existing"
            output.mkdir()
            sentinel = output / "keep"
            sentinel.write_bytes(b"valid-old-recovery-point")
            with (
                mock.patch.object(redis_maintenance, "load_key_file") as load_key,
                mock.patch.object(redis_maintenance.subprocess, "run") as run,
                mock.patch.object(redis_maintenance.subprocess, "Popen") as popen,
            ):
                with self.assertRaisesRegex(ValueError, "must not already exist"):
                    redis_maintenance.backup_release(
                        output,
                        key_file=parent / "redis.key",
                        postgres_manifest=postgres_manifest,
                        recovery_set=RECOVERY_SET,
                        **RELEASE,
                    )
            load_key.assert_not_called()
            run.assert_not_called()
            popen.assert_not_called()
            self.assertEqual(sentinel.read_bytes(), b"valid-old-recovery-point")

    def test_failed_backup_removes_only_its_new_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            postgres_manifest = self._write_postgres_manifest(parent)
            output = parent / "new-failed"
            existing = parent / "existing-valid"
            existing.mkdir()
            sentinel = existing / "manifest"
            sentinel.write_bytes(b"keep")
            with (
                mock.patch.object(redis_maintenance, "load_key_file", return_value=KEY),
                mock.patch.object(
                    redis_maintenance.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, stdout=""),
                ),
                mock.patch.object(
                    redis_maintenance.subprocess,
                    "Popen",
                    side_effect=lambda command, **kwargs: _FailingArchiveProcess(
                        command, payload=_tar_bytes(), **kwargs
                    ),
                ),
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    redis_maintenance.backup_release(
                        output,
                        key_file=parent / "redis.key",
                        postgres_manifest=postgres_manifest,
                        recovery_set=RECOVERY_SET,
                        **RELEASE,
                    )
            self.assertFalse(output.exists())
            self.assertEqual(sentinel.read_bytes(), b"keep")

    def test_backup_restores_an_originally_running_redis_after_success(self) -> None:
        running = True
        calls: list[list[str]] = []

        def run(command, **kwargs):
            nonlocal running
            rendered = list(command)
            calls.append(rendered)
            if rendered == redis_maintenance._status_command():
                return subprocess.CompletedProcess(
                    rendered, 0, stdout="redis\n" if running else ""
                )
            if rendered == redis_maintenance._stop_command():
                running = False
            elif rendered == redis_maintenance._start_command():
                running = True
            return subprocess.CompletedProcess(rendered, 0, stdout="")

        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            postgres_manifest = self._write_postgres_manifest(parent)
            output = parent / "redis-release"
            with (
                mock.patch.object(redis_maintenance, "load_key_file", return_value=KEY),
                mock.patch.object(redis_maintenance.subprocess, "run", side_effect=run),
                mock.patch.object(
                    redis_maintenance.subprocess,
                    "Popen",
                    side_effect=lambda command, **kwargs: _ArchiveProcess(
                        command, payload=_tar_bytes(), **kwargs
                    ),
                ),
            ):
                manifest = redis_maintenance.backup_release(
                    output,
                    key_file=parent / "redis.key",
                    postgres_manifest=postgres_manifest,
                    recovery_set=RECOVERY_SET,
                    **RELEASE,
                )

        self.assertEqual(manifest, output / "redis-manifest.json")
        self.assertTrue(running)
        self.assertEqual(calls.count(redis_maintenance._stop_command()), 1)
        self.assertEqual(calls.count(redis_maintenance._start_command()), 1)
        self.assertEqual(calls.count(redis_maintenance._health_command()), 1)
        self.assertEqual(calls[-1], redis_maintenance._health_command())

    def test_failed_backup_still_restores_an_originally_running_redis(self) -> None:
        running = True
        calls: list[list[str]] = []

        def run(command, **kwargs):
            nonlocal running
            rendered = list(command)
            calls.append(rendered)
            if rendered == redis_maintenance._status_command():
                return subprocess.CompletedProcess(
                    rendered, 0, stdout="redis\n" if running else ""
                )
            if rendered == redis_maintenance._stop_command():
                running = False
            elif rendered == redis_maintenance._start_command():
                running = True
            return subprocess.CompletedProcess(rendered, 0, stdout="")

        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            postgres_manifest = self._write_postgres_manifest(parent)
            output = parent / "redis-release"
            with (
                mock.patch.object(redis_maintenance, "load_key_file", return_value=KEY),
                mock.patch.object(redis_maintenance.subprocess, "run", side_effect=run),
                mock.patch.object(
                    redis_maintenance.subprocess,
                    "Popen",
                    side_effect=lambda command, **kwargs: _FailingArchiveProcess(
                        command, payload=_tar_bytes(), **kwargs
                    ),
                ),
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    redis_maintenance.backup_release(
                        output,
                        key_file=parent / "redis.key",
                        postgres_manifest=postgres_manifest,
                        recovery_set=RECOVERY_SET,
                        **RELEASE,
                    )

            self.assertFalse(output.exists())
        self.assertTrue(running)
        self.assertEqual(calls.count(redis_maintenance._start_command()), 1)
        self.assertEqual(calls[-1], redis_maintenance._health_command())

    def test_restart_failure_overrides_success_or_archive_error_and_is_redacted(self) -> None:
        for label, process_factory in (
            ("success", _ArchiveProcess),
            ("archive-error", _FailingArchiveProcess),
        ):
            running = True

            def run(command, **kwargs):
                nonlocal running
                rendered = list(command)
                if rendered == redis_maintenance._status_command():
                    return subprocess.CompletedProcess(
                        rendered, 0, stdout="redis\n" if running else ""
                    )
                if rendered == redis_maintenance._stop_command():
                    running = False
                    return subprocess.CompletedProcess(rendered, 0, stdout="")
                if rendered == redis_maintenance._start_command():
                    raise subprocess.CalledProcessError(
                        1, rendered, stderr="SENSITIVE_RESTART_DETAIL"
                    )
                return subprocess.CompletedProcess(rendered, 0, stdout="")

            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp_dir:
                parent = Path(temp_dir)
                postgres_manifest = self._write_postgres_manifest(parent)
                output = parent / "redis-release"
                with (
                    mock.patch.object(redis_maintenance, "load_key_file", return_value=KEY),
                    mock.patch.object(redis_maintenance.subprocess, "run", side_effect=run),
                    mock.patch.object(
                        redis_maintenance.subprocess,
                        "Popen",
                        side_effect=lambda command, _factory=process_factory, **kwargs: _factory(
                            command, payload=_tar_bytes(), **kwargs
                        ),
                    ),
                ):
                    with self.assertRaisesRegex(
                        redis_maintenance.RedisBackupFatalError,
                        "Redis restart could not be confirmed",
                    ) as raised:
                        redis_maintenance.backup_release(
                            output,
                            key_file=parent / "redis.key",
                            postgres_manifest=postgres_manifest,
                            recovery_set=RECOVERY_SET,
                            **RELEASE,
                        )
                self.assertNotIn("SENSITIVE_RESTART_DETAIL", str(raised.exception))
                self.assertFalse(output.exists())

    def test_backup_primary_survives_unconfirmed_cleanup_and_redis_restarts(self) -> None:
        running = True

        def run(command, **kwargs):
            nonlocal running
            rendered = list(command)
            if rendered == redis_maintenance._status_command():
                return subprocess.CompletedProcess(
                    rendered, 0, stdout="redis\n" if running else ""
                )
            if rendered == redis_maintenance._stop_command():
                running = False
            elif rendered == redis_maintenance._start_command():
                running = True
            return subprocess.CompletedProcess(rendered, 0, stdout="")

        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            postgres_manifest = self._write_postgres_manifest(parent)
            output = parent / "redis-release"
            with (
                mock.patch.object(redis_maintenance, "load_key_file", return_value=KEY),
                mock.patch.object(redis_maintenance.subprocess, "run", side_effect=run),
                mock.patch.object(
                    redis_maintenance.subprocess,
                    "Popen",
                    side_effect=lambda command, **kwargs: _FailingArchiveProcess(
                        command, payload=_tar_bytes(), **kwargs
                    ),
                ),
                mock.patch.object(
                    backup_output_policy,
                    "cleanup_created_directory",
                    side_effect=PermissionError("CLEANUP_PATH_SECRET"),
                ) as cleanup,
                self.assertRaises(subprocess.CalledProcessError) as raised,
            ):
                redis_maintenance.backup_release(
                    output,
                    key_file=parent / "redis.key",
                    postgres_manifest=postgres_manifest,
                    recovery_set=RECOVERY_SET,
                    **RELEASE,
                )

            self.assertEqual(
                raised.exception.__notes__,
                [backup_output_policy.CLEANUP_UNCONFIRMED_NOTE],
            )
            self.assertNotIn("CLEANUP_PATH_SECRET", " ".join(raised.exception.__notes__))
            self.assertEqual(cleanup.call_count, 1)
            self.assertTrue(output.is_dir())
            self.assertTrue(running)

    def test_restart_is_primary_when_its_single_cleanup_attempt_fails(self) -> None:
        running = True
        restart_error = subprocess.CalledProcessError(
            1,
            ["redis-start"],
            stderr="RESTART_DETAIL_SECRET",
        )

        def run(command, **kwargs):
            nonlocal running
            rendered = list(command)
            if rendered == redis_maintenance._status_command():
                return subprocess.CompletedProcess(
                    rendered, 0, stdout="redis\n" if running else ""
                )
            if rendered == redis_maintenance._stop_command():
                running = False
            elif rendered == redis_maintenance._start_command():
                raise restart_error
            return subprocess.CompletedProcess(rendered, 0, stdout="")

        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            postgres_manifest = self._write_postgres_manifest(parent)
            output = parent / "redis-release"
            with (
                mock.patch.object(redis_maintenance, "load_key_file", return_value=KEY),
                mock.patch.object(redis_maintenance.subprocess, "run", side_effect=run),
                mock.patch.object(
                    redis_maintenance.subprocess,
                    "Popen",
                    side_effect=lambda command, **kwargs: _ArchiveProcess(
                        command, payload=_tar_bytes(), **kwargs
                    ),
                ),
                mock.patch.object(
                    backup_output_policy,
                    "cleanup_created_directory",
                    side_effect=PermissionError("CLEANUP_PATH_SECRET"),
                ) as cleanup,
                self.assertRaises(redis_maintenance.RedisBackupFatalError) as raised,
            ):
                redis_maintenance.backup_release(
                    output,
                    key_file=parent / "redis.key",
                    postgres_manifest=postgres_manifest,
                    recovery_set=RECOVERY_SET,
                    **RELEASE,
                )

            self.assertIs(raised.exception.__cause__, restart_error)
            self.assertEqual(cleanup.call_count, 1)
            self.assertEqual(
                raised.exception.__notes__,
                [backup_output_policy.CLEANUP_UNCONFIRMED_NOTE],
            )
            self.assertEqual(
                str(raised.exception),
                "Redis restart could not be confirmed; "
                "backup output cleanup could not be confirmed",
            )
            self.assertTrue(output.is_dir())

    def test_running_or_health_confirmation_failure_is_fatal(self) -> None:
        for label in ("not-running", "health-failed"):
            running = True

            def run(command, **kwargs):
                nonlocal running
                rendered = list(command)
                if rendered == redis_maintenance._status_command():
                    return subprocess.CompletedProcess(
                        rendered, 0, stdout="redis\n" if running else ""
                    )
                if rendered == redis_maintenance._stop_command():
                    running = False
                elif rendered == redis_maintenance._start_command():
                    running = label == "health-failed"
                elif rendered == redis_maintenance._health_command():
                    raise subprocess.CalledProcessError(
                        1, rendered, stderr="SENSITIVE_HEALTH_DETAIL"
                    )
                return subprocess.CompletedProcess(rendered, 0, stdout="")

            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp_dir:
                parent = Path(temp_dir)
                postgres_manifest = self._write_postgres_manifest(parent)
                output = parent / "redis-release"
                with (
                    mock.patch.object(redis_maintenance, "load_key_file", return_value=KEY),
                    mock.patch.object(redis_maintenance.subprocess, "run", side_effect=run),
                    mock.patch.object(
                        redis_maintenance.subprocess,
                        "Popen",
                        side_effect=lambda command, **kwargs: _ArchiveProcess(
                            command, payload=_tar_bytes(), **kwargs
                        ),
                    ),
                ):
                    with self.assertRaisesRegex(
                        redis_maintenance.RedisBackupFatalError,
                        "Redis restart could not be confirmed",
                    ) as raised:
                        redis_maintenance.backup_release(
                            output,
                            key_file=parent / "redis.key",
                            postgres_manifest=postgres_manifest,
                            recovery_set=RECOVERY_SET,
                            **RELEASE,
                        )
                self.assertNotIn("SENSITIVE_HEALTH_DETAIL", str(raised.exception))
                self.assertFalse(output.exists())

    def test_backup_does_not_start_redis_that_was_already_stopped(self) -> None:
        calls: list[list[str]] = []

        def run(command, **kwargs):
            rendered = list(command)
            calls.append(rendered)
            return subprocess.CompletedProcess(rendered, 0, stdout="")

        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            postgres_manifest = self._write_postgres_manifest(parent)
            output = parent / "redis-release"
            with (
                mock.patch.object(redis_maintenance, "load_key_file", return_value=KEY),
                mock.patch.object(redis_maintenance.subprocess, "run", side_effect=run),
                mock.patch.object(
                    redis_maintenance.subprocess,
                    "Popen",
                    side_effect=lambda command, **kwargs: _ArchiveProcess(
                        command, payload=_tar_bytes(), **kwargs
                    ),
                ),
            ):
                redis_maintenance.backup_release(
                    output,
                    key_file=parent / "redis.key",
                    postgres_manifest=postgres_manifest,
                    recovery_set=RECOVERY_SET,
                    **RELEASE,
                )

        self.assertNotIn(redis_maintenance._stop_command(), calls)
        self.assertNotIn(redis_maintenance._start_command(), calls)
        self.assertNotIn(redis_maintenance._health_command(), calls)

    def test_verify_authenticates_exact_manifest_artifact_and_returns_aware_time(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir) / "bundle"
            expected = self._write_bundle(directory)
            with mock.patch.object(redis_maintenance, "load_key_file", return_value=KEY):
                manifest, created_at = redis_maintenance.verify_release_backup(
                    directory,
                    key_file=Path(temp_dir) / "redis.key",
                    postgres_manifest_sha256=POSTGRES_MANIFEST_SHA256,
                    recovery_set=RECOVERY_SET,
                    _include_created_at=True,
                    **RELEASE,
                )
            self.assertEqual(manifest, expected)
            self.assertIsInstance(created_at, datetime)
            self.assertIsNotNone(created_at.tzinfo)

    def test_verify_rejects_same_bytes_manifest_replacement_after_leaf_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir) / "bundle"
            self._write_bundle(directory)
            exact_gate = redis_maintenance.require_exact_regular_files
            replaced = False

            def replace_after_gate(candidate, expected_names):
                nonlocal replaced
                identities = exact_gate(candidate, expected_names)
                if not replaced:
                    replaced = True
                    manifest = candidate / "redis-manifest.json"
                    replacement = candidate / ".manifest-replacement"
                    replacement.write_bytes(manifest.read_bytes())
                    os.replace(replacement, manifest)
                return identities

            with (
                mock.patch.object(
                    redis_maintenance,
                    "require_exact_regular_files",
                    side_effect=replace_after_gate,
                ),
                mock.patch.object(redis_maintenance, "load_key_file", return_value=KEY),
            ):
                with self.assertRaisesRegex(ValueError, "manifest is invalid"):
                    self._verify(directory)

    def test_verified_manifest_digest_uses_the_authenticated_stable_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir) / "bundle"
            self._write_bundle(directory)
            manifest_path = directory / "redis-manifest.json"
            original = manifest_path.read_bytes()
            stable_loader = redis_maintenance.load_unique_json_with_bytes

            def replace_after_read(candidate: Path, *, max_bytes: int, **kwargs):
                value, raw = stable_loader(candidate, max_bytes=max_bytes, **kwargs)
                if candidate == manifest_path:
                    candidate.write_bytes(raw + b" ")
                return value, raw

            with mock.patch.object(
                redis_maintenance,
                "load_unique_json_with_bytes",
                side_effect=replace_after_read,
            ), mock.patch.object(redis_maintenance, "load_key_file", return_value=KEY):
                with self.assertRaisesRegex(ValueError, "changed"):
                    redis_maintenance.verify_release_backup(
                        directory,
                        key_file=Path(temp_dir) / "redis.key",
                        postgres_manifest_sha256=POSTGRES_MANIFEST_SHA256,
                        recovery_set=RECOVERY_SET,
                        _include_created_at=True,
                        _include_manifest_sha256=True,
                        **RELEASE,
                    )
            self.assertNotEqual(original, manifest_path.read_bytes())

    def test_verify_rejects_tamper_wrong_key_binding_postgres_sha_and_closed_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)

            artifact_tamper = parent / "artifact-tamper"
            self._write_bundle(artifact_tamper)
            artifact_path = artifact_tamper / "redis-data.tar.enc"
            data = bytearray(artifact_path.read_bytes())
            data[-17] ^= 1
            artifact_path.write_bytes(data)
            with mock.patch.object(redis_maintenance, "load_key_file", return_value=KEY):
                with self.assertRaises(ValueError):
                    self._verify(artifact_tamper)

            wrong_key = parent / "wrong-key"
            self._write_bundle(wrong_key)
            with mock.patch.object(redis_maintenance, "load_key_file", return_value=WRONG_KEY):
                with self.assertRaises(ValueError):
                    self._verify(wrong_key)

            binding = parent / "binding"
            self._write_bundle(binding)
            with mock.patch.object(redis_maintenance, "load_key_file", return_value=KEY):
                with self.assertRaisesRegex(ValueError, "release_tag"):
                    self._verify(binding, release_tag="v9.9.9")
                with self.assertRaisesRegex(ValueError, "PostgreSQL"):
                    self._verify(binding, postgres_manifest_sha256="c" * 64)

            for label, mutation in (
                ("old-schema", {"schema_version": 0}),
                ("unknown-field", {"unexpected": "signed-but-forbidden"}),
            ):
                directory = parent / label
                manifest = self._write_bundle(directory)
                manifest.update(mutation)
                manifest["manifest_hmac_sha256"] = _manifest_hmac(manifest)
                (directory / "redis-manifest.json").write_text(
                    json.dumps(manifest), encoding="utf-8"
                )
                with mock.patch.object(redis_maintenance, "load_key_file", return_value=KEY):
                    with self.assertRaises(ValueError):
                        self._verify(directory)

    def test_restore_authentication_failure_invokes_no_docker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir) / "bundle"
            self._write_bundle(directory)
            artifact = directory / "redis-data.tar.enc"
            data = bytearray(artifact.read_bytes())
            data[-1] ^= 1
            artifact.write_bytes(data)
            with (
                mock.patch.object(redis_maintenance, "load_key_file", return_value=KEY),
                mock.patch.object(redis_maintenance.subprocess, "run") as run,
                mock.patch.object(redis_maintenance.subprocess, "Popen") as popen,
            ):
                with self.assertRaises(ValueError):
                    self._restore(directory)
            run.assert_not_called()
            popen.assert_not_called()

    def test_restore_rejects_traversal_and_symlink_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            unsafe_archives = (
                ("traversal", _tar_bytes(member_name="../outside")),
                ("symlink", _tar_bytes(member_name="link", symlink=True)),
            )
            for label, archive in unsafe_archives:
                with self.subTest(label=label):
                    directory = parent / label
                    self._write_bundle(directory, archive=archive)
                    with (
                        mock.patch.object(redis_maintenance, "load_key_file", return_value=KEY),
                        mock.patch.object(redis_maintenance.subprocess, "run") as run,
                        mock.patch.object(redis_maintenance.subprocess, "Popen") as popen,
                    ):
                        with self.assertRaisesRegex(ValueError, "tar"):
                            self._restore(directory)
                    run.assert_not_called()
                    popen.assert_not_called()

    def test_restore_refuses_running_redis_after_all_read_only_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir) / "bundle"
            self._write_bundle(directory)
            with (
                mock.patch.object(redis_maintenance, "load_key_file", return_value=KEY),
                mock.patch.object(
                    redis_maintenance.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, stdout="redis\n"),
                ) as run,
                mock.patch.object(redis_maintenance.subprocess, "Popen") as popen,
            ):
                with self.assertRaisesRegex(ValueError, "must be stopped"):
                    self._restore(directory)
            run.assert_called_once()
            popen.assert_not_called()

    def test_restore_clears_volume_then_streams_authenticated_archive(self) -> None:
        archive = _tar_bytes()
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir) / "bundle"
            self._write_bundle(directory, archive=archive)
            with (
                mock.patch.object(
                    redis_maintenance,
                    "load_key_file",
                    return_value=KEY,
                ) as load_key,
                mock.patch.object(
                    redis_maintenance.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, stdout=""),
                ),
                mock.patch.object(
                    redis_maintenance.subprocess,
                    "Popen",
                    side_effect=lambda command, **kwargs: _RestoreProcess(command, **kwargs),
                ),
            ):
                self._restore(directory)

            self.assertEqual(len(_RestoreProcess.instances), 1)
            process = _RestoreProcess.instances[0]
            command_text = " ".join(process.command)
            self.assertIn(str(ROOT / "docker-compose.yml"), command_text)
            self.assertIn("find /data -mindepth 1", command_text)
            self.assertLess(command_text.index("find /data"), command_text.index("tar -C /data"))
            self.assertEqual(process.stdin.getvalue(), archive)
            self.assertNotIn(KEY.decode("ascii"), command_text)
            self.assertEqual(load_key.call_count, 1)

    def test_restore_stops_when_source_path_changes_after_staging(self) -> None:
        archive = _tar_bytes()
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir) / "bundle"
            self._write_bundle(directory, archive=archive)
            artifact = directory / "redis-data.tar.enc"

            def replace_source_after_staging(*args, **kwargs):
                artifact.write_bytes(b"replaced-after-authentication")
                return subprocess.CompletedProcess([], 0, stdout="")

            with (
                mock.patch.object(redis_maintenance, "load_key_file", return_value=KEY),
                mock.patch.object(
                    redis_maintenance.subprocess,
                    "run",
                    side_effect=replace_source_after_staging,
                ),
                mock.patch.object(
                    redis_maintenance.subprocess,
                    "Popen",
                    side_effect=lambda command, **kwargs: _RestoreProcess(command, **kwargs),
                ),
            ):
                with self.assertRaisesRegex(ValueError, "changed before restore"):
                    self._restore(directory)

            self.assertEqual(_RestoreProcess.instances, [])

    def test_restore_confirmation_and_postgres_hash_inputs_fail_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            directory = parent / "bundle"
            self._write_bundle(directory)
            postgres_manifest = self._write_postgres_manifest(parent)
            with (
                mock.patch.object(redis_maintenance, "load_key_file", return_value=KEY),
                mock.patch.object(redis_maintenance.subprocess, "run") as run,
                mock.patch.object(redis_maintenance.subprocess, "Popen") as popen,
            ):
                with self.assertRaisesRegex(ValueError, "confirm"):
                    self._restore(directory, confirm_release_tag="v0.0.1")
                with self.assertRaises(ValueError):
                    self._restore(directory, postgres_manifest_sha256="not-a-sha")
                with self.assertRaises(ValueError):
                    self._restore(
                        directory,
                        postgres_manifest=postgres_manifest,
                        postgres_manifest_sha256=POSTGRES_MANIFEST_SHA256,
                    )
            run.assert_not_called()
            popen.assert_not_called()

    def test_cli_is_release_only_and_has_no_redis_credentials(self) -> None:
        parser = redis_maintenance.build_parser()
        common = [
            "--key-file", "C:/secrets/redis.key",
            "--release-tag", RELEASE["release_tag"],
            "--release-commit", RELEASE["release_commit"],
            "--migration-head", RELEASE["migration_head"],
            "--container-manifest-sha256", RELEASE["container_manifest_sha256"],
            "--recovery-set", RECOVERY_SET,
        ]
        backup = parser.parse_args(
            [
                "backup-release", "--output-dir", "C:/backups/redis",
                "--postgres-manifest", "C:/backups/postgres/manifest.json", *common,
            ]
        )
        verify = parser.parse_args(
            [
                "verify-release", "--input-dir", "C:/backups/redis",
                "--postgres-manifest-sha256", POSTGRES_MANIFEST_SHA256, *common,
            ]
        )
        restore = parser.parse_args(
            [
                "restore-release", "--input-dir", "C:/backups/redis",
                "--postgres-manifest", "C:/backups/postgres/manifest.json",
                "--confirm-release-tag", RELEASE["release_tag"], *common,
            ]
        )
        self.assertEqual(backup.command, "backup-release")
        self.assertEqual(verify.command, "verify-release")
        self.assertEqual(restore.command, "restore-release")
        for parsed in (backup, verify, restore):
            names = vars(parsed)
            self.assertNotIn("password", names)
            self.assertNotIn("redis_url", names)
            self.assertNotIn("service", names)
            self.assertNotIn("compose_file", names)


if __name__ == "__main__":
    unittest.main()
