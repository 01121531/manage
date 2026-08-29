"""Release-bound encrypted backup and restore for the production Redis volume."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from threading import Thread
from typing import Sequence

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from scripts.backup_crypto import (
    ALGORITHM as BACKUP_ENCRYPTION_ALGORITHM,
    FORMAT_VERSION as BACKUP_ENCRYPTION_FORMAT,
    authenticate_file,
    decrypt_stream,
    decrypt_file_to_stream,
    encrypt_stream,
    key_id,
    load_key_file,
)
from scripts.backup_output_policy import (
    CLEANUP_UNCONFIRMED_NOTE,
    cleanup_created_directory_after_failure,
    cleanup_unconfirmed,
    create_write_once_directory,
    discard_claimed_temporary_file,
    publish_bundle_write_once_file,
    require_exact_regular_files,
    write_fsynced_temporary_bytes,
)
from scripts.external_json import (
    StableFileError,
    StableFileIdentity,
    load_unique_json_with_bytes,
    open_stable_binary,
    read_stable_bytes,
    stable_file_identity,
)
from scripts.production_docker_environment import (
    validate_production_docker_environment as _validate_production_docker_environment,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_COMPOSE_FILE = REPOSITORY_ROOT / "docker-compose.yml"
PRODUCTION_ENV_FILE = REPOSITORY_ROOT / ".env"
PRODUCTION_COMPOSE_PROJECT = "email-platform"
REDIS_SERVICE = "redis"
ARTIFACT_NAME = "redis-data.tar.enc"
MANIFEST_NAME = "redis-manifest.json"
MANIFEST_SCHEMA = 1
MANIFEST_HMAC_FIELD = "manifest_hmac_sha256"
MANIFEST_HKDF_INFO = b"email-platform/redis-backup-manifest/v1/hmac-sha256"
BACKUP_BUNDLE_LEAVES = frozenset({ARTIFACT_NAME, MANIFEST_NAME})
LOGICAL_NAME = "redis-data"
SOURCE_VOLUME = "redis-data"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RELEASE_TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_RELEASE_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_MIGRATION_HEAD = re.compile(r"^[0-9]{4}_[A-Za-z0-9_]+$")
_RECOVERY_SET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_MANIFEST_BYTES = 64 * 1024
_RELEASE_FIELDS = (
    "release_tag",
    "release_commit",
    "migration_head",
    "container_manifest_sha256",
)
_MANIFEST_FIELDS = {
    "schema_version",
    "created_at",
    "artifact",
    "sha256",
    "size_bytes",
    "algorithm",
    "format_version",
    "key_id",
    *_RELEASE_FIELDS,
    "postgres_manifest_sha256",
    "recovery_set",
    MANIFEST_HMAC_FIELD,
}
_TERMINAL_TAR_ENTRY_LIMIT = 1_000_000


class RedisBackupFatalError(RuntimeError):
    """Redis could not be restored to its pre-backup running state."""


def _require_sha256(value: str, *, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _require_recovery_set(value: str) -> str:
    if not isinstance(value, str) or not _RECOVERY_SET.fullmatch(value):
        raise ValueError("recovery set is invalid")
    return value


def _release_binding(
    *,
    release_tag: str,
    release_commit: str,
    migration_head: str,
    container_manifest_sha256: str,
) -> dict[str, str]:
    if not isinstance(release_tag, str) or not _RELEASE_TAG.fullmatch(release_tag):
        raise ValueError("invalid release_tag")
    if not isinstance(release_commit, str) or not _RELEASE_COMMIT.fullmatch(
        release_commit
    ):
        raise ValueError("invalid release_commit")
    if not isinstance(migration_head, str) or not _MIGRATION_HEAD.fullmatch(
        migration_head
    ):
        raise ValueError("invalid migration_head")
    return {
        "release_tag": release_tag,
        "release_commit": release_commit,
        "migration_head": migration_head,
        "container_manifest_sha256": _require_sha256(
            container_manifest_sha256,
            label="container_manifest_sha256",
        ),
    }


def _hash_file(path: Path, *, label: str) -> tuple[str, int]:
    if path.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    digest = hashlib.sha256()
    size_bytes = 0
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
                size_bytes += len(chunk)
    except OSError as error:
        raise ValueError(f"{label} cannot be read") from error
    if size_bytes <= 0:
        raise ValueError(f"{label} is empty")
    return digest.hexdigest(), size_bytes


def _postgres_manifest_sha256(path_value: Path | str) -> str:
    path = Path(path_value)
    if not path.is_absolute():
        raise ValueError("PostgreSQL manifest path must be absolute")
    try:
        raw = read_stable_bytes(path, max_bytes=_MAX_MANIFEST_BYTES)
    except (OSError, ValueError) as error:
        raise ValueError("PostgreSQL manifest cannot be read safely") from error
    return hashlib.sha256(raw).hexdigest()


def _read_manifest(
    path: Path,
    *,
    expected_identity: StableFileIdentity | None = None,
) -> tuple[dict[str, object], bytes]:
    if path.is_symlink():
        raise ValueError("Redis manifest is invalid")
    try:
        manifest, raw = load_unique_json_with_bytes(
            path,
            max_bytes=_MAX_MANIFEST_BYTES,
            expected_identity=expected_identity,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("Redis manifest is invalid") from error
    if not isinstance(manifest, dict):
        raise ValueError("Redis manifest is invalid")
    return manifest, raw


def _canonical_manifest_bytes(manifest: dict[str, object]) -> bytes:
    return json.dumps(
        {
            field: value
            for field, value in manifest.items()
            if field != MANIFEST_HMAC_FIELD
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _manifest_hmac_sha256(manifest: dict[str, object], key: bytes) -> str:
    mac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=MANIFEST_HKDF_INFO,
    ).derive(key)
    return hmac.new(
        mac_key,
        _canonical_manifest_bytes(manifest),
        hashlib.sha256,
    ).hexdigest()


def _compose_command(*arguments: str) -> list[str]:
    return [
        "docker",
        "compose",
        "--project-directory",
        str(REPOSITORY_ROOT),
        "--env-file",
        str(PRODUCTION_ENV_FILE),
        "--project-name",
        PRODUCTION_COMPOSE_PROJECT,
        "--file",
        str(PRODUCTION_COMPOSE_FILE),
        *arguments,
    ]


def _stop_command() -> list[str]:
    return _compose_command("stop", REDIS_SERVICE)


def _start_command() -> list[str]:
    return _compose_command(
        "up", "-d", "--no-build", "--pull", "never", REDIS_SERVICE
    )


def _status_command() -> list[str]:
    return _compose_command(
        "ps", "--status", "running", "--services", REDIS_SERVICE
    )


def _health_command() -> list[str]:
    return _compose_command(
        "exec", "-T", REDIS_SERVICE, "/usr/local/bin/redis-healthcheck"
    )


def _archive_command() -> list[str]:
    return _compose_command(
        "run",
        "--rm",
        "--no-deps",
        "-T",
        "--entrypoint",
        "tar",
        REDIS_SERVICE,
        "-C",
        "/data",
        "-cf",
        "-",
        ".",
    )


def _restore_command() -> list[str]:
    clear_then_extract = (
        "find /data -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + "
        "&& tar -C /data -xf -"
    )
    return _compose_command(
        "run",
        "--rm",
        "--no-deps",
        "-T",
        "--entrypoint",
        "sh",
        REDIS_SERVICE,
        "-euc",
        clear_then_extract,
    )


def _redis_is_running() -> bool:
    result = subprocess.run(
        _status_command(),
        check=True,
        capture_output=True,
        text=True,
    )
    return REDIS_SERVICE in {
        line.strip() for line in (result.stdout or "").splitlines()
    }


def _restore_running_redis_after_backup() -> None:
    subprocess.run(
        _start_command(),
        check=True,
        capture_output=True,
        text=True,
    )
    if not _redis_is_running():
        raise RuntimeError("Redis did not resume after backup")
    subprocess.run(
        _health_command(),
        check=True,
        capture_output=True,
        text=True,
    )


def _write_encrypted_archive(path: Path, key: bytes) -> None:
    temporary_path: Path | None = None
    process: subprocess.Popen[bytes] | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as destination:
            temporary_path = Path(destination.name)
            process = subprocess.Popen(_archive_command(), stdout=subprocess.PIPE)
            if process.stdout is None:
                raise RuntimeError("Redis archive stdout pipe is unavailable")
            try:
                encrypt_stream(
                    process.stdout,
                    destination,
                    key,
                    logical_name=LOGICAL_NAME,
                    source_database=SOURCE_VOLUME,
                )
            except BaseException:
                process.kill()
                process.wait()
                raise
            finally:
                process.stdout.close()
            return_code = process.wait()
            process = None
            if return_code != 0:
                raise subprocess.CalledProcessError(return_code, _archive_command())
            destination.flush()
            os.fsync(destination.fileno())
        if temporary_path.stat().st_size <= 0:
            raise ValueError("Redis backup artifact is empty")
        publishing_path = temporary_path
        temporary_path = None
        publish_bundle_write_once_file(publishing_path, path)
    finally:
        if process is not None:
            process.kill()
            process.wait()
        discard_claimed_temporary_file(temporary_path)


def backup_release(
    output_dir: Path | str,
    *,
    key_file: Path | str,
    release_tag: str,
    release_commit: str,
    migration_head: str,
    container_manifest_sha256: str,
    postgres_manifest: Path | str,
    recovery_set: str,
) -> Path:
    """Stop Redis and publish a write-once encrypted volume recovery point."""

    _validate_production_docker_environment()
    directory_claim = create_write_once_directory(output_dir)
    directory = directory_claim.path
    directory_claimed = True
    rollback_unconfirmed = False
    redis_was_running = False
    try:
        binding = _release_binding(
            release_tag=release_tag,
            release_commit=release_commit,
            migration_head=migration_head,
            container_manifest_sha256=container_manifest_sha256,
        )
        reviewed_recovery_set = _require_recovery_set(recovery_set)
        postgres_sha256 = _postgres_manifest_sha256(postgres_manifest)
        key = load_key_file(key_file)

        redis_was_running = _redis_is_running()
        if redis_was_running:
            subprocess.run(
                _stop_command(),
                check=True,
                capture_output=True,
                text=True,
            )
            if _redis_is_running():
                raise RuntimeError("Redis did not stop before backup")

        artifact_path = directory / ARTIFACT_NAME
        _write_encrypted_archive(artifact_path, key)
        artifact_sha256, artifact_size = _hash_file(
            artifact_path, label="Redis backup artifact"
        )
        manifest: dict[str, object] = {
            "schema_version": MANIFEST_SCHEMA,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "artifact": ARTIFACT_NAME,
            "sha256": artifact_sha256,
            "size_bytes": artifact_size,
            "algorithm": BACKUP_ENCRYPTION_ALGORITHM,
            "format_version": BACKUP_ENCRYPTION_FORMAT,
            "key_id": key_id(key),
            **binding,
            "postgres_manifest_sha256": postgres_sha256,
            "recovery_set": reviewed_recovery_set,
        }
        manifest[MANIFEST_HMAC_FIELD] = _manifest_hmac_sha256(manifest, key)
        manifest_path = directory / MANIFEST_NAME
        temporary_manifest = write_fsynced_temporary_bytes(
            manifest_path,
            (
                json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True)
                + "\n"
            ).encode("utf-8"),
        )
        publish_bundle_write_once_file(temporary_manifest, manifest_path)
        return manifest_path
    except BaseException as error:
        rollback_unconfirmed = not cleanup_created_directory_after_failure(
            directory_claim,
            error,
        )
        directory_claimed = False
        raise
    finally:
        if redis_was_running:
            try:
                _restore_running_redis_after_backup()
            except BaseException as restart_error:
                cleanup_confirmed = not rollback_unconfirmed
                if directory_claimed:
                    cleanup_confirmed = cleanup_created_directory_after_failure(
                        directory_claim,
                        restart_error,
                    )
                message = "Redis restart could not be confirmed"
                if not cleanup_confirmed:
                    message += f"; {CLEANUP_UNCONFIRMED_NOTE}"
                fatal_error = RedisBackupFatalError(message)
                if not cleanup_confirmed:
                    fatal_error.add_note(CLEANUP_UNCONFIRMED_NOTE)
                raise fatal_error from restart_error


def _verify_release_backup_details(
    input_dir: Path | str,
    *,
    key_file: Path | str,
    release_tag: str,
    release_commit: str,
    migration_head: str,
    container_manifest_sha256: str,
    postgres_manifest_sha256: str,
    recovery_set: str,
) -> tuple[
    dict[str, object],
    datetime,
    str,
    dict[str, StableFileIdentity],
    bytes,
]:
    """Authenticate one exact release-bound Redis recovery point."""

    expected_binding = _release_binding(
        release_tag=release_tag,
        release_commit=release_commit,
        migration_head=migration_head,
        container_manifest_sha256=container_manifest_sha256,
    )
    expected_postgres_sha256 = _require_sha256(
        postgres_manifest_sha256,
        label="PostgreSQL manifest SHA-256",
    )
    expected_recovery_set = _require_recovery_set(recovery_set)
    directory = Path(input_dir)
    identities = require_exact_regular_files(directory, BACKUP_BUNDLE_LEAVES)
    key = load_key_file(key_file)
    manifest, manifest_bytes = _read_manifest(
        directory / MANIFEST_NAME,
        expected_identity=identities[MANIFEST_NAME],
    )
    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        raise ValueError("Redis release manifest schema v1 is required")
    if set(manifest) != _MANIFEST_FIELDS:
        raise ValueError("Redis release manifest contains unexpected fields")
    actual_mac = manifest.get(MANIFEST_HMAC_FIELD)
    if not isinstance(actual_mac, str) or not _SHA256.fullmatch(actual_mac):
        raise ValueError("Redis release manifest authentication is invalid")
    expected_mac = _manifest_hmac_sha256(manifest, key)
    if not hmac.compare_digest(actual_mac, expected_mac):
        raise ValueError("Redis release manifest authentication failed")

    created_at = manifest.get("created_at")
    if not isinstance(created_at, str):
        raise ValueError("Redis backup creation time is invalid")
    try:
        parsed_created_at = datetime.fromisoformat(created_at)
    except ValueError as error:
        raise ValueError("Redis backup creation time is invalid") from error
    if parsed_created_at.tzinfo is None:
        raise ValueError("Redis backup creation time is invalid")

    for field in _RELEASE_FIELDS:
        if manifest.get(field) != expected_binding[field]:
            raise ValueError(f"Redis release binding mismatch: {field}")
    if manifest.get("postgres_manifest_sha256") != expected_postgres_sha256:
        raise ValueError("Redis PostgreSQL manifest binding mismatch")
    if manifest.get("recovery_set") != expected_recovery_set:
        raise ValueError("Redis recovery set binding mismatch")
    if manifest.get("artifact") != ARTIFACT_NAME:
        raise ValueError("Redis backup artifact name is invalid")
    if manifest.get("algorithm") != BACKUP_ENCRYPTION_ALGORITHM:
        raise ValueError("Redis backup encryption algorithm is invalid")
    if manifest.get("format_version") != BACKUP_ENCRYPTION_FORMAT:
        raise ValueError("Redis backup encryption format is invalid")
    if manifest.get("key_id") != key_id(key):
        raise ValueError("Redis backup encryption key mismatch")
    size_bytes = manifest.get("size_bytes")
    artifact_sha256 = manifest.get("sha256")
    if (
        not isinstance(size_bytes, int)
        or isinstance(size_bytes, bool)
        or size_bytes <= 0
        or not isinstance(artifact_sha256, str)
        or not _SHA256.fullmatch(artifact_sha256)
    ):
        raise ValueError("Redis backup artifact metadata is invalid")
    artifact_path = directory / ARTIFACT_NAME
    try:
        with open_stable_binary(
            artifact_path,
            expected_identity=identities[ARTIFACT_NAME],
        ) as (artifact_stream, metadata):
            digest = hashlib.sha256()
            actual_size = 0
            while chunk := artifact_stream.read(1024 * 1024):
                digest.update(chunk)
                actual_size += len(chunk)
            if actual_size != size_bytes or not hmac.compare_digest(
                digest.hexdigest(), artifact_sha256
            ):
                raise ValueError("Redis backup artifact integrity check failed")
            artifact_stream.seek(0)
            decrypt_stream(
                artifact_stream,
                None,
                key,
                metadata.st_size,
                expected_logical_name=LOGICAL_NAME,
                expected_source_database=SOURCE_VOLUME,
            )
    except StableFileError as error:
        raise ValueError("Redis backup artifact cannot be opened safely") from error
    if require_exact_regular_files(directory, BACKUP_BUNDLE_LEAVES) != identities:
        raise ValueError("Redis backup bundle changed during verification")
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    return manifest, parsed_created_at, manifest_sha256, identities, key


def verify_release_backup(
    input_dir: Path | str,
    *,
    key_file: Path | str,
    release_tag: str,
    release_commit: str,
    migration_head: str,
    container_manifest_sha256: str,
    postgres_manifest_sha256: str,
    recovery_set: str,
    _include_created_at: bool = False,
    _include_manifest_sha256: bool = False,
) -> (
    dict[str, object]
    | tuple[dict[str, object], datetime]
    | tuple[dict[str, object], str]
    | tuple[dict[str, object], datetime, str]
):
    manifest, parsed_created_at, manifest_sha256, _, _ = (
        _verify_release_backup_details(
            input_dir,
            key_file=key_file,
            release_tag=release_tag,
            release_commit=release_commit,
            migration_head=migration_head,
            container_manifest_sha256=container_manifest_sha256,
            postgres_manifest_sha256=postgres_manifest_sha256,
            recovery_set=recovery_set,
        )
    )
    if _include_created_at:
        if _include_manifest_sha256:
            return manifest, parsed_created_at, manifest_sha256
        return manifest, parsed_created_at
    if _include_manifest_sha256:
        return manifest, manifest_sha256
    return manifest


def _validate_tar_member(member: tarfile.TarInfo) -> None:
    name = member.name
    if not name or "\x00" in name or "\\" in name:
        raise ValueError("Redis tar entry path is invalid")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("Redis tar entry escapes the data directory")
    if member.issym() or member.islnk():
        raise ValueError("Redis tar links are not allowed")
    if not member.isdir() and not member.isreg():
        raise ValueError("Redis tar special entries are not allowed")


def _validate_tar_archive(path: Path, key: bytes) -> None:
    read_descriptor, write_descriptor = os.pipe()
    producer_error: list[BaseException] = []

    def decrypt() -> None:
        try:
            with os.fdopen(write_descriptor, "wb") as destination:
                decrypt_file_to_stream(
                    path,
                    destination,
                    key,
                    expected_logical_name=LOGICAL_NAME,
                    expected_source_database=SOURCE_VOLUME,
                )
        except BaseException as error:
            producer_error.append(error)

    producer = Thread(target=decrypt, name="redis-backup-tar-validator", daemon=False)
    producer.start()
    validation_error: BaseException | None = None
    entry_count = 0
    try:
        with os.fdopen(read_descriptor, "rb") as source:
            try:
                with tarfile.open(fileobj=source, mode="r|*") as archive:
                    for member in archive:
                        entry_count += 1
                        if entry_count > _TERMINAL_TAR_ENTRY_LIMIT:
                            raise ValueError("Redis tar contains too many entries")
                        _validate_tar_member(member)
            except (tarfile.TarError, OSError, ValueError) as error:
                validation_error = ValueError("Redis tar safety validation failed")
                validation_error.__cause__ = error
    finally:
        producer.join()
    if validation_error is not None:
        raise validation_error
    if producer_error:
        raise ValueError("Redis tar safety validation failed") from producer_error[0]
    if entry_count == 0:
        raise ValueError("Redis tar archive is empty")


def _stage_authenticated_artifact(
    source_path: Path,
    key: bytes,
    *,
    expected_sha256: str,
    expected_size: int,
    expected_identity: StableFileIdentity,
) -> Path:
    """Copy one verified ciphertext inode so destructive restore cannot race its path."""

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        source_descriptor = os.open(source_path, flags)
    except OSError as error:
        raise ValueError("Redis backup artifact cannot be opened safely") from error
    staged_path: Path | None = None
    try:
        source_metadata = os.fstat(source_descriptor)
        try:
            named_metadata = source_path.lstat()
        except OSError as error:
            raise ValueError(
                "Redis backup artifact cannot be opened safely"
            ) from error
        if (
            not stat.S_ISREG(source_metadata.st_mode)
            or not stat.S_ISREG(named_metadata.st_mode)
            or stat.S_ISLNK(named_metadata.st_mode)
            or bool(
                getattr(named_metadata, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            )
            or stable_file_identity(source_metadata) != expected_identity
            or stable_file_identity(named_metadata) != expected_identity
        ):
            raise ValueError("Redis backup artifact must be a regular file")
        digest = hashlib.sha256()
        size_bytes = 0
        with (
            os.fdopen(source_descriptor, "rb", closefd=False) as source,
            tempfile.NamedTemporaryFile(
                prefix="email-platform-redis-restore-",
                suffix=".enc",
                delete=False,
            ) as destination,
        ):
            staged_path = Path(destination.name)
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                size_bytes += len(chunk)
                destination.write(chunk)
        if size_bytes != expected_size or not hmac.compare_digest(
            digest.hexdigest(), expected_sha256
        ):
            raise ValueError("Redis backup artifact changed after verification")
        authenticate_file(
            staged_path,
            key,
            expected_logical_name=LOGICAL_NAME,
            expected_source_database=SOURCE_VOLUME,
        )
        result = staged_path
        staged_path = None
        return result
    finally:
        os.close(source_descriptor)
        if staged_path is not None:
            staged_path.unlink(missing_ok=True)


def _restore_postgres_sha256(
    *,
    postgres_manifest: Path | str | None,
    postgres_manifest_sha256: str | None,
) -> str:
    if (postgres_manifest is None) == (postgres_manifest_sha256 is None):
        raise ValueError(
            "restore requires exactly one PostgreSQL manifest path or SHA-256"
        )
    if postgres_manifest is not None:
        return _postgres_manifest_sha256(postgres_manifest)
    assert postgres_manifest_sha256 is not None
    return _require_sha256(
        postgres_manifest_sha256,
        label="PostgreSQL manifest SHA-256",
    )


def restore_release(
    input_dir: Path | str,
    *,
    key_file: Path | str,
    release_tag: str,
    release_commit: str,
    migration_head: str,
    container_manifest_sha256: str,
    recovery_set: str,
    confirm_release_tag: str,
    postgres_manifest: Path | str | None = None,
    postgres_manifest_sha256: str | None = None,
) -> None:
    """Authenticate, validate, clear, and stream-restore the stopped Redis volume."""

    _validate_production_docker_environment()
    if confirm_release_tag != release_tag:
        raise ValueError("confirm_release_tag must exactly match release_tag")
    reviewed_postgres_sha256 = _restore_postgres_sha256(
        postgres_manifest=postgres_manifest,
        postgres_manifest_sha256=postgres_manifest_sha256,
    )
    manifest, _, _, identities, key = _verify_release_backup_details(
        input_dir,
        key_file=key_file,
        release_tag=release_tag,
        release_commit=release_commit,
        migration_head=migration_head,
        container_manifest_sha256=container_manifest_sha256,
        postgres_manifest_sha256=reviewed_postgres_sha256,
        recovery_set=recovery_set,
    )
    artifact_path = Path(input_dir) / ARTIFACT_NAME
    staged_artifact = _stage_authenticated_artifact(
        artifact_path,
        key,
        expected_sha256=str(manifest["sha256"]),
        expected_size=int(manifest["size_bytes"]),
        expected_identity=identities[ARTIFACT_NAME],
    )
    try:
        _validate_tar_archive(staged_artifact, key)
        if require_exact_regular_files(
            Path(input_dir), BACKUP_BUNDLE_LEAVES
        ) != identities:
            raise ValueError("Redis backup bundle changed before restore")
        if _redis_is_running():
            raise ValueError("Redis must be stopped before restore")
        if require_exact_regular_files(
            Path(input_dir), BACKUP_BUNDLE_LEAVES
        ) != identities:
            raise ValueError("Redis backup bundle changed before restore")

        command = _restore_command()
        process = subprocess.Popen(command, stdin=subprocess.PIPE)
        if process.stdin is None:
            process.kill()
            process.wait()
            raise RuntimeError("Redis restore stdin pipe is unavailable")
        try:
            decrypt_file_to_stream(
                staged_artifact,
                process.stdin,
                key,
                expected_logical_name=LOGICAL_NAME,
                expected_source_database=SOURCE_VOLUME,
            )
            process.stdin.close()
            return_code = process.wait()
            if return_code != 0:
                raise subprocess.CalledProcessError(return_code, command)
        except BaseException:
            if process.poll() is None:
                process.kill()
            process.wait()
            raise
    finally:
        staged_artifact.unlink(missing_ok=True)


def _add_release_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--migration-head", required=True)
    parser.add_argument("--container-manifest-sha256", required=True)
    parser.add_argument("--recovery-set", required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    backup = commands.add_parser("backup-release")
    backup.add_argument("--output-dir", required=True)
    backup.add_argument("--postgres-manifest", required=True)
    _add_release_arguments(backup)

    verify = commands.add_parser("verify-release")
    verify.add_argument("--input-dir", required=True)
    verify.add_argument("--postgres-manifest-sha256", required=True)
    _add_release_arguments(verify)

    restore = commands.add_parser("restore-release")
    restore.add_argument("--input-dir", required=True)
    postgres = restore.add_mutually_exclusive_group(required=True)
    postgres.add_argument("--postgres-manifest")
    postgres.add_argument("--postgres-manifest-sha256")
    restore.add_argument("--confirm-release-tag", required=True)
    _add_release_arguments(restore)
    return parser


def _run_cli_command(args: argparse.Namespace) -> int:
    common = {
        "key_file": args.key_file,
        "release_tag": args.release_tag,
        "release_commit": args.release_commit,
        "migration_head": args.migration_head,
        "container_manifest_sha256": args.container_manifest_sha256,
        "recovery_set": args.recovery_set,
    }
    if args.command == "backup-release":
        print(
            backup_release(
                args.output_dir,
                postgres_manifest=args.postgres_manifest,
                **common,
            )
        )
        return 0
    if args.command == "verify-release":
        manifest = verify_release_backup(
            args.input_dir,
            postgres_manifest_sha256=args.postgres_manifest_sha256,
            **common,
        )
        print(json.dumps(manifest, ensure_ascii=False, sort_keys=True))
        return 0
    if args.command == "restore-release":
        restore_release(
            args.input_dir,
            postgres_manifest=args.postgres_manifest,
            postgres_manifest_sha256=args.postgres_manifest_sha256,
            confirm_release_tag=args.confirm_release_tag,
            **common,
        )
        return 0
    raise AssertionError(f"Unhandled command: {args.command}")


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _run_cli_command(args)
    except Exception as error:
        if isinstance(error, RedisBackupFatalError):
            label = "Redis restart could not be confirmed"
        else:
            label = f"{args.command} failed"
        suffix = (
            f"; {CLEANUP_UNCONFIRMED_NOTE}" if cleanup_unconfirmed(error) else ""
        )
        print(f"redis-maintenance-error: {label}{suffix}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
