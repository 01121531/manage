"""PostgreSQL backup, restore, and drill helpers for the compose stack."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from scripts.backup_crypto import (
    ALGORITHM as BACKUP_ENCRYPTION_ALGORITHM,
    FORMAT_VERSION as BACKUP_ENCRYPTION_FORMAT,
    decrypt_stream,
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
    prepare_write_once_file,
    publish_bundle_write_once_file,
    publish_write_once_file,
    require_exact_regular_files,
    write_fsynced_temporary_bytes,
)
from scripts.external_json import (
    StableFileError,
    StableFileIdentity,
    load_unique_json_with_bytes,
    open_stable_binary,
)
from scripts.production_docker_environment import (
    validate_production_docker_environment as _validate_production_docker_environment,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_COMPOSE_FILE = REPOSITORY_ROOT / "docker-compose.yml"
PRODUCTION_ENV_FILE = REPOSITORY_ROOT / ".env"
PRODUCTION_COMPOSE_PROJECT = "email-platform"
_SAFE_DB_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RELEASE_TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_RELEASE_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_MIGRATION_HEAD = re.compile(r"^[0-9]{4}_[A-Za-z0-9_]+$")
_MAX_MANIFEST_BYTES = 64 * 1024
BACKUP_MANIFEST_NAME = "manifest.json"
BACKUP_MANIFEST_SCHEMA = 3
BACKUP_RELEASE_MANIFEST_SCHEMA = 5
BACKUP_MANIFEST_HMAC_FIELD = "manifest_hmac_sha256"
BACKUP_MANIFEST_HKDF_INFO = b"email-platform/postgres-backup-manifest/v5/hmac-sha256"
BACKUP_BUNDLE_DATABASES = ("platform", "keycloak")
BACKUP_BUNDLE_LEAVES = frozenset(
    {BACKUP_MANIFEST_NAME, "platform.dump.enc", "keycloak.dump.enc"}
)
RESTORE_OWNER_ENV = {
    "platform": "POSTGRES_USER",
    "keycloak": "KEYCLOAK_DB_USER",
}
RELEASE_BINDING_FIELDS = (
    "release_tag",
    "release_commit",
    "migration_head",
    "container_manifest_sha256",
)
CRITICAL_TABLES = {
    "platform": ("users", "devices", "audit_events"),
    "keycloak": (
        "realm",
        "user_entity",
        "credential",
        "event_entity",
        "admin_event_entity",
    ),
}


@dataclass(frozen=True)
class BackupResult:
    path: Path
    sha256: str
    size_bytes: int
    key_id: str


@dataclass(frozen=True)
class BackupBundleResult:
    directory: Path
    manifest_path: Path
    databases: dict[str, BackupResult]


@dataclass(frozen=True)
class DrillBundleResult:
    bundle: BackupBundleResult
    critical_row_counts: dict[str, dict[str, dict[str, int]]]


def _require_safe_db_name(value: str) -> str:
    candidate = value.strip()
    if not candidate or not _SAFE_DB_NAME.fullmatch(candidate):
        raise ValueError(
            "database name must contain only letters, digits, and underscores"
        )
    return candidate


def _require_restore_owner_env(value: str) -> str:
    if value not in set(RESTORE_OWNER_ENV.values()):
        raise ValueError(
            "restore owner must use an approved database role environment variable"
        )
    return value


def _compose_exec(service: str, shell_command: str) -> list[str]:
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
        "exec",
        "-T",
        service,
        "sh",
        "-lc",
        shell_command,
    ]


def backup_command(
    *,
    database: str | None = None,
    service: str = "postgres",
) -> list[str]:
    database_arg = '"$POSTGRES_DB"' if database is None else f'"{_require_safe_db_name(database)}"'
    return _compose_exec(
        service,
        f'pg_dump -Fc --no-owner --no-privileges -U "$POSTGRES_USER" {database_arg}',
    )


def restore_command(
    *,
    target_db: str,
    service: str = "postgres",
    owner_env: str = "POSTGRES_USER",
) -> list[str]:
    db_name = _require_safe_db_name(target_db)
    owner = _require_restore_owner_env(owner_env)
    return _compose_exec(
        service,
        f'pg_restore --clean --if-exists --no-owner --no-privileges '
        f'--role="${owner}" -U "$POSTGRES_USER" -d "{db_name}"',
    )


def create_database_command(
    *,
    target_db: str,
    service: str = "postgres",
    owner_env: str = "POSTGRES_USER",
) -> list[str]:
    db_name = _require_safe_db_name(target_db)
    owner = _require_restore_owner_env(owner_env)
    return _compose_exec(
        service,
        f'createdb -U "$POSTGRES_USER" --owner="${owner}" "{db_name}"',
    )


def drop_database_command(*, target_db: str, service: str = "postgres") -> list[str]:
    db_name = _require_safe_db_name(target_db)
    return _compose_exec(
        service,
        f'dropdb -U "$POSTGRES_USER" --if-exists "{db_name}"',
    )


def count_tables_command(*, target_db: str, service: str = "postgres") -> list[str]:
    db_name = _require_safe_db_name(target_db)
    return _compose_exec(
        service,
        (
            'psql -U "$POSTGRES_USER" -d "{db}" -tAc '
            "\"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'\""
        ).format(db=db_name),
    )


def count_tables(*, target_db: str, service: str = "postgres") -> int:
    _validate_production_docker_environment()
    result = subprocess.run(
        count_tables_command(target_db=target_db, service=service),
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        count = int(result.stdout.strip())
    except (AttributeError, ValueError) as error:
        raise ValueError(f"invalid table count for database {target_db}") from error
    if count <= 0:
        raise ValueError(f"database has no public tables: {target_db}")
    return count


def count_rows_command(
    *,
    target_db: str,
    table: str,
    service: str = "postgres",
) -> list[str]:
    db_name = _require_safe_db_name(target_db)
    allowed_tables = {name for names in CRITICAL_TABLES.values() for name in names}
    if table not in allowed_tables:
        raise ValueError(f"table is not in the disaster-recovery whitelist: {table}")
    return _compose_exec(
        service,
        f'psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "{db_name}" '
        f'-tAc \'SELECT COUNT(*) FROM public."{table}"\'',
    )


def count_rows(
    *,
    target_db: str,
    table: str,
    service: str = "postgres",
) -> int:
    _validate_production_docker_environment()
    result = subprocess.run(
        count_rows_command(target_db=target_db, table=table, service=service),
        check=True,
        capture_output=True,
        text=True,
    )
    try:
        count = int(result.stdout.strip())
    except (AttributeError, ValueError) as error:
        raise ValueError(f"invalid row count for {target_db}.public.{table}") from error
    if count < 0:
        raise ValueError(f"invalid row count for {target_db}.public.{table}")
    return count


def critical_row_counts(
    *,
    logical_name: str,
    target_db: str,
    service: str = "postgres",
) -> dict[str, int]:
    _validate_production_docker_environment()
    try:
        tables = CRITICAL_TABLES[logical_name]
    except KeyError as error:
        raise ValueError(f"unknown bundle database: {logical_name}") from error
    return {
        table: count_rows(target_db=target_db, table=table, service=service)
        for table in tables
    }


def backup_database(
    output_path: Path | str,
    *,
    key_file: Path | str,
    database: str | None = None,
    logical_name: str = "single",
    service: str = "postgres",
    _bundle_owned: bool = False,
    _loaded_key: bytes | None = None,
) -> BackupResult:
    _validate_production_docker_environment()
    path = prepare_write_once_file(output_path)
    key = load_key_file(key_file) if _loaded_key is None else _loaded_key
    source_database = "POSTGRES_DB" if database is None else _require_safe_db_name(database)
    command = backup_command(database=database, service=service)
    temporary_path: Path | None = None
    process: subprocess.Popen[bytes] | None = None
    digest = hashlib.sha256()
    size_bytes = 0
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            process = subprocess.Popen(command, stdout=subprocess.PIPE)
            if process.stdout is None:
                raise RuntimeError("pg_dump stdout pipe is unavailable")
            try:
                encrypt_stream(
                    process.stdout,
                    stream,
                    key,
                    logical_name=logical_name,
                    source_database=source_database,
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
                raise subprocess.CalledProcessError(return_code, command)
            stream.flush()
            os.fsync(stream.fileno())
            stream.seek(0)
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
                size_bytes += len(chunk)
        if size_bytes <= 0:
            raise ValueError(f"backup is empty: {path}")
        publishing_path = temporary_path
        if _bundle_owned:
            temporary_path = None
            publish_bundle_write_once_file(publishing_path, path)
        else:
            publish_write_once_file(temporary_path, path)
            temporary_path = None
    finally:
        if process is not None:
            process.kill()
            process.wait()
        discard_claimed_temporary_file(temporary_path)
    return BackupResult(
        path=path,
        sha256=digest.hexdigest(),
        size_bytes=size_bytes,
        key_id=key_id(key),
    )


def restore_database(
    input_path: Path | str,
    *,
    key_file: Path | str,
    target_db: str,
    expected_logical_name: str = "single",
    expected_source_database: str = "POSTGRES_DB",
    service: str = "postgres",
    owner_env: str = "POSTGRES_USER",
    _expected_identity: StableFileIdentity | None = None,
    _expected_sha256: str | None = None,
    _loaded_key: bytes | None = None,
) -> None:
    _validate_production_docker_environment()
    path = Path(input_path)
    key = load_key_file(key_file) if _loaded_key is None else _loaded_key
    command = restore_command(
        target_db=target_db,
        service=service,
        owner_env=owner_env,
    )
    try:
        with open_stable_binary(
            path,
            expected_identity=_expected_identity,
        ) as (encrypted_stream, metadata):
            encrypted_size = metadata.st_size
            if _expected_sha256 is not None:
                digest = hashlib.sha256()
                for chunk in iter(lambda: encrypted_stream.read(1024 * 1024), b""):
                    digest.update(chunk)
                if not hmac.compare_digest(digest.hexdigest(), _expected_sha256):
                    raise ValueError("backup artifact changed after verification")
                encrypted_stream.seek(0)
            decrypt_stream(
                encrypted_stream,
                None,
                key,
                encrypted_size,
                expected_logical_name=expected_logical_name,
                expected_source_database=expected_source_database,
            )
            encrypted_stream.seek(0)
            process = subprocess.Popen(command, stdin=subprocess.PIPE)
            if process.stdin is None:
                process.kill()
                process.wait()
                raise RuntimeError("pg_restore stdin pipe is unavailable")
            try:
                decrypt_stream(
                    encrypted_stream,
                    process.stdin,
                    key,
                    encrypted_size,
                    expected_logical_name=expected_logical_name,
                    expected_source_database=expected_source_database,
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
    except StableFileError as error:
        raise ValueError("backup artifact cannot be opened safely") from error


def run_backup(
    output_path: Path | str,
    *,
    key_file: Path | str,
    service: str = "postgres",
) -> BackupResult:
    _validate_production_docker_environment()
    return backup_database(output_path, key_file=key_file, service=service)


def _artifact_metadata(result: BackupResult, *, database: str) -> dict[str, object]:
    return {
        "database": database,
        "artifact": result.path.name,
        "sha256": result.sha256,
        "size_bytes": result.size_bytes,
        "algorithm": BACKUP_ENCRYPTION_ALGORITHM,
        "format_version": BACKUP_ENCRYPTION_FORMAT,
        "key_id": result.key_id,
    }


def _release_binding(
    *,
    release_tag: str | None,
    release_commit: str | None,
    migration_head: str | None,
    container_manifest_sha256: str | None,
) -> dict[str, str] | None:
    values = {
        "release_tag": release_tag,
        "release_commit": release_commit,
        "migration_head": migration_head,
        "container_manifest_sha256": container_manifest_sha256,
    }
    if all(value is None for value in values.values()):
        return None
    if any(value is None for value in values.values()):
        raise ValueError("release binding requires all four fields")
    if not all(isinstance(value, str) for value in values.values()):
        raise ValueError("release binding fields must be strings")
    binding = {key: value for key, value in values.items() if isinstance(value, str)}
    if not _RELEASE_TAG.fullmatch(binding["release_tag"]):
        raise ValueError("invalid release tag")
    if not _RELEASE_COMMIT.fullmatch(binding["release_commit"]):
        raise ValueError("invalid release commit")
    if not _MIGRATION_HEAD.fullmatch(binding["migration_head"]):
        raise ValueError("invalid migration head")
    if not _SHA256.fullmatch(binding["container_manifest_sha256"]):
        raise ValueError("invalid container manifest SHA-256")
    return binding


def _canonical_manifest_bytes(manifest: dict[str, object]) -> bytes:
    authenticated = {
        field: value
        for field, value in manifest.items()
        if field != BACKUP_MANIFEST_HMAC_FIELD
    }
    return json.dumps(
        authenticated,
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
        info=BACKUP_MANIFEST_HKDF_INFO,
    ).derive(key)
    return hmac.new(
        mac_key,
        _canonical_manifest_bytes(manifest),
        hashlib.sha256,
    ).hexdigest()


def backup_bundle(
    output_dir: Path | str,
    *,
    key_file: Path | str,
    platform_db: str,
    keycloak_db: str,
    service: str = "postgres",
    release_tag: str | None = None,
    release_commit: str | None = None,
    migration_head: str | None = None,
    container_manifest_sha256: str | None = None,
) -> BackupBundleResult:
    _validate_production_docker_environment()
    release_binding = _release_binding(
        release_tag=release_tag,
        release_commit=release_commit,
        migration_head=migration_head,
        container_manifest_sha256=container_manifest_sha256,
    )
    database_names = {
        "platform": _require_safe_db_name(platform_db),
        "keycloak": _require_safe_db_name(keycloak_db),
    }
    directory_claim = create_write_once_directory(output_dir)
    directory = directory_claim.path
    manifest_path = directory / BACKUP_MANIFEST_NAME
    artifact_paths = {
        logical_name: directory / f"{logical_name}.dump.enc"
        for logical_name in BACKUP_BUNDLE_DATABASES
    }
    results: dict[str, BackupResult] = {}
    try:
        key = load_key_file(key_file)
        for logical_name, database_name in database_names.items():
            results[logical_name] = backup_database(
                artifact_paths[logical_name],
                key_file=key_file,
                database=database_name,
                logical_name=logical_name,
                service=service,
                _bundle_owned=True,
                _loaded_key=key,
            )
        manifest: dict[str, object] = {
            "schema_version": (
                BACKUP_RELEASE_MANIFEST_SCHEMA
                if release_binding is not None
                else BACKUP_MANIFEST_SCHEMA
            ),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "databases": {
                logical_name: _artifact_metadata(
                    results[logical_name], database=database_names[logical_name]
                )
                for logical_name in BACKUP_BUNDLE_DATABASES
            },
        }
        if release_binding is not None:
            manifest.update(release_binding)
            manifest[BACKUP_MANIFEST_HMAC_FIELD] = _manifest_hmac_sha256(
                manifest,
                key,
            )
        temporary_manifest = write_fsynced_temporary_bytes(
            manifest_path,
            (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode(
                "utf-8"
            ),
        )
        publish_bundle_write_once_file(temporary_manifest, manifest_path)
    except BaseException as error:
        cleanup_created_directory_after_failure(directory_claim, error)
        raise
    return BackupBundleResult(
        directory=directory,
        manifest_path=manifest_path,
        databases=results,
    )


def _verify_bundle_details(
    input_dir: Path | str,
    *,
    key_file: Path | str,
) -> tuple[
    dict[str, object],
    dict[str, dict[str, object]],
    str,
    dict[str, StableFileIdentity],
    bytes,
]:
    directory = Path(input_dir)
    identities = require_exact_regular_files(directory, BACKUP_BUNDLE_LEAVES)
    key = load_key_file(key_file)
    manifest_path = directory / BACKUP_MANIFEST_NAME
    try:
        manifest, manifest_bytes = load_unique_json_with_bytes(
            manifest_path,
            max_bytes=_MAX_MANIFEST_BYTES,
            expected_identity=identities[BACKUP_MANIFEST_NAME],
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid backup manifest: {error}") from error
    if not isinstance(manifest, dict):
        raise ValueError("unsupported backup manifest schema")
    schema_version = manifest.get("schema_version")
    if schema_version == 4:
        raise ValueError(
            "unauthenticated release-bound backup schema v4 is unsupported"
        )
    if schema_version not in {
        BACKUP_MANIFEST_SCHEMA,
        BACKUP_RELEASE_MANIFEST_SCHEMA,
    }:
        raise ValueError("unsupported backup manifest schema")
    release_fields_present = {field for field in RELEASE_BINDING_FIELDS if field in manifest}
    expected_manifest_fields = {"schema_version", "created_at", "databases"}
    if schema_version == BACKUP_MANIFEST_SCHEMA:
        if release_fields_present:
            raise ValueError("generic encrypted backup manifest cannot contain release binding")
    else:
        expected_manifest_fields.update(RELEASE_BINDING_FIELDS)
        expected_manifest_fields.add(BACKUP_MANIFEST_HMAC_FIELD)
        if BACKUP_MANIFEST_HMAC_FIELD not in manifest:
            raise ValueError("release-bound backup manifest authentication is missing")
        if release_fields_present != set(RELEASE_BINDING_FIELDS):
            raise ValueError(
                "release-bound encrypted backup manifest requires all release binding fields"
            )
    if set(manifest) != expected_manifest_fields:
        raise ValueError("backup manifest contains unexpected fields")
    if schema_version == BACKUP_RELEASE_MANIFEST_SCHEMA:
        actual_mac = manifest.get(BACKUP_MANIFEST_HMAC_FIELD)
        if not isinstance(actual_mac, str) or not _SHA256.fullmatch(actual_mac):
            raise ValueError("invalid release-bound backup manifest authentication")
        expected_mac = _manifest_hmac_sha256(manifest, key)
        if not hmac.compare_digest(actual_mac, expected_mac):
            raise ValueError("release-bound backup manifest authentication failed")
        _release_binding(
            release_tag=manifest.get("release_tag"),
            release_commit=manifest.get("release_commit"),
            migration_head=manifest.get("migration_head"),
            container_manifest_sha256=manifest.get("container_manifest_sha256"),
        )
    created_at = manifest.get("created_at")
    if not isinstance(created_at, str):
        raise ValueError("invalid backup manifest creation time")
    try:
        parsed_created_at = datetime.fromisoformat(created_at)
    except ValueError as error:
        raise ValueError("invalid backup manifest creation time") from error
    if parsed_created_at.tzinfo is None:
        raise ValueError("invalid backup manifest creation time")
    databases = manifest.get("databases")
    if not isinstance(databases, dict) or set(databases) != set(BACKUP_BUNDLE_DATABASES):
        raise ValueError("backup manifest must contain platform and keycloak databases")
    verified: dict[str, dict[str, object]] = {}
    for logical_name in BACKUP_BUNDLE_DATABASES:
        entry = databases.get(logical_name)
        if not isinstance(entry, dict):
            raise ValueError(f"invalid manifest entry: {logical_name}")
        if set(entry) != {
            "database",
            "artifact",
            "sha256",
            "size_bytes",
            "algorithm",
            "format_version",
            "key_id",
        }:
            raise ValueError(f"unexpected manifest entry fields: {logical_name}")
        database = entry.get("database")
        artifact = entry.get("artifact")
        sha256 = entry.get("sha256")
        size_bytes = entry.get("size_bytes")
        algorithm = entry.get("algorithm")
        format_version = entry.get("format_version")
        entry_key_id = entry.get("key_id")
        if not isinstance(database, str):
            raise ValueError(f"invalid database name: {logical_name}")
        _require_safe_db_name(database)
        if (
            not isinstance(artifact, str)
            or Path(artifact).name != artifact
            or artifact != f"{logical_name}.dump.enc"
        ):
            raise ValueError(f"invalid backup artifact path: {logical_name}")
        if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
            raise ValueError(f"invalid backup hash: {logical_name}")
        if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes <= 0:
            raise ValueError(f"invalid backup size: {logical_name}")
        if algorithm != BACKUP_ENCRYPTION_ALGORITHM:
            raise ValueError(f"invalid backup encryption algorithm: {logical_name}")
        if format_version != BACKUP_ENCRYPTION_FORMAT:
            raise ValueError(f"invalid backup encryption format: {logical_name}")
        if entry_key_id != key_id(key):
            raise ValueError(f"backup encryption key mismatch: {logical_name}")
        artifact_path = directory / artifact
        try:
            with open_stable_binary(
                artifact_path,
                expected_identity=identities[artifact],
            ) as (artifact_stream, metadata):
                if metadata.st_size != size_bytes:
                    raise ValueError(f"backup size mismatch: {logical_name}")
                digest = hashlib.sha256()
                for chunk in iter(lambda: artifact_stream.read(1024 * 1024), b""):
                    digest.update(chunk)
                if digest.hexdigest() != sha256:
                    raise ValueError(f"backup hash mismatch: {logical_name}")
                artifact_stream.seek(0)
                decrypt_stream(
                    artifact_stream,
                    None,
                    key,
                    metadata.st_size,
                    expected_logical_name=logical_name,
                    expected_source_database=database,
                )
        except StableFileError as error:
            raise ValueError(
                f"backup artifact cannot be opened safely: {logical_name}"
            ) from error
        verified[logical_name] = dict(entry)
    if require_exact_regular_files(directory, BACKUP_BUNDLE_LEAVES) != identities:
        raise ValueError("backup bundle changed during verification")
    return (
        manifest,
        verified,
        hashlib.sha256(manifest_bytes).hexdigest(),
        identities,
        key,
    )


def verify_bundle(
    input_dir: Path | str,
    *,
    key_file: Path | str,
) -> dict[str, dict[str, object]]:
    _, verified, _, _, _ = _verify_bundle_details(input_dir, key_file=key_file)
    return verified


def verify_bundle_release_binding(
    input_dir: Path | str,
    *,
    key_file: Path | str,
    release_tag: str,
    release_commit: str,
    migration_head: str,
    container_manifest_sha256: str,
    _include_verified: bool = False,
    _include_created_at: bool = False,
    _include_manifest_sha256: bool = False,
) -> (
    dict[str, str]
    | tuple[dict[str, str], dict[str, dict[str, object]]]
    | tuple[dict[str, str], datetime]
    | tuple[dict[str, str], str]
    | tuple[dict[str, str], datetime, str]
):
    if _include_verified and (_include_created_at or _include_manifest_sha256):
        raise ValueError("backup verification detail modes are mutually exclusive")
    directory = Path(input_dir)
    manifest, verified, manifest_sha256, _, _ = _verify_bundle_details(
        directory,
        key_file=key_file,
    )
    if manifest.get("schema_version") != BACKUP_RELEASE_MANIFEST_SCHEMA:
        raise ValueError("backup bundle is not release-bound")
    expected = _release_binding(
        release_tag=release_tag,
        release_commit=release_commit,
        migration_head=migration_head,
        container_manifest_sha256=container_manifest_sha256,
    )
    if expected is None:
        raise ValueError("expected release binding requires all four fields")
    for field in RELEASE_BINDING_FIELDS:
        if manifest.get(field) != expected[field]:
            raise ValueError(f"release binding mismatch: {field}")
    if _include_verified:
        return expected, verified
    if _include_created_at:
        created_at = datetime.fromisoformat(str(manifest["created_at"]))
        if _include_manifest_sha256:
            return expected, created_at, manifest_sha256
        return expected, created_at
    if _include_manifest_sha256:
        return expected, manifest_sha256
    return expected


def restore_bundle(
    input_dir: Path | str,
    *,
    key_file: Path | str,
    platform_target_db: str,
    keycloak_target_db: str,
    service: str = "postgres",
    release_tag: str | None = None,
    release_commit: str | None = None,
    migration_head: str | None = None,
    container_manifest_sha256: str | None = None,
) -> None:
    _validate_production_docker_environment()
    directory = Path(input_dir)
    expected_binding = _release_binding(
        release_tag=release_tag,
        release_commit=release_commit,
        migration_head=migration_head,
        container_manifest_sha256=container_manifest_sha256,
    )
    manifest, verified, _, identities, key = _verify_bundle_details(
        directory,
        key_file=key_file,
    )
    if expected_binding is not None:
        if manifest.get("schema_version") != BACKUP_RELEASE_MANIFEST_SCHEMA:
            raise ValueError("backup bundle is not release-bound")
        for field in RELEASE_BINDING_FIELDS:
            if manifest.get(field) != expected_binding[field]:
                raise ValueError(f"release binding mismatch: {field}")
    targets = {
        "platform": _require_safe_db_name(platform_target_db),
        "keycloak": _require_safe_db_name(keycloak_target_db),
    }
    for logical_name in BACKUP_BUNDLE_DATABASES:
        if require_exact_regular_files(directory, BACKUP_BUNDLE_LEAVES) != identities:
            raise ValueError("backup bundle changed before restore")
        source_database = verified[logical_name]["database"]
        restore_database(
            directory / f"{logical_name}.dump.enc",
            key_file=key_file,
            target_db=targets[logical_name],
            expected_logical_name=logical_name,
            expected_source_database=source_database,
            service=service,
            owner_env=RESTORE_OWNER_ENV[logical_name],
            _expected_identity=identities[f"{logical_name}.dump.enc"],
            _expected_sha256=str(verified[logical_name]["sha256"]),
            _loaded_key=key,
        )


def run_restore(
    input_path: Path | str,
    *,
    key_file: Path | str,
    target_db: str,
    service: str = "postgres",
) -> None:
    _validate_production_docker_environment()
    restore_database(input_path, key_file=key_file, target_db=target_db, service=service)


def run_drill(
    output_path: Path | str,
    *,
    key_file: Path | str,
    scratch_db: str,
    service: str = "postgres",
) -> tuple[BackupResult, str]:
    _validate_production_docker_environment()
    scratch_name = _require_safe_db_name(scratch_db)
    backup = backup_database(output_path, key_file=key_file, service=service)
    subprocess.run(create_database_command(target_db=scratch_name, service=service), check=True)
    try:
        restore_database(
            backup.path,
            key_file=key_file,
            target_db=scratch_name,
            service=service,
        )
        count_tables(target_db=scratch_name, service=service)
    finally:
        subprocess.run(drop_database_command(target_db=scratch_name, service=service), check=True)
    return backup, scratch_name


def drill_bundle(
    output_dir: Path | str,
    *,
    key_file: Path | str,
    platform_db: str,
    keycloak_db: str,
    platform_scratch_db: str,
    keycloak_scratch_db: str,
    service: str = "postgres",
    release_tag: str | None = None,
    release_commit: str | None = None,
    migration_head: str | None = None,
    container_manifest_sha256: str | None = None,
) -> DrillBundleResult:
    _validate_production_docker_environment()
    source_databases = {
        "platform": _require_safe_db_name(platform_db),
        "keycloak": _require_safe_db_name(keycloak_db),
    }
    scratch_databases = {
        "platform": _require_safe_db_name(platform_scratch_db),
        "keycloak": _require_safe_db_name(keycloak_scratch_db),
    }
    if len(set(source_databases.values()) | set(scratch_databases.values())) != 4:
        raise ValueError("source and scratch database names must all be different")
    source_counts = {
        logical_name: count_tables(target_db=database, service=service)
        for logical_name, database in source_databases.items()
    }
    source_row_counts = {
        logical_name: critical_row_counts(
            logical_name=logical_name,
            target_db=database,
            service=service,
        )
        for logical_name, database in source_databases.items()
    }
    bundle = backup_bundle(
        output_dir,
        key_file=key_file,
        platform_db=source_databases["platform"],
        keycloak_db=source_databases["keycloak"],
        service=service,
        release_tag=release_tag,
        release_commit=release_commit,
        migration_head=migration_head,
        container_manifest_sha256=container_manifest_sha256,
    )
    verify_bundle(bundle.directory, key_file=key_file)
    created: list[str] = []
    evidence: dict[str, dict[str, dict[str, int]]] = {}
    try:
        for logical_name in BACKUP_BUNDLE_DATABASES:
            scratch_db = scratch_databases[logical_name]
            subprocess.run(
                create_database_command(
                    target_db=scratch_db,
                    service=service,
                    owner_env=RESTORE_OWNER_ENV[logical_name],
                ),
                check=True,
            )
            created.append(scratch_db)
            restore_database(
                bundle.directory / f"{logical_name}.dump.enc",
                key_file=key_file,
                target_db=scratch_db,
                expected_logical_name=logical_name,
                expected_source_database=source_databases[logical_name],
                service=service,
                owner_env=RESTORE_OWNER_ENV[logical_name],
            )
            restored_count = count_tables(target_db=scratch_db, service=service)
            if restored_count != source_counts[logical_name]:
                raise ValueError(
                    f"restored table count mismatch: {logical_name} "
                    f"source={source_counts[logical_name]} restored={restored_count}"
                )
            restored_row_counts = critical_row_counts(
                logical_name=logical_name,
                target_db=scratch_db,
                service=service,
            )
            evidence[logical_name] = {}
            for table in CRITICAL_TABLES[logical_name]:
                source_count = source_row_counts[logical_name][table]
                restored_row_count = restored_row_counts[table]
                evidence[logical_name][table] = {
                    "source": source_count,
                    "restored": restored_row_count,
                }
                if restored_row_count != source_count:
                    raise ValueError(
                        f"restored row count mismatch: {logical_name}.{table} "
                        f"source={source_count} restored={restored_row_count}"
                    )
    finally:
        for scratch_db in reversed(created):
            subprocess.run(
                drop_database_command(target_db=scratch_db, service=service),
                check=True,
            )
    return DrillBundleResult(bundle=bundle, critical_row_counts=evidence)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.postgres_maintenance",
        description="Create, restore, or drill PostgreSQL backups in the compose stack.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    backup_parser = subparsers.add_parser("backup", help="Create a custom-format backup.")
    backup_parser.add_argument("--output", required=True, help="Backup file path.")
    backup_parser.add_argument("--key-file", type=Path, required=True)
    backup_parser.add_argument("--service", default="postgres", help="Compose service name.")

    restore_parser = subparsers.add_parser("restore", help="Restore a backup into a target database.")
    restore_parser.add_argument("--input", required=True, help="Backup file path.")
    restore_parser.add_argument("--key-file", type=Path, required=True)
    restore_parser.add_argument("--target-db", required=True, help="Target database name.")
    restore_parser.add_argument("--service", default="postgres", help="Compose service name.")

    drill_parser = subparsers.add_parser(
        "drill",
        help="Backup, restore to a scratch database, verify it, then clean up.",
    )
    drill_parser.add_argument("--output", required=True, help="Backup file path.")
    drill_parser.add_argument("--key-file", type=Path, required=True)
    drill_parser.add_argument("--scratch-db", required=True, help="Temporary restore database name.")
    drill_parser.add_argument("--service", default="postgres", help="Compose service name.")

    bundle_parser = subparsers.add_parser(
        "backup-bundle",
        help="Back up the platform and Keycloak databases with an integrity manifest.",
    )
    bundle_parser.add_argument("--output-dir", required=True, help="Backup bundle directory.")
    bundle_parser.add_argument("--key-file", type=Path, required=True)
    bundle_parser.add_argument("--platform-db", default="email_platform")
    bundle_parser.add_argument("--keycloak-db", default="keycloak")
    bundle_parser.add_argument("--service", default="postgres", help="Compose service name.")
    for field in RELEASE_BINDING_FIELDS:
        bundle_parser.add_argument("--" + field.replace("_", "-"))

    verify_parser = subparsers.add_parser(
        "verify-bundle",
        help="Verify both database artifacts against their integrity manifest.",
    )
    verify_parser.add_argument("--input-dir", required=True, help="Backup bundle directory.")
    verify_parser.add_argument("--key-file", type=Path, required=True)

    restore_bundle_parser = subparsers.add_parser(
        "restore-bundle",
        help="Verify and restore the platform and Keycloak databases.",
    )
    restore_bundle_parser.add_argument("--input-dir", required=True)
    restore_bundle_parser.add_argument("--key-file", type=Path, required=True)
    restore_bundle_parser.add_argument("--platform-target-db", default="email_platform")
    restore_bundle_parser.add_argument("--keycloak-target-db", default="keycloak")
    restore_bundle_parser.add_argument("--service", default="postgres", help="Compose service name.")
    for field in RELEASE_BINDING_FIELDS:
        restore_bundle_parser.add_argument("--" + field.replace("_", "-"))

    drill_bundle_parser = subparsers.add_parser(
        "drill-bundle",
        help="Back up and restore-test both platform and Keycloak databases.",
    )
    drill_bundle_parser.add_argument("--output-dir", required=True)
    drill_bundle_parser.add_argument("--key-file", type=Path, required=True)
    drill_bundle_parser.add_argument("--platform-db", default="email_platform")
    drill_bundle_parser.add_argument("--keycloak-db", default="keycloak")
    drill_bundle_parser.add_argument(
        "--platform-scratch-db", default="email_platform_restore_drill"
    )
    drill_bundle_parser.add_argument(
        "--keycloak-scratch-db", default="keycloak_restore_drill"
    )
    drill_bundle_parser.add_argument("--service", default="postgres", help="Compose service name.")
    for field in RELEASE_BINDING_FIELDS:
        drill_bundle_parser.add_argument("--" + field.replace("_", "-"))

    return parser


def _run_cli_command(args: argparse.Namespace) -> int:
    if args.command == "backup":
        result = run_backup(args.output, key_file=args.key_file, service=args.service)
        print(result.path)
        print(result.sha256)
        print(result.size_bytes)
        return 0
    if args.command == "restore":
        run_restore(
            args.input,
            key_file=args.key_file,
            target_db=args.target_db,
            service=args.service,
        )
        return 0
    if args.command == "drill":
        backup, scratch_db = run_drill(
            args.output,
            key_file=args.key_file,
            scratch_db=args.scratch_db,
            service=args.service,
        )
        print(backup.path)
        print(backup.sha256)
        print(scratch_db)
        return 0
    if args.command == "backup-bundle":
        bundle = backup_bundle(
            args.output_dir,
            key_file=args.key_file,
            platform_db=args.platform_db,
            keycloak_db=args.keycloak_db,
            service=args.service,
            release_tag=args.release_tag,
            release_commit=args.release_commit,
            migration_head=args.migration_head,
            container_manifest_sha256=args.container_manifest_sha256,
        )
        print(bundle.manifest_path)
        for logical_name in BACKUP_BUNDLE_DATABASES:
            result = bundle.databases[logical_name]
            print(f"{logical_name} {result.sha256} {result.size_bytes}")
        return 0
    if args.command == "verify-bundle":
        verify_bundle(args.input_dir, key_file=args.key_file)
        print(Path(args.input_dir) / BACKUP_MANIFEST_NAME)
        return 0
    if args.command == "restore-bundle":
        restore_bundle(
            args.input_dir,
            key_file=args.key_file,
            platform_target_db=args.platform_target_db,
            keycloak_target_db=args.keycloak_target_db,
            service=args.service,
            release_tag=args.release_tag,
            release_commit=args.release_commit,
            migration_head=args.migration_head,
            container_manifest_sha256=args.container_manifest_sha256,
        )
        return 0
    if args.command == "drill-bundle":
        drill = drill_bundle(
            args.output_dir,
            key_file=args.key_file,
            platform_db=args.platform_db,
            keycloak_db=args.keycloak_db,
            platform_scratch_db=args.platform_scratch_db,
            keycloak_scratch_db=args.keycloak_scratch_db,
            service=args.service,
            release_tag=args.release_tag,
            release_commit=args.release_commit,
            migration_head=args.migration_head,
            container_manifest_sha256=args.container_manifest_sha256,
        )
        print(drill.bundle.manifest_path)
        print(json.dumps({"critical_row_counts": drill.critical_row_counts}, sort_keys=True))
        return 0
    raise AssertionError(f"Unhandled command: {args.command}")


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _run_cli_command(args)
    except Exception as error:
        suffix = (
            f"; {CLEANUP_UNCONFIRMED_NOTE}" if cleanup_unconfirmed(error) else ""
        )
        print(
            f"postgres-maintenance-error: {args.command} failed{suffix}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
