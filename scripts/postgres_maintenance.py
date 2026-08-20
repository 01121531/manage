"""PostgreSQL backup, restore, and drill helpers for the compose stack."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


_SAFE_DB_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
BACKUP_MANIFEST_NAME = "manifest.json"
BACKUP_MANIFEST_SCHEMA = 1
BACKUP_BUNDLE_DATABASES = ("platform", "keycloak")
CRITICAL_TABLES = {
    "platform": ("users", "devices", "audit_events"),
    "keycloak": ("realm", "user_entity", "credential"),
}


@dataclass(frozen=True)
class BackupResult:
    path: Path
    sha256: str
    size_bytes: int


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


def _compose_exec(service: str, shell_command: str) -> list[str]:
    return ["docker", "compose", "exec", "-T", service, "sh", "-lc", shell_command]


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


def restore_command(*, target_db: str, service: str = "postgres") -> list[str]:
    db_name = _require_safe_db_name(target_db)
    return _compose_exec(
        service,
        f'pg_restore --clean --if-exists --no-owner --no-privileges -U "$POSTGRES_USER" -d "{db_name}"',
    )


def create_database_command(*, target_db: str, service: str = "postgres") -> list[str]:
    db_name = _require_safe_db_name(target_db)
    return _compose_exec(
        service,
        f'createdb -U "$POSTGRES_USER" "{db_name}"',
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
    database: str | None = None,
    service: str = "postgres",
) -> BackupResult:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    command = backup_command(database=database, service=service)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            subprocess.run(command, check=True, stdout=stream)
        if temporary_path.stat().st_size <= 0:
            raise ValueError(f"backup is empty: {path}")
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    data = path.read_bytes()
    return BackupResult(
        path=path,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )


def restore_database(
    input_path: Path | str,
    *,
    target_db: str,
    service: str = "postgres",
) -> None:
    path = Path(input_path)
    command = restore_command(target_db=target_db, service=service)
    with path.open("rb") as stream:
        subprocess.run(command, check=True, stdin=stream)


def run_backup(
    output_path: Path | str,
    *,
    service: str = "postgres",
) -> BackupResult:
    return backup_database(output_path, service=service)


def _artifact_metadata(result: BackupResult, *, database: str) -> dict[str, object]:
    return {
        "database": database,
        "artifact": result.path.name,
        "sha256": result.sha256,
        "size_bytes": result.size_bytes,
    }


def backup_bundle(
    output_dir: Path | str,
    *,
    platform_db: str,
    keycloak_db: str,
    service: str = "postgres",
) -> BackupBundleResult:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    manifest_path = directory / BACKUP_MANIFEST_NAME
    manifest_path.unlink(missing_ok=True)
    database_names = {
        "platform": _require_safe_db_name(platform_db),
        "keycloak": _require_safe_db_name(keycloak_db),
    }
    results = {
        logical_name: backup_database(
            directory / f"{logical_name}.dump",
            database=database_name,
            service=service,
        )
        for logical_name, database_name in database_names.items()
    }
    manifest = {
        "schema_version": BACKUP_MANIFEST_SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "databases": {
            logical_name: _artifact_metadata(
                results[logical_name], database=database_names[logical_name]
            )
            for logical_name in BACKUP_BUNDLE_DATABASES
        },
    }
    temporary_manifest = directory / f".{BACKUP_MANIFEST_NAME}.tmp"
    temporary_manifest.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary_manifest, manifest_path)
    return BackupBundleResult(
        directory=directory,
        manifest_path=manifest_path,
        databases=results,
    )


def verify_bundle(input_dir: Path | str) -> dict[str, dict[str, object]]:
    directory = Path(input_dir)
    manifest_path = directory / BACKUP_MANIFEST_NAME
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid backup manifest: {error}") from error
    if not isinstance(manifest, dict) or manifest.get("schema_version") != BACKUP_MANIFEST_SCHEMA:
        raise ValueError("unsupported backup manifest schema")
    databases = manifest.get("databases")
    if not isinstance(databases, dict) or set(databases) != set(BACKUP_BUNDLE_DATABASES):
        raise ValueError("backup manifest must contain platform and keycloak databases")
    verified: dict[str, dict[str, object]] = {}
    for logical_name in BACKUP_BUNDLE_DATABASES:
        entry = databases.get(logical_name)
        if not isinstance(entry, dict):
            raise ValueError(f"invalid manifest entry: {logical_name}")
        database = entry.get("database")
        artifact = entry.get("artifact")
        sha256 = entry.get("sha256")
        size_bytes = entry.get("size_bytes")
        if not isinstance(database, str):
            raise ValueError(f"invalid database name: {logical_name}")
        _require_safe_db_name(database)
        if (
            not isinstance(artifact, str)
            or Path(artifact).name != artifact
            or artifact != f"{logical_name}.dump"
        ):
            raise ValueError(f"invalid backup artifact path: {logical_name}")
        if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
            raise ValueError(f"invalid backup hash: {logical_name}")
        if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes <= 0:
            raise ValueError(f"invalid backup size: {logical_name}")
        artifact_path = directory / artifact
        try:
            data = artifact_path.read_bytes()
        except OSError as error:
            raise ValueError(f"missing backup artifact: {logical_name}") from error
        if len(data) != size_bytes:
            raise ValueError(f"backup size mismatch: {logical_name}")
        if hashlib.sha256(data).hexdigest() != sha256:
            raise ValueError(f"backup hash mismatch: {logical_name}")
        verified[logical_name] = dict(entry)
    return verified


def restore_bundle(
    input_dir: Path | str,
    *,
    platform_target_db: str,
    keycloak_target_db: str,
    service: str = "postgres",
) -> None:
    directory = Path(input_dir)
    verify_bundle(directory)
    targets = {
        "platform": _require_safe_db_name(platform_target_db),
        "keycloak": _require_safe_db_name(keycloak_target_db),
    }
    for logical_name in BACKUP_BUNDLE_DATABASES:
        restore_database(
            directory / f"{logical_name}.dump",
            target_db=targets[logical_name],
            service=service,
        )


def run_restore(
    input_path: Path | str,
    *,
    target_db: str,
    service: str = "postgres",
) -> None:
    restore_database(input_path, target_db=target_db, service=service)


def run_drill(
    output_path: Path | str,
    *,
    scratch_db: str,
    service: str = "postgres",
) -> tuple[BackupResult, str]:
    scratch_name = _require_safe_db_name(scratch_db)
    backup = backup_database(output_path, service=service)
    subprocess.run(create_database_command(target_db=scratch_name, service=service), check=True)
    try:
        restore_database(backup.path, target_db=scratch_name, service=service)
        count_tables(target_db=scratch_name, service=service)
    finally:
        subprocess.run(drop_database_command(target_db=scratch_name, service=service), check=True)
    return backup, scratch_name


def drill_bundle(
    output_dir: Path | str,
    *,
    platform_db: str,
    keycloak_db: str,
    platform_scratch_db: str,
    keycloak_scratch_db: str,
    service: str = "postgres",
) -> DrillBundleResult:
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
        platform_db=source_databases["platform"],
        keycloak_db=source_databases["keycloak"],
        service=service,
    )
    verify_bundle(bundle.directory)
    created: list[str] = []
    evidence: dict[str, dict[str, dict[str, int]]] = {}
    try:
        for logical_name in BACKUP_BUNDLE_DATABASES:
            scratch_db = scratch_databases[logical_name]
            subprocess.run(
                create_database_command(target_db=scratch_db, service=service),
                check=True,
            )
            created.append(scratch_db)
            restore_database(
                bundle.directory / f"{logical_name}.dump",
                target_db=scratch_db,
                service=service,
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
    backup_parser.add_argument("--service", default="postgres", help="Compose service name.")

    restore_parser = subparsers.add_parser("restore", help="Restore a backup into a target database.")
    restore_parser.add_argument("--input", required=True, help="Backup file path.")
    restore_parser.add_argument("--target-db", required=True, help="Target database name.")
    restore_parser.add_argument("--service", default="postgres", help="Compose service name.")

    drill_parser = subparsers.add_parser(
        "drill",
        help="Backup, restore to a scratch database, verify it, then clean up.",
    )
    drill_parser.add_argument("--output", required=True, help="Backup file path.")
    drill_parser.add_argument("--scratch-db", required=True, help="Temporary restore database name.")
    drill_parser.add_argument("--service", default="postgres", help="Compose service name.")

    bundle_parser = subparsers.add_parser(
        "backup-bundle",
        help="Back up the platform and Keycloak databases with an integrity manifest.",
    )
    bundle_parser.add_argument("--output-dir", required=True, help="Backup bundle directory.")
    bundle_parser.add_argument("--platform-db", default="email_platform")
    bundle_parser.add_argument("--keycloak-db", default="keycloak")
    bundle_parser.add_argument("--service", default="postgres", help="Compose service name.")

    verify_parser = subparsers.add_parser(
        "verify-bundle",
        help="Verify both database artifacts against their integrity manifest.",
    )
    verify_parser.add_argument("--input-dir", required=True, help="Backup bundle directory.")

    restore_bundle_parser = subparsers.add_parser(
        "restore-bundle",
        help="Verify and restore the platform and Keycloak databases.",
    )
    restore_bundle_parser.add_argument("--input-dir", required=True)
    restore_bundle_parser.add_argument("--platform-target-db", default="email_platform")
    restore_bundle_parser.add_argument("--keycloak-target-db", default="keycloak")
    restore_bundle_parser.add_argument("--service", default="postgres", help="Compose service name.")

    drill_bundle_parser = subparsers.add_parser(
        "drill-bundle",
        help="Back up and restore-test both platform and Keycloak databases.",
    )
    drill_bundle_parser.add_argument("--output-dir", required=True)
    drill_bundle_parser.add_argument("--platform-db", default="email_platform")
    drill_bundle_parser.add_argument("--keycloak-db", default="keycloak")
    drill_bundle_parser.add_argument(
        "--platform-scratch-db", default="email_platform_restore_drill"
    )
    drill_bundle_parser.add_argument(
        "--keycloak-scratch-db", default="keycloak_restore_drill"
    )
    drill_bundle_parser.add_argument("--service", default="postgres", help="Compose service name.")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "backup":
        result = run_backup(args.output, service=args.service)
        print(result.path)
        print(result.sha256)
        print(result.size_bytes)
        return 0
    if args.command == "restore":
        run_restore(args.input, target_db=args.target_db, service=args.service)
        return 0
    if args.command == "drill":
        backup, scratch_db = run_drill(
            args.output,
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
            platform_db=args.platform_db,
            keycloak_db=args.keycloak_db,
            service=args.service,
        )
        print(bundle.manifest_path)
        for logical_name in BACKUP_BUNDLE_DATABASES:
            result = bundle.databases[logical_name]
            print(f"{logical_name} {result.sha256} {result.size_bytes}")
        return 0
    if args.command == "verify-bundle":
        verify_bundle(args.input_dir)
        print(Path(args.input_dir) / BACKUP_MANIFEST_NAME)
        return 0
    if args.command == "restore-bundle":
        restore_bundle(
            args.input_dir,
            platform_target_db=args.platform_target_db,
            keycloak_target_db=args.keycloak_target_db,
            service=args.service,
        )
        return 0
    if args.command == "drill-bundle":
        drill = drill_bundle(
            args.output_dir,
            platform_db=args.platform_db,
            keycloak_db=args.keycloak_db,
            platform_scratch_db=args.platform_scratch_db,
            keycloak_scratch_db=args.keycloak_scratch_db,
            service=args.service,
        )
        print(drill.bundle.manifest_path)
        print(json.dumps({"critical_row_counts": drill.critical_row_counts}, sort_keys=True))
        return 0
    raise AssertionError(f"Unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
