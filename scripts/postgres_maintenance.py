"""PostgreSQL backup, restore, and drill helpers for the compose stack."""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


_SAFE_DB_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class BackupResult:
    path: Path
    sha256: str
    size_bytes: int


def _require_safe_db_name(value: str) -> str:
    candidate = value.strip()
    if not candidate or not _SAFE_DB_NAME.fullmatch(candidate):
        raise ValueError(
            "database name must contain only letters, digits, and underscores"
        )
    return candidate


def _compose_exec(service: str, shell_command: str) -> list[str]:
    return ["docker", "compose", "exec", "-T", service, "sh", "-lc", shell_command]


def backup_command(*, service: str = "postgres") -> list[str]:
    return _compose_exec(
        service,
        'pg_dump -Fc --no-owner --no-privileges -U "$POSTGRES_USER" "$POSTGRES_DB"',
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


def backup_database(
    output_path: Path | str,
    *,
    service: str = "postgres",
) -> BackupResult:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    command = backup_command(service=service)
    with path.open("wb") as stream:
        subprocess.run(command, check=True, stdout=stream)
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
        subprocess.run(count_tables_command(target_db=scratch_name, service=service), check=True)
    finally:
        subprocess.run(drop_database_command(target_db=scratch_name, service=service), check=True)
    return backup, scratch_name


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
    raise AssertionError(f"Unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
