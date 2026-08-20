"""Verify the two-database backup/restore contract and operator guidance."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "platform" / "README.md"
SCRIPT = ROOT / "scripts" / "postgres_maintenance.py"
RUNBOOK = ROOT / "deploy" / "runbooks" / "restore.md"


def _load_maintenance_module():
    spec = importlib.util.spec_from_file_location("verified_postgres_maintenance", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load postgres_maintenance.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    if not SCRIPT.exists():
        print("Missing postgres_maintenance.py", file=sys.stderr)
        return 1
    try:
        maintenance = _load_maintenance_module()
        parser = maintenance.build_parser()
    except Exception as error:
        print(f"Cannot load backup tooling: {error}", file=sys.stderr)
        return 1
    subparser_actions = [
        action for action in parser._actions if hasattr(action, "choices") and action.choices
    ]
    commands = set(subparser_actions[0].choices) if subparser_actions else set()
    required_commands = {
        "backup-bundle",
        "verify-bundle",
        "restore-bundle",
        "drill-bundle",
    }
    if not required_commands.issubset(commands):
        print(f"Missing backup bundle commands: {sorted(required_commands - commands)}", file=sys.stderr)
        return 1
    if tuple(maintenance.BACKUP_BUNDLE_DATABASES) != ("platform", "keycloak"):
        print("Backup bundle must require platform and keycloak databases", file=sys.stderr)
        return 1
    if maintenance.CRITICAL_TABLES != {
        "platform": ("users", "devices", "audit_events"),
        "keycloak": ("realm", "user_entity", "credential"),
    }:
        print("Backup drill critical-table whitelist is incomplete", file=sys.stderr)
        return 1
    for function_name in ("backup_bundle", "verify_bundle", "restore_bundle", "drill_bundle"):
        if not callable(getattr(maintenance, function_name, None)):
            print(f"Missing backup function: {function_name}", file=sys.stderr)
            return 1

    documents = {
        "README": README.read_text(encoding="utf-8"),
        "restore runbook": RUNBOOK.read_text(encoding="utf-8"),
    }
    for label, document in documents.items():
        for command in required_commands:
            needle = f"python -m scripts.postgres_maintenance {command}"
            if needle not in document:
                print(f"{label} is missing: {needle}", file=sys.stderr)
                return 1
        for needle in ("platform.dump", "keycloak.dump", "manifest.json", "SHA-256"):
            if needle not in document:
                print(f"{label} is missing: {needle}", file=sys.stderr)
                return 1
        for table in ("users", "devices", "audit_events", "realm", "user_entity", "credential"):
            if table not in document:
                print(f"{label} is missing critical-table evidence guidance: {table}", file=sys.stderr)
                return 1
    print("backup-tools-ok platform-keycloak-bundle-integrity-validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
