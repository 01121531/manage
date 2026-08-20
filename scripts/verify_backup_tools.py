"""Verify the two-database backup/restore contract and operator guidance."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "platform" / "README.md"
SCRIPT = ROOT / "scripts" / "postgres_maintenance.py"
RUNBOOK = ROOT / "deploy" / "runbooks" / "restore.md"
VAULT_SCRIPT = ROOT / "scripts" / "vault_maintenance.py"
VAULT_RUNBOOK = ROOT / "deploy" / "runbooks" / "vault-restore.md"


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
    for function_name in (
        "backup_bundle",
        "verify_bundle",
        "verify_bundle_release_binding",
        "restore_bundle",
        "drill_bundle",
    ):
        if not callable(getattr(maintenance, function_name, None)):
            print(f"Missing backup function: {function_name}", file=sys.stderr)
            return 1
    if maintenance.BACKUP_RELEASE_MANIFEST_SCHEMA != 2:
        print("Release-bound backup schema v2 is required", file=sys.stderr)
        return 1
    if set(maintenance.RELEASE_BINDING_FIELDS) != {
        "release_tag",
        "release_commit",
        "migration_head",
        "container_manifest_sha256",
    }:
        print("Release-bound backup fields are incomplete", file=sys.stderr)
        return 1

    if not VAULT_SCRIPT.exists():
        print("Missing vault_maintenance.py", file=sys.stderr)
        return 1
    vault_spec = importlib.util.spec_from_file_location(
        "verified_vault_maintenance", VAULT_SCRIPT
    )
    if vault_spec is None or vault_spec.loader is None:
        print("Cannot load vault_maintenance.py", file=sys.stderr)
        return 1
    vault = importlib.util.module_from_spec(vault_spec)
    sys.modules[vault_spec.name] = vault
    vault_spec.loader.exec_module(vault)
    vault_commands = {
        command
        for action in vault.build_parser()._actions
        if hasattr(action, "choices") and action.choices
        for command in action.choices
    }
    if vault_commands != {"backup", "verify", "restore"}:
        print("Vault maintenance commands are incomplete", file=sys.stderr)
        return 1
    for function_name in ("create_snapshot", "verify_snapshot", "restore_snapshot"):
        if not callable(getattr(vault, function_name, None)):
            print(f"Missing Vault snapshot function: {function_name}", file=sys.stderr)
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
    vault_runbook = VAULT_RUNBOOK.read_text(encoding="utf-8")
    for needle in (
        "python -m scripts.vault_maintenance backup",
        "python -m scripts.vault_maintenance verify",
        "python -m scripts.vault_maintenance restore",
        "--confirm-restore",
        "vault.snap",
        "vault-manifest.json",
        "SHA-256",
        "isolated",
    ):
        if needle not in vault_runbook:
            print(f"Vault restore runbook is missing: {needle}", file=sys.stderr)
            return 1
    print("backup-tools-ok platform-keycloak-vault-integrity-validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
