"""Verify chapter-13 planning defaults and their runtime values remain aligned."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from platform.config import Settings
from scripts.external_json import (
    MAX_INTAKE_JSON_BYTES,
    load_unique_json,
    load_unique_json_with_bytes,
    parse_unique_json_bytes,
)
from scripts.external_text import load_stable_text
from scripts.external_yaml import load_unique_yaml_with_text, parse_unique_yaml


DECISIONS = ROOT / "deploy" / "chapter13-default-decisions.json"
COMPOSE = ROOT / "docker-compose.yml"
REALM = ROOT / "infra" / "keycloak" / "email-platform-realm.json"
ENV_EXAMPLE = ROOT / ".env.example"
EXPECTED = {
    "schema_version": 1,
    "plan_chapter": "13",
    "production_acceptance": False,
    "decisions": {
        "sub2_adapter": {
            "default": "standard_http_api",
            "status": "generic_adapter_only",
            "confirmation_required": "real Sub2 API or browser-backoffice contract",
        },
        "card_secret_boundary": {
            "default": "pan_in_card_vault_never_store_cvv",
            "status": "repository_gate_passed",
            "confirmation_required": "provider field inventory and PCI scope decision",
        },
        "resource_lease": {
            "max_active_tasks_per_user": 1,
            "task_ttl_seconds": 1800,
            "status": "repository_gate_passed",
            "confirmation_required": "target concurrency and recovery observation",
        },
        "tenant_isolation": {
            "default": "tenant_id_required_from_first_schema",
            "status": "repository_gate_passed",
            "confirmation_required": "target PostgreSQL and identity-provider tenant tests",
        },
        "login": {
            "default": "oidc_pkce_with_mfa",
            "status": "repository_gate_passed",
            "confirmation_required": "target Keycloak ACR-to-LoA, PKCE and Device Flow evidence",
        },
        "capacity_basis": {
            "users": 100,
            "concurrent_tasks": 10,
            "status": "unvalidated_planning_default",
            "confirmation_required": "target load profile, provider limits and deployment decision",
        },
        "mail_code": {
            "visibility": "current_task_only",
            "consumption": "one_time",
            "ttl_seconds": 60,
            "status": "repository_gate_passed",
            "confirmation_required": "real provider stale-code and delivery-delay evidence",
        },
    },
}


def decision_errors(
    document: Any,
    *,
    compose_text: str | None = None,
    realm_text: str | None = None,
    env_text: str | None = None,
) -> list[str]:
    errors: list[str] = []
    if document != EXPECTED:
        errors.append("chapter-13 default decision contract is invalid")
    runtime_defaults = {
        name: Settings.model_fields[name].default
        for name in ("task_ttl_seconds", "sub2_concurrency", "mail_code_ttl_seconds")
    }
    if runtime_defaults != {
        "task_ttl_seconds": 1800,
        "sub2_concurrency": 10,
        "mail_code_ttl_seconds": 60,
    }:
        errors.append("chapter-13 runtime defaults have drifted")
    try:
        if compose_text is None:
            _, compose = load_unique_yaml_with_text(COMPOSE)
        else:
            parse_unique_yaml(compose_text)
            compose = compose_text
    except (OSError, UnicodeError, yaml.YAMLError):
        errors.append("chapter-13 Compose input is unreadable")
        compose = ""
    if compose.count("PLATFORM_AUTH_MODE: oidc") != 3:
        errors.append("managed API and workers must use OIDC")
    if (
        compose.count(
            "PLATFORM_SUB2_CONCURRENCY: ${PLATFORM_SUB2_CONCURRENCY:-10}"
        )
        != 2
        or "PLATFORM_SUB2_CONCURRENCY:-40" in compose
    ):
        errors.append("chapter-13 Compose concurrency default has drifted")
    if realm_text is None:
        _, realm_bytes = load_unique_json_with_bytes(
            REALM,
            max_bytes=MAX_INTAKE_JSON_BYTES,
        )
        realm = realm_bytes.decode("utf-8")
    else:
        parse_unique_json_bytes(realm_text.encode("utf-8"))
        realm = realm_text
    if realm.count('"pkce.code.challenge.method": "S256"') != 2:
        errors.append("reviewed Web and Desktop clients must require S256 PKCE")
    example = load_stable_text(ENV_EXAMPLE) if env_text is None else env_text
    if "PLATFORM_SUB2_CONCURRENCY=10" not in example:
        errors.append("production example does not use the chapter-13 concurrency basis")
    return errors


def main() -> int:
    try:
        document = load_unique_json(
            DECISIONS,
            max_bytes=MAX_INTAKE_JSON_BYTES,
        )
        errors = decision_errors(document)
    except (OSError, UnicodeError, json.JSONDecodeError):
        errors = ["chapter-13 default decisions are unreadable"]
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    print("chapter13-defaults-ok production_acceptance=false capacity=100/10")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
