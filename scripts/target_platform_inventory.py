"""Validate the target-platform inventory without accepting secret values."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.external_json import load_unique_json
from scripts.external_text import load_stable_text
from scripts.external_yaml import load_unique_yaml_with_text, parse_unique_yaml

INVENTORY = (
    ROOT / "deploy" / "inventory-envelopes" / "target-platform.synthetic.json"
)
COMPOSE = ROOT / "docker-compose.yml"
ENV_EXAMPLE = ROOT / ".env.example"

_TOP_LEVEL_KEYS = {
    "schema_version",
    "record_type",
    "inventory_reference",
    "synthetic",
    "inventory_status",
    "review_reference",
    "reviewed_at",
    "valid_until",
    "production_acceptance",
    "environment",
    "public_endpoints",
    "control_planes",
    "certificate_ownership",
    "runtime_locations",
    "prohibited_content",
}
_PUBLIC_KEYS = {
    "platform_domain",
    "application_origin",
    "identity_issuer",
    "external_dns_owner_reference",
    "external_certificate_owner_reference",
}
_CONTROL_PLANE_KEYS = {
    "keycloak_owner_reference",
    "vault_owner_reference",
    "internal_dns_owner_reference",
}
_CERTIFICATE_KEYS = {
    "internal_ca_owner_reference",
    "issuance_owner_reference",
    "rotation_owner_reference",
    "leaf_dns_sans",
}
_RUNTIME_KEYS = {
    "path_policy",
    "repository_external_confirmed",
    "secret_files",
    "vault_token_directories",
    "policy_files",
    "internal_tls_root",
    "rolling_route_directory",
    "evidence_root",
}
_PROHIBITED_KEYS = {
    "contains_live_credentials",
    "contains_personal_data",
    "contains_private_key_values",
    "contains_certificate_values",
    "contains_token_values",
    "contains_secret_values",
    "contains_pan_or_cvv_values",
}
_SECRET_FILE_KEYS = {
    "POSTGRES_PASSWORD_FILE",
    "POSTGRES_APP_PASSWORD_FILE",
    "KEYCLOAK_DB_PASSWORD_FILE",
    "PLATFORM_MIGRATION_DATABASE_URL_FILE",
    "PLATFORM_DATABASE_URL_FILE",
    "PLATFORM_REDIS_URL_FILE",
    "REDIS_CONFIG_FILE",
    "REDIS_ACL_FILE",
    "REDIS_HEALTHCHECK_PASSWORD_FILE",
    "KEYCLOAK_CONFIG_FILE",
}
_VAULT_DIRECTORY_KEYS = {
    "PLATFORM_VAULT_API_TOKEN_DIR",
    "PLATFORM_VAULT_MAIL_TOKEN_DIR",
    "PLATFORM_VAULT_SUB2_TOKEN_DIR",
}
_POLICY_FILE_KEYS = {
    "PLATFORM_MAIL_ALLOWED_ORIGINS_FILE",
    "PLATFORM_SUB2_ALLOWED_ORIGINS_FILE",
    "ALERTMANAGER_CONFIG_FILE",
}
_LEAF_DNS_SANS = {
    "api": "api",
    "web": "web",
    "api-green": "api-green",
    "web-green": "web-green",
    "keycloak": "keycloak",
    "worker-mail": "worker-mail",
    "worker-sub2": "worker-sub2",
    "prometheus": "prometheus",
    "alertmanager": "alertmanager",
}
_CERTIFICATE_ENV_KEYS = {
    "PLATFORM_INTERNAL_CA_FILE",
    "PLATFORM_INTERNAL_API_CERT_FILE",
    "PLATFORM_INTERNAL_API_KEY_FILE",
    "PLATFORM_INTERNAL_WEB_CERT_FILE",
    "PLATFORM_INTERNAL_WEB_KEY_FILE",
    "PLATFORM_ROLLING_GREEN_API_CERT_FILE",
    "PLATFORM_ROLLING_GREEN_API_KEY_FILE",
    "PLATFORM_ROLLING_GREEN_WEB_CERT_FILE",
    "PLATFORM_ROLLING_GREEN_WEB_KEY_FILE",
    "PLATFORM_INTERNAL_KEYCLOAK_CERT_FILE",
    "PLATFORM_INTERNAL_KEYCLOAK_KEY_FILE",
    "PLATFORM_INTERNAL_WORKER_MAIL_CERT_FILE",
    "PLATFORM_INTERNAL_WORKER_MAIL_KEY_FILE",
    "PLATFORM_INTERNAL_WORKER_SUB2_CERT_FILE",
    "PLATFORM_INTERNAL_WORKER_SUB2_KEY_FILE",
    "PLATFORM_INTERNAL_PROMETHEUS_CERT_FILE",
    "PLATFORM_INTERNAL_PROMETHEUS_KEY_FILE",
    "PLATFORM_INTERNAL_ALERTMANAGER_CERT_FILE",
    "PLATFORM_INTERNAL_ALERTMANAGER_KEY_FILE",
    "PLATFORM_TLS_CERT_FILE",
    "PLATFORM_TLS_KEY_FILE",
}
_COMPOSE_CERTIFICATE_KEYS = _CERTIFICATE_ENV_KEYS - {
    "PLATFORM_ROLLING_GREEN_API_CERT_FILE",
    "PLATFORM_ROLLING_GREEN_API_KEY_FILE",
    "PLATFORM_ROLLING_GREEN_WEB_CERT_FILE",
    "PLATFORM_ROLLING_GREEN_WEB_KEY_FILE",
}
_ENVIRONMENT_INPUT_KEYS = (
    _SECRET_FILE_KEYS
    | _VAULT_DIRECTORY_KEYS
    | _POLICY_FILE_KEYS
    | _CERTIFICATE_ENV_KEYS
    | {
        "PLATFORM_DOMAIN",
        "PLATFORM_VAULT_ADDR",
        "PLATFORM_ROLLING_ROUTE_DIR",
    }
)
_COMPOSE_INPUT_KEYS = (
    _SECRET_FILE_KEYS
    | _VAULT_DIRECTORY_KEYS
    | _POLICY_FILE_KEYS
    | _COMPOSE_CERTIFICATE_KEYS
    | {"PLATFORM_DOMAIN", "PLATFORM_VAULT_ADDR"}
)
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_ENVIRONMENT = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
_UTC_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)
_PLACEHOLDERS = {
    "change_me",
    "changeme",
    "example",
    "invalid",
    "local",
    "localhost",
    "placeholder",
    "tbd",
    "test",
    "todo",
    "unknown",
}
_REPOSITORY_PATH_SEGMENTS = {".git", "repo", "repository", "source", "src", "workspace"}


def _safe_reference(value: Any) -> bool:
    return (
        isinstance(value, str)
        and _REFERENCE.fullmatch(value) is not None
        and value.casefold() not in _PLACEHOLDERS
    )


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed if parsed.tzinfo == timezone.utc else None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _production_domain(value: Any) -> bool:
    if not isinstance(value, str) or value != value.casefold() or not _DOMAIN.fullmatch(value):
        return False
    if _PLACEHOLDERS.intersection(value.split(".")):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return True
    return False


def _target_host_path(value: Any) -> bool:
    if (
        not isinstance(value, str)
        or not 1 < len(value) <= 512
        or value.strip() != value
        or not value.startswith("/")
        or "//" in value
        or value.endswith("/")
    ):
        return False
    path = PurePosixPath(value)
    folded_parts = {part.casefold() for part in path.parts}
    return (
        "." not in path.parts
        and ".." not in path.parts
        and not folded_parts.intersection(_PLACEHOLDERS)
        and not folded_parts.intersection(_REPOSITORY_PATH_SEGMENTS)
        and path.as_posix() == value
    )


def _mapping_has_exact_keys(value: Any, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def inventory_errors(
    document: Any,
    *,
    evaluated_at: datetime | None = None,
) -> list[str]:
    evaluation_time = evaluated_at or _utc_now()
    if not isinstance(document, dict) or set(document) != _TOP_LEVEL_KEYS:
        return ["target platform inventory top-level schema is invalid"]
    errors: list[str] = []
    if (
        document.get("schema_version") != 2
        or document.get("record_type") != "target_platform_inventory"
    ):
        errors.append("target platform inventory identity is invalid")
    if document.get("production_acceptance") is not False:
        errors.append("target platform inventory must not claim production acceptance")

    prohibited = document.get("prohibited_content")
    if (
        not _mapping_has_exact_keys(prohibited, _PROHIBITED_KEYS)
        or any(value is not False for value in prohibited.values())
    ):
        errors.append("target platform inventory prohibited-content declaration is invalid")

    public = document.get("public_endpoints")
    control_planes = document.get("control_planes")
    certificates = document.get("certificate_ownership")
    runtime = document.get("runtime_locations")
    if not _mapping_has_exact_keys(public, _PUBLIC_KEYS):
        errors.append("target platform public endpoint schema is invalid")
    if not _mapping_has_exact_keys(control_planes, _CONTROL_PLANE_KEYS):
        errors.append("target platform control-plane schema is invalid")
    if not _mapping_has_exact_keys(certificates, _CERTIFICATE_KEYS):
        errors.append("target platform certificate ownership schema is invalid")
    elif certificates.get("leaf_dns_sans") != _LEAF_DNS_SANS:
        errors.append("target platform internal TLS leaf inventory is invalid")
    if not _mapping_has_exact_keys(runtime, _RUNTIME_KEYS):
        errors.append("target platform runtime-location schema is invalid")
    else:
        if runtime.get("path_policy") != "repository_external_target_host_paths_only":
            errors.append("target platform runtime path policy is invalid")
        for key, expected_keys in (
            ("secret_files", _SECRET_FILE_KEYS),
            ("vault_token_directories", _VAULT_DIRECTORY_KEYS),
            ("policy_files", _POLICY_FILE_KEYS),
        ):
            if not _mapping_has_exact_keys(runtime.get(key), expected_keys):
                errors.append(f"target platform {key} inventory is invalid")

    synthetic = document.get("synthetic")
    reference = document.get("inventory_reference")
    review_reference = document.get("review_reference")
    reviewed_at = document.get("reviewed_at")
    valid_until = document.get("valid_until")
    environment = document.get("environment")
    if not isinstance(synthetic, bool) or not _safe_reference(reference):
        errors.append("target platform inventory reference is invalid")
        return errors

    if synthetic:
        nested_values: list[Any] = []
        if isinstance(public, dict):
            nested_values.extend(public.values())
        if isinstance(control_planes, dict):
            nested_values.extend(control_planes.values())
        if isinstance(certificates, dict):
            nested_values.extend(
                certificates.get(key)
                for key in (
                    "internal_ca_owner_reference",
                    "issuance_owner_reference",
                    "rotation_owner_reference",
                )
            )
        if isinstance(runtime, dict):
            for key in ("secret_files", "vault_token_directories", "policy_files"):
                value = runtime.get(key)
                if isinstance(value, dict):
                    nested_values.extend(value.values())
            nested_values.extend(
                runtime.get(key)
                for key in (
                    "internal_tls_root",
                    "rolling_route_directory",
                    "evidence_root",
                )
            )
        if (
            not reference.startswith("synthetic-")
            or document.get("inventory_status") != "pending"
            or environment != "production"
            or review_reference is not None
            or reviewed_at is not None
            or valid_until is not None
            or not isinstance(runtime, dict)
            or runtime.get("repository_external_confirmed") is not False
            or any(value is not None for value in nested_values)
        ):
            errors.append("synthetic target platform inventory metadata is invalid")
        return errors

    if (
        not isinstance(environment, str)
        or _ENVIRONMENT.fullmatch(environment) is None
        or environment.casefold() in _PLACEHOLDERS
    ):
        errors.append("reviewed target platform environment is invalid")
    if (
        reference.startswith("synthetic-")
        or document.get("inventory_status") != "reviewed"
        or not _safe_reference(review_reference)
        or reference == review_reference
    ):
        errors.append("reviewed target platform inventory metadata is invalid")
    reviewed = _parse_utc(reviewed_at)
    expires = _parse_utc(valid_until)
    if reviewed is None or expires is None or reviewed >= expires:
        errors.append("reviewed target platform inventory validity window is invalid")
    elif reviewed > evaluation_time:
        errors.append("reviewed target platform inventory timestamp is in the future")
    elif expires <= evaluation_time:
        errors.append("reviewed target platform inventory is expired")

    if isinstance(public, dict):
        domain = public.get("platform_domain")
        if (
            not _production_domain(domain)
            or public.get("application_origin") != f"https://{domain}"
            or public.get("identity_issuer")
            != f"https://identity.{domain}/realms/email-platform"
            or not _safe_reference(public.get("external_dns_owner_reference"))
            or not _safe_reference(public.get("external_certificate_owner_reference"))
        ):
            errors.append("reviewed target platform public endpoints are invalid")
    if isinstance(control_planes, dict) and not all(
        _safe_reference(value) for value in control_planes.values()
    ):
        errors.append("reviewed target platform control-plane owners are invalid")
    if isinstance(certificates, dict) and not all(
        _safe_reference(certificates.get(key))
        for key in (
            "internal_ca_owner_reference",
            "issuance_owner_reference",
            "rotation_owner_reference",
        )
    ):
        errors.append("reviewed target platform certificate owners are invalid")

    if isinstance(runtime, dict):
        location_values: list[Any] = []
        for key in ("secret_files", "vault_token_directories", "policy_files"):
            mapping = runtime.get(key)
            if isinstance(mapping, dict):
                location_values.extend(mapping.values())
        location_values.extend(
            runtime.get(key)
            for key in (
                "internal_tls_root",
                "rolling_route_directory",
                "evidence_root",
            )
        )
        if (
            runtime.get("repository_external_confirmed") is not True
            or not all(_target_host_path(value) for value in location_values)
            or len(set(location_values)) != len(location_values)
        ):
            errors.append("reviewed target platform runtime locations are invalid")
    return errors


def _env_keys(text: str) -> set[str]:
    return {
        line.split("=", 1)[0]
        for line in text.splitlines()
        if line and not line.lstrip().startswith("#") and "=" in line
    }


def runtime_alignment_errors(
    document: Any,
    *,
    compose_text: str | None = None,
    env_text: str | None = None,
    evaluated_at: datetime | None = None,
) -> list[str]:
    evaluation_time = evaluated_at or _utc_now()
    if inventory_errors(document, evaluated_at=evaluation_time):
        return ["target platform inventory must be valid before runtime alignment"]
    try:
        if compose_text is None:
            _, compose = load_unique_yaml_with_text(COMPOSE)
        else:
            parse_unique_yaml(compose_text)
            compose = compose_text
        env = load_stable_text(ENV_EXAMPLE) if env_text is None else env_text
    except (OSError, UnicodeError, yaml.YAMLError):
        return ["repository deployment input contract is unavailable"]
    errors: list[str] = []
    if not _ENVIRONMENT_INPUT_KEYS.issubset(_env_keys(env)):
        errors.append("repository environment contract is missing inventory inputs")
    compose_inputs = set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", compose))
    if not _COMPOSE_INPUT_KEYS.issubset(compose_inputs):
        errors.append("Compose does not consume the expected inventory inputs")
    return errors


def _load(path: Path) -> Any:
    return load_unique_json(path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify-repository")
    check = commands.add_parser("check")
    check.add_argument("--input", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    evaluation_time = _utc_now()
    path = INVENTORY if arguments.command == "verify-repository" else arguments.input
    try:
        document = _load(path)
    except (OSError, UnicodeError, json.JSONDecodeError):
        print("target-platform-inventory-invalid", file=sys.stderr)
        return 1
    errors = inventory_errors(document, evaluated_at=evaluation_time)
    if arguments.command == "check" and not errors and document.get("synthetic") is not False:
        errors.append("target platform inventory must be reviewed non-synthetic material")
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    alignment = runtime_alignment_errors(document, evaluated_at=evaluation_time)
    if alignment:
        print("; ".join(alignment), file=sys.stderr)
        return 1 if arguments.command == "verify-repository" else 2
    if arguments.command == "verify-repository":
        print("target-platform-inventory-ok status=pending production_acceptance=false")
    else:
        print("target-platform-inventory-aligned production_acceptance=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
