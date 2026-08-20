"""Verify Vault credentials and policies are isolated by runtime service."""

from __future__ import annotations

from pathlib import Path
import re
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
ENV_EXAMPLE = ROOT / ".env.example"
VAULT_DIR = ROOT / "infra" / "vault"

SERVICE_TOKEN_SOURCES = {
    "api": "${PLATFORM_VAULT_API_TOKEN:-}",
    "worker-mail": "${PLATFORM_VAULT_MAIL_TOKEN:-}",
    "worker-sub2": "${PLATFORM_VAULT_SUB2_TOKEN:-}",
}
POLICY_PATHS = {
    "email-platform-api-cards.hcl": {"secret/data/cards/*"},
    "email-platform-mail.hcl": {"secret/data/mailboxes/*"},
    "email-platform-sub2.hcl": {
        "secret/data/cards/*",
        "secret/data/sub2/credential",
        "secret/data/sub2/proxy",
    },
}
DEPLOYMENT_CREDENTIALS = {
    f"PLATFORM_VAULT_{service}_{kind}"
    for service in ("API", "MAIL", "SUB2")
    for kind in ("TOKEN", "ROLE_ID", "SECRET_ID")
}


def _service_environment(service: object) -> dict[str, object]:
    if not isinstance(service, dict):
        return {}
    environment = service.get("environment", {})
    return environment if isinstance(environment, dict) else {}


def _env_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        values[name] = value
    return values


def load_assets() -> tuple[dict[str, object], str, dict[str, str], str]:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    policies = {
        name: (VAULT_DIR / "policies" / name).read_text(encoding="utf-8")
        for name in POLICY_PATHS
    }
    return (
        compose,
        ENV_EXAMPLE.read_text(encoding="utf-8"),
        policies,
        (VAULT_DIR / "configure-approles.sh").read_text(encoding="utf-8"),
    )


def validate_vault_isolation(
    compose: dict[str, object],
    env_text: str,
    policies: dict[str, str],
    bootstrap: str,
) -> list[str]:
    errors: list[str] = []
    services = compose.get("services", {})
    if not isinstance(services, dict):
        return ["Compose services block is invalid"]

    for service_name, expected_source in SERVICE_TOKEN_SOURCES.items():
        environment = _service_environment(services.get(service_name))
        if environment.get("PLATFORM_VAULT_TOKEN") != expected_source:
            errors.append(
                f"{service_name} PLATFORM_VAULT_TOKEN must come only from {expected_source}"
            )
        leaked = sorted(DEPLOYMENT_CREDENTIALS.intersection(environment))
        if leaked:
            errors.append(
                f"{service_name} must not receive deployment AppRole variables: "
                + ", ".join(leaked)
            )
        serialized_environment = yaml.safe_dump(environment)
        allowed_source = expected_source.removeprefix("${").split(":", 1)[0]
        unexpected_sources = sorted(
            name
            for name in DEPLOYMENT_CREDENTIALS
            if name != allowed_source and f"${{{name}" in serialized_environment
        )
        if unexpected_sources:
            errors.append(
                f"{service_name} references another service/AppRole credential: "
                + ", ".join(unexpected_sources)
            )

    for service_name in ("migrate", "web"):
        environment = _service_environment(services.get(service_name))
        leaked = sorted(name for name in environment if name.startswith("PLATFORM_VAULT_"))
        if leaked:
            errors.append(f"{service_name} must not receive Vault credentials")

    env_values = _env_values(env_text)
    if "PLATFORM_VAULT_TOKEN" in env_values:
        errors.append("Shared PLATFORM_VAULT_TOKEN must not be declared")
    missing = sorted(DEPLOYMENT_CREDENTIALS - env_values.keys())
    if missing:
        errors.append("Missing per-service Vault variables: " + ", ".join(missing))
    for name in DEPLOYMENT_CREDENTIALS:
        value = env_values.get(name, "")
        if value and not value.startswith("CHANGE_ME_"):
            errors.append(f"{name} must be empty or an unusable placeholder")

    for policy_name, allowed_paths in POLICY_PATHS.items():
        policy = policies.get(policy_name, "")
        paths = set(re.findall(r'^path\s+"([^"]+)"', policy, re.MULTILINE))
        if paths != allowed_paths:
            errors.append(
                f"{policy_name} paths must be exactly {sorted(allowed_paths)}"
            )
        capabilities = re.findall(r"capabilities\s*=\s*\[([^]]*)\]", policy)
        if len(capabilities) != len(allowed_paths) or any(
            set(re.findall(r'"([^"]+)"', item)) != {"read"}
            for item in capabilities
        ):
            errors.append(f"{policy_name} must grant read only on every path")

    required_bootstrap_fragments = {
        "bind_secret_id=true",
        "token_no_default_policy=true",
        "token_type=service",
        "secret_id_num_uses=1",
        "secret_id_ttl=10m",
        "token_ttl=15m",
        "token_max_ttl=1h",
    }
    missing_fragments = sorted(
        fragment for fragment in required_bootstrap_fragments if fragment not in bootstrap
    )
    if missing_fragments:
        errors.append(
            "AppRole helper is missing safe defaults: " + ", ".join(missing_fragments)
        )
    forbidden_bootstrap = ("auth/approle/login", "secret-id/lookup", "-field=secret_id")
    if any(fragment in bootstrap for fragment in forbidden_bootstrap):
        errors.append("AppRole helper must not retrieve or exchange deployment credentials")

    return errors


def main() -> int:
    try:
        assets = load_assets()
    except (OSError, yaml.YAMLError) as error:
        print(f"Unable to load Vault isolation assets: {error}", file=sys.stderr)
        return 1
    errors = validate_vault_isolation(*assets)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(
        "vault-isolation-ok api=cards-only mail=mailboxes-only "
        "sub2=sub2-and-cards-only"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
