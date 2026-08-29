"""Verify compose variables and PostgreSQL database-role isolation."""

from __future__ import annotations

import pathlib
import re
import sys

import yaml

try:
    from scripts.external_text import load_stable_text
    from scripts.external_yaml import parse_unique_yaml, read_stable_yaml_text
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_text import load_stable_text  # type: ignore[no-redef]
    from external_yaml import parse_unique_yaml, read_stable_yaml_text


ROOT = pathlib.Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
ENV_EXAMPLE = ROOT / ".env.example"
POSTGRES_INIT = (
    ROOT / "infra" / "postgres" / "init" / "02-create-platform-runtime-role.sh"
)

KEYCLOAK_USER_REF = "${KEYCLOAK_DB_USER:?set KEYCLOAK_DB_USER in .env}"
KEYCLOAK_PASSWORD_FILE = "/run/secrets/postgres/keycloak-password"
DEVICE_LIMIT_REF = "${PLATFORM_MAX_ACTIVE_DEVICES_PER_USER:-5}"


def _env_values(env_text: str) -> dict[str, str]:
    return {
        line.split("=", 1)[0]: line.split("=", 1)[1]
        for line in env_text.splitlines()
        if line and not line.lstrip().startswith("#") and "=" in line
    }


def verification_errors(
    *,
    compose_text: str | None = None,
    env_text: str | None = None,
    init_text: str | None = None,
) -> list[str]:
    compose_source = (
        read_stable_yaml_text(COMPOSE) if compose_text is None else compose_text
    )
    try:
        env_source = (
            load_stable_text(ENV_EXAMPLE) if env_text is None else env_text
        )
        init_source = (
            load_stable_text(POSTGRES_INIT) if init_text is None else init_text
        )
    except (OSError, UnicodeError):
        return ["Cannot inspect compose database roles"]
    errors: list[str] = []

    variables = set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)", compose_source))
    env_values = _env_values(env_source)
    missing = sorted(variables - set(env_values))
    if missing:
        errors.append("Missing .env.example variables: " + ", ".join(missing))

    try:
        compose = parse_unique_yaml(compose_source)
        services = compose["services"]
        postgres_env = services["postgres"]["environment"]
        api_env = services["api"]["environment"]
    except (KeyError, TypeError, yaml.YAMLError) as error:
        errors.append(f"Cannot inspect compose database roles: {error}")
        return errors

    expected_compose = (
        (postgres_env, "KEYCLOAK_DB_USER", KEYCLOAK_USER_REF),
        (postgres_env, "KEYCLOAK_DB_PASSWORD_FILE", KEYCLOAK_PASSWORD_FILE),
        (
            api_env,
            "PLATFORM_MAX_ACTIVE_DEVICES_PER_USER",
            DEVICE_LIMIT_REF,
        ),
    )
    for environment, name, expected in expected_compose:
        if environment.get(name) != expected:
            errors.append(f"Compose {name} does not use the reviewed environment source")

    for name in ("KEYCLOAK_DB_USER", "KEYCLOAK_DB_PASSWORD_FILE"):
        if not env_values.get(name):
            errors.append(f".env.example must define {name}")
    if env_values.get("KEYCLOAK_DB_USER") in {
        env_values.get("POSTGRES_USER"),
        env_values.get("POSTGRES_APP_USER"),
    }:
        errors.append("Keycloak database user must be distinct from platform database roles")
    if env_values.get("KEYCLOAK_DB_PASSWORD_FILE") in {
        env_values.get("POSTGRES_PASSWORD_FILE"),
        env_values.get("POSTGRES_APP_PASSWORD_FILE"),
    }:
        errors.append("Keycloak database password placeholder must be distinct")

    init_markers = (
        r"\getenv app_password POSTGRES_APP_PASSWORD",
        r"\getenv keycloak_user KEYCLOAK_DB_USER",
        r"\getenv keycloak_password KEYCLOAK_DB_PASSWORD",
        'read_secret_file KEYCLOAK_DB_PASSWORD "$KEYCLOAK_DB_PASSWORD_FILE"',
        "ALTER DATABASE keycloak OWNER TO %I",
        r"\getenv bootstrap_user POSTGRES_USER",
        'REASSIGN OWNED BY :"bootstrap_user" TO :"keycloak_user"',
        '"$KEYCLOAK_DB_USER" = "$POSTGRES_USER"',
        '"$KEYCLOAK_DB_USER" = "$POSTGRES_APP_USER"',
        '"$KEYCLOAK_DB_PASSWORD" = "$POSTGRES_BOOTSTRAP_PASSWORD"',
        '"$KEYCLOAK_DB_PASSWORD" = "$POSTGRES_APP_PASSWORD"',
    )
    for marker in init_markers:
        if marker not in init_source:
            errors.append(
                f"PostgreSQL init is missing Keycloak role guard: {marker}"
            )
    for marker in ("NOSUPERUSER", "NOCREATEDB", "NOCREATEROLE", "NOINHERIT"):
        if init_source.count(marker) < 2:
            errors.append(f"Both runtime database roles must enforce {marker}")
    for marker in ("--set=app_password", "--set=keycloak_password", "set -x"):
        if marker in init_source:
            errors.append(
                f"PostgreSQL init may expose a password through argv/logging: {marker}"
            )
    return errors


def main() -> int:
    try:
        compose_source = read_stable_yaml_text(COMPOSE)
    except (OSError, UnicodeError) as error:
        print(f"Cannot inspect compose database roles: {error}", file=sys.stderr)
        return 1
    errors = verification_errors(compose_text=compose_source)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    variables = set(
        re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)", compose_source)
    )
    print(
        f"compose-env-ok variables={len(variables)} keycloak-db-role=isolated "
        f"file={COMPOSE.relative_to(ROOT)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
