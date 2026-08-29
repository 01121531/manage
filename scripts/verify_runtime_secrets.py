"""Fail closed when production runtime credentials are injected inline."""

from __future__ import annotations

from pathlib import Path
import re
import sys

import yaml

try:
    from scripts.external_yaml import load_unique_yaml, parse_unique_yaml
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_yaml import load_unique_yaml, parse_unique_yaml

try:
    from scripts.external_text import load_stable_text
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_text import load_stable_text


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
ENV_EXAMPLE = ROOT / ".env.example"
POSTGRES_INIT = ROOT / "infra/postgres/init/02-create-platform-runtime-role.sh"
POSTGRES_HEALTHCHECK = ROOT / "infra/postgres-healthcheck.sh"
REDIS_HEALTHCHECK = ROOT / "infra/redis-healthcheck.sh"
CONFIG = ROOT / "platform/config.py"
MIGRATION = ROOT / "platform/migrations/env.py"
ASSET_PATHS = (
    ENV_EXAMPLE,
    POSTGRES_INIT,
    POSTGRES_HEALTHCHECK,
    REDIS_HEALTHCHECK,
    CONFIG,
    MIGRATION,
)

FORBIDDEN_ENV_KEYS = {
    "POSTGRES_PASSWORD",
    "POSTGRES_APP_PASSWORD",
    "KEYCLOAK_DB_PASSWORD",
    "KC_DB_PASSWORD",
    "KC_BOOTSTRAP_ADMIN_PASSWORD",
    "KEYCLOAK_ADMIN_PASSWORD",
    "REDIS_PASSWORD",
    "PLATFORM_DATABASE_URL",
    "PLATFORM_MIGRATION_DATABASE_URL",
    "ALEMBIC_DATABASE_URL",
    "PLATFORM_REDIS_URL",
}


def _env_values(text: str) -> dict[str, str]:
    return {
        line.split("=", 1)[0]: line.split("=", 1)[1]
        for line in text.splitlines()
        if line and not line.lstrip().startswith("#") and "=" in line
    }


def _mount(service: dict, target: str) -> dict | None:
    for mount in service.get("volumes", []):
        if isinstance(mount, dict) and mount.get("target") == target:
            return mount
    return None


def _require_read_only_bind(
    errors: list[str], service_name: str, service: dict, target: str
) -> None:
    mount = _mount(service, target)
    if mount is None:
        errors.append(f"{service_name} must mount {target}")
        return
    if mount.get("read_only") is not True:
        errors.append(f"{service_name} secret mount {target} must be read-only")
    if mount.get("type") != "bind" or mount.get("bind", {}).get(
        "create_host_path"
    ) is not False:
        errors.append(
            f"{service_name} secret mount {target} must be an external fail-closed bind"
        )


def load_text_assets(paths: tuple[Path, ...] | None = None) -> dict[Path, str]:
    selected_paths = ASSET_PATHS if paths is None else paths
    return {path: load_stable_text(path) for path in selected_paths}


def _descriptor_secret_errors(
    label: str,
    source: str,
    *,
    path_variable: str,
    value_variable: str,
) -> list[str]:
    path = f'"${path_variable}"'
    markers = (
        f'exec 9<{path}',
        '[ ! -f "/proc/self/fd/9" ]',
        f'{path} -ef "/proc/self/fd/9"',
        f"read -r {value_variable} <&9",
        "read -r extra <&9",
        "exec 9<&-",
    )
    errors = [
        f"{label} is missing descriptor-bound secret handling: {marker}"
        for marker in markers
        if marker not in source
    ]
    if source.count(f'{path} -ef "/proc/self/fd/9"') < 2:
        errors.append(f"{label} must bind the secret path before and after reading")
    if (
        re.search(rf"awk[^\n]*\$\{{?{re.escape(path_variable)}\}}?", source)
        or f'< {path}' in source
        or f'[ ! -r {path} ]' in source
    ):
        errors.append(f"{label} must not reopen the secret by path")
    return errors


def verification_errors(
    *,
    compose_text: str | None = None,
    env_text: str | None = None,
    postgres_init_text: str | None = None,
    postgres_healthcheck_text: str | None = None,
    redis_healthcheck_text: str | None = None,
    config_text: str | None = None,
    migration_text: str | None = None,
) -> list[str]:
    requested_assets = (
        (ENV_EXAMPLE, env_text),
        (POSTGRES_INIT, postgres_init_text),
        (POSTGRES_HEALTHCHECK, postgres_healthcheck_text),
        (REDIS_HEALTHCHECK, redis_healthcheck_text),
        (CONFIG, config_text),
        (MIGRATION, migration_text),
    )
    missing_paths = tuple(path for path, text in requested_assets if text is None)
    default_assets = load_text_assets(missing_paths)
    env_source = default_assets[ENV_EXAMPLE] if env_text is None else env_text
    init_source = (
        default_assets[POSTGRES_INIT]
        if postgres_init_text is None
        else postgres_init_text
    )
    postgres_health_source = (
        default_assets[POSTGRES_HEALTHCHECK]
        if postgres_healthcheck_text is None
        else postgres_healthcheck_text
    )
    health_source = (
        default_assets[REDIS_HEALTHCHECK]
        if redis_healthcheck_text is None
        else redis_healthcheck_text
    )
    config_source = default_assets[CONFIG] if config_text is None else config_text
    migration_source = (
        default_assets[MIGRATION] if migration_text is None else migration_text
    )
    errors: list[str] = []

    env_values = _env_values(env_source)
    present_forbidden = sorted(FORBIDDEN_ENV_KEYS & env_values.keys())
    if present_forbidden:
        errors.append(".env.example contains inline credential settings: " + ", ".join(present_forbidden))
    required_host_paths = {
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
    for name in sorted(required_host_paths):
        value = env_values.get(name, "")
        if not value.startswith("/"):
            errors.append(f"{name} must be an absolute external host path")

    try:
        compose = (
            load_unique_yaml(COMPOSE)
            if compose_text is None
            else parse_unique_yaml(compose_text)
        )
        services = compose["services"]
    except (KeyError, OSError, TypeError, UnicodeError, yaml.YAMLError) as exc:
        return [f"Cannot inspect Compose runtime secrets: {exc}"]

    for service_name, service in services.items():
        environment = service.get("environment") or {}
        if isinstance(environment, dict):
            forbidden = sorted(FORBIDDEN_ENV_KEYS & environment.keys())
            if forbidden and service_name != "vault":
                errors.append(f"{service_name} injects inline credential settings: {', '.join(forbidden)}")
            for name, value in environment.items():
                if name != "VAULT_DEV_ROOT_TOKEN_ID" and re.search(r"^[a-z][a-z0-9+.-]*://[^/@\s]+:[^/@\s]+@", str(value), re.I):
                    errors.append(f"{service_name} {name} contains a credential-bearing URI")
        command = " ".join(str(item) for item in service.get("command", []))
        if service_name != "vault" and ("--requirepass" in command or re.search(r"\$\{[^}]*PASSWORD", command)):
            errors.append(f"{service_name} command contains an inline password")

    postgres = services["postgres"]
    postgres_env = postgres.get("environment", {})
    expected_postgres = {
        "POSTGRES_PASSWORD_FILE": "/run/secrets/postgres/superuser-password",
        "POSTGRES_APP_PASSWORD_FILE": "/run/secrets/postgres/platform-password",
        "KEYCLOAK_DB_PASSWORD_FILE": "/run/secrets/postgres/keycloak-password",
    }
    for name, target in expected_postgres.items():
        if postgres_env.get(name) != target:
            errors.append(f"postgres must set {name} to {target}")
        _require_read_only_bind(errors, "postgres", postgres, target)
    if (postgres.get("healthcheck") or {}).get("test") != [
        "CMD",
        "sh",
        "/usr/local/bin/postgres-healthcheck",
    ]:
        errors.append(
            "postgres healthcheck must use the credential-authenticating exec-form helper"
        )
    _require_read_only_bind(
        errors, "postgres", postgres, "/usr/local/bin/postgres-healthcheck"
    )

    postgres_health_markers = (
        "set -eu",
        ': "${POSTGRES_DB:?POSTGRES_DB is required}"',
        ': "${POSTGRES_USER:?POSTGRES_USER is required}"',
        ': "${POSTGRES_PASSWORD_FILE:?POSTGRES_PASSWORD_FILE is required}"',
        ': "${POSTGRES_APP_USER:?POSTGRES_APP_USER is required}"',
        ': "${POSTGRES_APP_PASSWORD_FILE:?POSTGRES_APP_PASSWORD_FILE is required}"',
        ': "${KEYCLOAK_DB_USER:?KEYCLOAK_DB_USER is required}"',
        ': "${KEYCLOAK_DB_PASSWORD_FILE:?KEYCLOAK_DB_PASSWORD_FILE is required}"',
        "umask 077",
        "mktemp /tmp/postgres-healthcheck.XXXXXX",
        "trap 'rm -f \"$pgpass_file\"' EXIT",
        "trap 'exit 1' HUP INT TERM",
        'chmod 600 "$pgpass_file"',
        'if [ -z "$password" ]',
        "unset password password_field",
        'PGPASSFILE="$pgpass_file" psql',
        "--no-password",
        "--set=ON_ERROR_STOP=1",
        "--command='SELECT 1'",
        'check_database "$POSTGRES_DB" "$POSTGRES_USER" "$POSTGRES_PASSWORD_FILE"',
        'check_database "$POSTGRES_DB" "$POSTGRES_APP_USER" "$POSTGRES_APP_PASSWORD_FILE"',
        'check_database "keycloak" "$KEYCLOAK_DB_USER" "$KEYCLOAK_DB_PASSWORD_FILE"',
    )
    for marker in postgres_health_markers:
        if marker not in postgres_health_source:
            errors.append(f"PostgreSQL healthcheck helper is missing: {marker}")
    errors.extend(
        _descriptor_secret_errors(
            "PostgreSQL healthcheck helper",
            postgres_health_source,
            path_variable="password_file",
            value_variable="password",
        )
    )
    if (
        "set -x" in postgres_health_source
        or "PGPASSWORD" in postgres_health_source
        or "export PGPASSFILE" in postgres_health_source
        or re.search(r"--password(?:=|\s)", postgres_health_source)
        or re.search(r"\becho\b[^\n]*\$password\b", postgres_health_source)
    ):
        errors.append(
            "PostgreSQL healthcheck may expose authentication outside a child-only PGPASSFILE"
        )

    expected_url_files = {
        "migrate": ("ALEMBIC_DATABASE_URL_FILE", "/run/secrets/runtime/migration-database-url"),
        "api": ("PLATFORM_DATABASE_URL_FILE", "/run/secrets/runtime/database-url"),
        "worker-mail": ("PLATFORM_DATABASE_URL_FILE", "/run/secrets/runtime/database-url"),
        "worker-sub2": ("PLATFORM_DATABASE_URL_FILE", "/run/secrets/runtime/database-url"),
    }
    for name, (setting, target) in expected_url_files.items():
        service = services[name]
        if (service.get("environment") or {}).get(setting) != target:
            errors.append(f"{name} must set {setting} to {target}")
        _require_read_only_bind(errors, name, service, target)
    for service_name in ("api", "worker-sub2"):
        service = services[service_name]
        if (service.get("environment") or {}).get(
            "PLATFORM_REDIS_URL_FILE"
        ) != "/run/secrets/runtime/redis-url":
            errors.append(f"{service_name} must use PLATFORM_REDIS_URL_FILE")
        _require_read_only_bind(
            errors, service_name, service, "/run/secrets/runtime/redis-url"
        )

    redis = services["redis"]
    if redis.get("command") != ["redis-server", "/run/config/redis.conf"]:
        errors.append("redis must start only from the external redis.conf")
    if (redis.get("healthcheck") or {}).get("test") != ["CMD", "/usr/local/bin/redis-healthcheck"]:
        errors.append("redis healthcheck must not contain credentials or authentication argv")
    for target in ("/run/config/redis.conf", "/run/secrets/redis/users.acl", "/run/secrets/redis/healthcheck-password"):
        _require_read_only_bind(errors, "redis", redis, target)
    for marker in ("REDIS_HEALTHCHECK_PASSWORD_FILE", "printf '%s\\n'", "--askpass", "--user healthcheck"):
        if marker not in health_source:
            errors.append(f"Redis healthcheck helper is missing: {marker}")
    errors.extend(
        _descriptor_secret_errors(
            "Redis healthcheck helper",
            health_source,
            path_variable="password_file",
            value_variable="password",
        )
    )
    if "REDISCLI_AUTH" in health_source or re.search(
        r"redis-cli[^\n]*(?:\s-a\s|--pass(?:word)?(?:=|\s))", health_source
    ):
        errors.append("Redis healthcheck exposes authentication through argv")

    keycloak = services["keycloak"]
    if "--config-file=/opt/keycloak/conf/runtime.conf" not in keycloak.get("command", []):
        errors.append("keycloak must load its external runtime.conf")
    _require_read_only_bind(errors, "keycloak", keycloak, "/opt/keycloak/conf/runtime.conf")
    if any(name.startswith("KC_DB_") or name.startswith("KC_BOOTSTRAP_ADMIN_") for name in (keycloak.get("environment") or {})):
        errors.append("keycloak database/bootstrap credentials must exist only in runtime.conf")

    for marker in ("POSTGRES_PASSWORD_FILE", "POSTGRES_APP_PASSWORD_FILE", "KEYCLOAK_DB_PASSWORD_FILE", "read_secret_file", "unset POSTGRES_BOOTSTRAP_PASSWORD"):
        if marker not in init_source:
            errors.append(f"PostgreSQL init is missing safe file handling: {marker}")
    errors.extend(
        _descriptor_secret_errors(
            "PostgreSQL init helper",
            init_source,
            path_variable="file_path",
            value_variable="value",
        )
    )
    for marker in (
        "database_url_file",
        "redis_url_file",
        "require_file",
        "_read_runtime_secret",
        "read_stable_runtime_bytes_with_metadata(",
        "stat.S_IWGRP | stat.S_IWOTH",
        'raw.decode("utf-8")',
    ):
        if marker not in config_source:
            errors.append(f"Platform config is missing file-only runtime handling: {marker}")
    for marker in ("ALEMBIC_DATABASE_URL_FILE", "managed_environment", "forbids inline database URLs"):
        if marker not in migration_source:
            errors.append(f"Alembic is missing production file-only handling: {marker}")
    return errors


def main() -> int:
    try:
        errors = verification_errors()
    except OSError:
        print("Cannot inspect runtime secret assets", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("runtime-secrets-ok file-only=postgres,platform,redis,keycloak")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
