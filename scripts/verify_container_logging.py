"""Verify production Compose services use the reviewed bounded log policy."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Any

import yaml

try:
    from scripts.external_yaml import load_unique_yaml
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_yaml import load_unique_yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
POLICY_KEY = "x-platform-logging"
REVIEWED_POLICY = {
    "driver": "json-file",
    "options": {"max-size": "10m", "max-file": "5"},
}
REQUIRED_SERVICES = {
    "postgres",
    "redis",
    "keycloak",
    "migrate",
    "api",
    "worker-mail",
    "worker-sub2",
    "web",
    "edge",
    "alertmanager",
    "prometheus",
}


def load_compose(path: Path = COMPOSE) -> dict[str, Any]:
    value = load_unique_yaml(path)
    if not isinstance(value, dict):
        raise ValueError("Compose must contain a YAML mapping")
    return value


def validate_container_logging(compose: object) -> list[str]:
    if not isinstance(compose, dict):
        return ["Compose must contain a YAML mapping"]
    errors: list[str] = []
    policy = compose.get(POLICY_KEY)
    if policy != REVIEWED_POLICY:
        errors.append("Compose logging anchor must equal the reviewed bounded policy")
    services = compose.get("services")
    if not isinstance(services, dict):
        return errors + ["Compose services must contain a YAML mapping"]

    for name in sorted(REQUIRED_SERVICES - set(services)):
        errors.append(f"Compose is missing required production service: {name}")

    for name, raw_service in services.items():
        if not isinstance(raw_service, dict):
            errors.append(f"Compose service must be a YAML mapping: {name}")
            continue
        if name == "vault":
            if raw_service.get("profiles") != ["vault-dev"]:
                errors.append("Vault logging exception requires exactly the vault-dev profile")
            logging = raw_service.get("logging")
            if logging is not None and (logging is not policy or logging != REVIEWED_POLICY):
                errors.append("Vault logging must reuse the reviewed policy when configured")
            continue
        logging = raw_service.get("logging")
        if logging is not policy:
            errors.append(f"Production service must reuse the logging anchor: {name}")
        if logging != REVIEWED_POLICY:
            errors.append(f"Production service logging policy is unbounded or unsafe: {name}")
    if "vault" not in services:
        errors.append("Compose is missing the vault-dev service")
    return errors


def main() -> int:
    try:
        compose = load_compose()
    except (OSError, ValueError, yaml.YAMLError) as error:
        print(f"Container logging asset load failed: {error}", file=sys.stderr)
        return 1
    errors = validate_container_logging(compose)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("container-logging-ok bounded-json-file-policy-on-all-production-services")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
