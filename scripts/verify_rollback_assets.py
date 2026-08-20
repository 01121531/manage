"""Verify Compose uses rollback-safe shared image overrides."""

from __future__ import annotations

from pathlib import Path
import re

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
ENV_EXAMPLE = ROOT / ".env.example"

EXPECTED_IMAGES = {
    "migrate": "${PLATFORM_API_IMAGE:-email-platform-api:local}",
    "api": "${PLATFORM_API_IMAGE:-email-platform-api:local}",
    "worker-mail": "${PLATFORM_API_IMAGE:-email-platform-api:local}",
    "worker-sub2": "${PLATFORM_API_IMAGE:-email-platform-api:local}",
    "web": "${PLATFORM_WEB_IMAGE:-email-platform-web:local}",
    "edge": "${PLATFORM_EDGE_IMAGE:-email-platform-edge:local}",
}
REQUIRED_IMAGE_VARIABLES = {
    "PLATFORM_API_IMAGE",
    "PLATFORM_WEB_IMAGE",
    "PLATFORM_EDGE_IMAGE",
}
VARIABLE_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?}")


def _env_keys(text: str) -> set[str]:
    return {
        line.split("=", 1)[0].strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#") and "=" in line
    }


def _is_worker_image_variable(name: str) -> bool:
    upper_name = name.upper()
    return "WORKER" in upper_name and "IMAGE" in upper_name


def rollback_asset_errors(compose_text: str, env_text: str) -> list[str]:
    try:
        compose = yaml.safe_load(compose_text)
    except yaml.YAMLError as error:
        return [f"docker-compose.yml is invalid YAML: {error}"]
    if not isinstance(compose, dict) or not isinstance(compose.get("services"), dict):
        return ["docker-compose.yml must contain a services mapping"]

    services = compose["services"]
    errors: list[str] = []
    image_variables: set[str] = set()
    for service_name, expected_image in EXPECTED_IMAGES.items():
        service = services.get(service_name)
        if not isinstance(service, dict):
            errors.append(f"missing service: {service_name}")
            continue
        image = service.get("image")
        if image != expected_image:
            errors.append(
                f"{service_name} image must be {expected_image}, got {image!r}"
            )
        if isinstance(image, str):
            image_variables.update(VARIABLE_PATTERN.findall(image))

    env_keys = _env_keys(env_text)
    missing_variables = sorted(REQUIRED_IMAGE_VARIABLES - env_keys)
    if missing_variables:
        errors.append(
            ".env.example is missing image variables: "
            + ", ".join(missing_variables)
        )
    independent_worker_variables = sorted(
        name
        for name in image_variables | env_keys
        if _is_worker_image_variable(name)
    )
    if independent_worker_variables:
        errors.append(
            "independent worker image variables are forbidden: "
            + ", ".join(independent_worker_variables)
        )
    return errors


def main() -> int:
    errors = rollback_asset_errors(
        COMPOSE.read_text(encoding="utf-8"),
        ENV_EXAMPLE.read_text(encoding="utf-8"),
    )
    if errors:
        for error in errors:
            print(f"rollback-assets-error: {error}")
        return 1
    print("rollback-assets-ok shared-images-and-immutable-overrides-documented")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
