"""Verify that compose service boundaries keep secrets on the right side."""

from __future__ import annotations

from pathlib import Path
import sys

import yaml

try:
    from scripts.external_yaml import load_unique_yaml
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from external_yaml import load_unique_yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
EXPECTED_SERVICE_NETWORKS = {
    "postgres": {"postgres-backend"},
    "redis": {"redis-backend"},
    "keycloak": {"frontend", "postgres-backend", "metrics"},
    "vault": {"vault-backend"},
    "migrate": {"postgres-backend"},
    "api": {
        "frontend",
        "postgres-backend",
        "redis-backend",
        "vault-backend",
        "metrics",
    },
    "worker-mail": {"postgres-backend", "vault-backend", "metrics"},
    "worker-sub2": {
        "postgres-backend",
        "redis-backend",
        "vault-backend",
        "metrics",
    },
    "web": {"frontend"},
    "edge": {"frontend"},
    "alertmanager": {"alerting"},
    "prometheus": {"metrics", "alerting"},
}
DATA_ONLY_SERVICES = {"postgres", "redis", "vault", "migrate"}
SCRAPE_TARGET_SERVICES = {"api", "keycloak", "worker-mail", "worker-sub2"}
MAIL_ALLOWED_ORIGINS_CONTAINER_PATH = "/run/config/mail/allowed-origins"
MAIL_ALLOWED_ORIGINS_SOURCE = (
    "${PLATFORM_MAIL_ALLOWED_ORIGINS_FILE:?set "
    "PLATFORM_MAIL_ALLOWED_ORIGINS_FILE in .env}"
)
MAIL_ALLOWED_ORIGINS_VOLUME = {
    "type": "bind",
    "source": MAIL_ALLOWED_ORIGINS_SOURCE,
    "target": MAIL_ALLOWED_ORIGINS_CONTAINER_PATH,
    "read_only": True,
    "bind": {"create_host_path": False},
}
SUB2_ALLOWED_ORIGINS_CONTAINER_PATH = "/run/config/sub2/allowed-origins"
SUB2_ALLOWED_ORIGINS_SOURCE = (
    "${PLATFORM_SUB2_ALLOWED_ORIGINS_FILE:?set "
    "PLATFORM_SUB2_ALLOWED_ORIGINS_FILE in .env}"
)
SUB2_ALLOWED_ORIGINS_VOLUME = {
    "type": "bind",
    "source": SUB2_ALLOWED_ORIGINS_SOURCE,
    "target": SUB2_ALLOWED_ORIGINS_CONTAINER_PATH,
    "read_only": True,
    "bind": {"create_host_path": False},
}
SUB2_POLICY_INPUTS = (
    "PLATFORM_SUB2_POLICY_VERSION",
    "PLATFORM_SUB2_GROUP_ID",
    "PLATFORM_SUB2_CONCURRENCY",
    "PLATFORM_SUB2_PROXY_REF",
    "PLATFORM_SUB2_CREDENTIAL_REF",
    "PLATFORM_SUB2_UPLOAD_URL",
)


def _service_env(service: dict[str, object]) -> dict[str, object]:
    env = service.get("environment", {})
    if isinstance(env, dict):
        return env
    if isinstance(env, list):
        result: dict[str, object] = {}
        for item in env:
            if not isinstance(item, str) or "=" not in item:
                continue
            key, value = item.split("=", 1)
            result[key] = value
        return result
    return {}


def _service_networks(service: object) -> set[str]:
    if not isinstance(service, dict):
        return set()
    networks = service.get("networks", [])
    if isinstance(networks, list):
        return {str(item) for item in networks}
    if isinstance(networks, dict):
        return {str(item) for item in networks}
    return set()


def validate_service_boundaries(compose: object) -> list[str]:
    if not isinstance(compose, dict):
        return ["Compose document must be a mapping"]
    errors: list[str] = []
    services = compose.get("services", {})
    if not isinstance(services, dict):
        return ["Compose services block is invalid"]

    declared_networks = compose.get("networks", {})
    required_networks = {
        "frontend",
        "postgres-backend",
        "redis-backend",
        "vault-backend",
        "metrics",
        "alerting",
    }
    if not isinstance(declared_networks, dict) or set(declared_networks) != required_networks:
        errors.append(
            "Compose network declarations do not match the reviewed service topology"
        )
    else:
        for name in sorted(required_networks):
            network = declared_networks.get(name)
            if not isinstance(network, dict) or network.get("driver") != "bridge":
                errors.append(f"{name} network must use the bridge driver")
        for name in ("postgres-backend", "redis-backend", "vault-backend"):
            network = declared_networks.get(name)
            if not isinstance(network, dict) or network.get("internal") is not True:
                errors.append(
                    f"{name} network must be internal without a default external gateway"
                )

    actual_networks: dict[str, set[str]] = {}
    for service_name, expected in EXPECTED_SERVICE_NETWORKS.items():
        service = services.get(service_name)
        if not isinstance(service, dict):
            errors.append(f"Missing service {service_name}")
            actual_networks[service_name] = set()
            continue
        if "network_mode" in service:
            errors.append(f"{service_name} must not set network_mode")
        actual = _service_networks(service)
        actual_networks[service_name] = actual
        if actual != expected:
            errors.append(
                f"{service_name} networks must be exactly {sorted(expected)}"
            )

    required_pairs = {
        ("edge", target) for target in ("web", "api", "keycloak")
    }
    required_pairs.update(
        (client, "postgres")
        for client in ("api", "keycloak", "worker-mail", "worker-sub2")
    )
    required_pairs.update(
        (client, "redis") for client in ("api", "worker-sub2")
    )
    required_pairs.update(
        (client, "vault") for client in ("api", "worker-mail", "worker-sub2")
    )
    required_pairs.update(
        ("prometheus", target)
        for target in SCRAPE_TARGET_SERVICES
    )
    required_pairs.add(("prometheus", "alertmanager"))
    for source, target in sorted(required_pairs):
        if not actual_networks.get(source, set()).intersection(
            actual_networks.get(target, set())
        ):
            errors.append(f"Required network path is missing: {source} -> {target}")

    forbidden_pairs = {
        (monitoring, data_service)
        for monitoring in ("prometheus", "alertmanager")
        for data_service in DATA_ONLY_SERVICES
    }
    forbidden_pairs.update(
        ("alertmanager", target) for target in SCRAPE_TARGET_SERVICES
    )
    for source, target in sorted(forbidden_pairs):
        shared = actual_networks.get(source, set()).intersection(
            actual_networks.get(target, set())
        )
        if shared:
            errors.append(
                f"Forbidden network path exists: {source} -> {target}: "
                + ", ".join(sorted(shared))
            )

    data_plane = {
        "postgres",
        "redis",
        "vault",
        "migrate",
        "worker-mail",
        "worker-sub2",
        "alertmanager",
        "prometheus",
    }
    for public_service in ("edge", "web"):
        for data_service in sorted(data_plane):
            shared = actual_networks.get(public_service, set()).intersection(
                actual_networks.get(data_service, set())
            )
            if shared:
                errors.append(
                    f"{public_service} must be isolated from {data_service}: "
                    + ", ".join(sorted(shared))
                )

    api = services.get("api")
    mail_worker = services.get("worker-mail")
    sub2_worker = services.get("worker-sub2")
    if not isinstance(api, dict) or not isinstance(mail_worker, dict) or not isinstance(sub2_worker, dict):
        errors.append("Missing api, worker-mail or worker-sub2 service")
        return errors

    for name, worker in (
        ("worker-mail", mail_worker),
        ("worker-sub2", sub2_worker),
    ):
        if worker.get("ports"):
            errors.append(f"{name} must not publish a host port")

    api_env = _service_env(api)
    mail_env = _service_env(mail_worker)
    sub2_env = _service_env(sub2_worker)

    forbidden_api = {
        "PLATFORM_MAIL_API_URL",
        "PLATFORM_MAIL_TIMEOUT_SECONDS",
        "PLATFORM_MAIL_ALLOWED_ORIGINS_FILE",
        "PLATFORM_SUB2_ALLOWED_ORIGINS_FILE",
    }
    unexpected_api = sorted(name for name in forbidden_api if name in api_env)
    if unexpected_api:
        errors.append(
            "API service must not carry worker-only upstream envs: "
            + ", ".join(unexpected_api)
        )

    api_sub2_policy = {name: api_env.get(name) for name in SUB2_POLICY_INPUTS}
    worker_sub2_policy = {name: sub2_env.get(name) for name in SUB2_POLICY_INPUTS}
    if any(value is None for value in api_sub2_policy.values()):
        errors.append("API service must carry all server-owned Sub2 policy inputs")
    if api_sub2_policy != worker_sub2_policy:
        errors.append("API and worker-sub2 Sub2 policy inputs must match exactly")

    if "PLATFORM_MAIL_API_URL" not in mail_env:
        errors.append("worker-mail must carry PLATFORM_MAIL_API_URL")
    if "PLATFORM_MAIL_POLL_MODE" not in mail_env:
        errors.append("worker-mail must carry PLATFORM_MAIL_POLL_MODE")
    if (
        mail_env.get("PLATFORM_MAIL_ALLOWED_ORIGINS_FILE")
        != MAIL_ALLOWED_ORIGINS_CONTAINER_PATH
    ):
        errors.append("worker-mail allowed origins environment identity is invalid")
    mail_volumes = mail_worker.get("volumes", [])
    mail_allowed_origin_volumes = (
        [
            volume
            for volume in mail_volumes
            if isinstance(volume, dict)
            and volume.get("target") == MAIL_ALLOWED_ORIGINS_CONTAINER_PATH
        ]
        if isinstance(mail_volumes, list)
        else []
    )
    if mail_allowed_origin_volumes != [MAIL_ALLOWED_ORIGINS_VOLUME]:
        errors.append("worker-mail allowed origins volume identity is invalid")

    if "PLATFORM_SUB2_UPLOAD_URL" not in sub2_env:
        errors.append("worker-sub2 must carry PLATFORM_SUB2_UPLOAD_URL")
    if (
        sub2_env.get("PLATFORM_SUB2_ALLOWED_ORIGINS_FILE")
        != SUB2_ALLOWED_ORIGINS_CONTAINER_PATH
    ):
        errors.append("worker-sub2 allowed origins environment identity is invalid")
    volumes = sub2_worker.get("volumes", [])
    allowed_origin_volumes = (
        [
            volume
            for volume in volumes
            if isinstance(volume, dict)
            and volume.get("target") == SUB2_ALLOWED_ORIGINS_CONTAINER_PATH
        ]
        if isinstance(volumes, list)
        else []
    )
    if allowed_origin_volumes != [SUB2_ALLOWED_ORIGINS_VOLUME]:
        errors.append("worker-sub2 allowed origins volume identity is invalid")
    for name in ("PLATFORM_SUB2_PROXY_REF", "PLATFORM_SUB2_CREDENTIAL_REF"):
        if name not in sub2_env:
            errors.append(f"worker-sub2 must carry {name}")
    if (sub2_worker.get("depends_on") or {}).get("redis") != {
        "condition": "service_healthy"
    }:
        errors.append("worker-sub2 must wait for healthy Redis concurrency storage")
    return errors


def main() -> int:
    try:
        compose = load_unique_yaml(COMPOSE)
    except (OSError, yaml.YAMLError) as error:
        print(f"Cannot load Compose service boundaries: {error}", file=sys.stderr)
        return 1
    errors = validate_service_boundaries(compose)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print(
        "service-boundaries-ok frontend-data-isolated monitoring-data-isolated "
        "data-networks=split-internal api=policy-metadata-only "
        "mail-worker=mail-only sub2-worker=sub2-only"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
