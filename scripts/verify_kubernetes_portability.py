"""Verify the fail-closed Kubernetes portability baseline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.target_intake_preflight import phase_checkpoint_errors
from scripts.external_json import MAX_INTAKE_JSON_BYTES, load_unique_json
from scripts.external_text import load_stable_text
from scripts.external_yaml import load_unique_yaml, load_unique_yaml_all


KUBERNETES_ROOT = ROOT / "deploy" / "kubernetes"
BASE = KUBERNETES_ROOT / "base"
SECRET_CONTRACT = KUBERNETES_ROOT / "secret-contract.json"
README = KUBERNETES_ROOT / "README.md"
COMPOSE = ROOT / "docker-compose.yml"
RELEASE_MANIFEST = ROOT / "deploy" / "release-manifest.json"
TARGET_REQUIREMENTS = ROOT / "deploy" / "target-intake-requirements.json"
MAX_RUNBOOK_BYTES = 64 * 1024

EXPECTED_RESOURCES = [
    "namespace.yaml",
    "service-accounts.yaml",
    "config.yaml",
    "migration-job.yaml",
    "workloads.yaml",
    "availability.yaml",
    "network-policies.yaml",
]
EXPECTED_DEPLOYMENTS = {"api", "web", "worker-mail", "worker-sub2"}
EXPECTED_SERVICES = {"api", "web"}
EXPECTED_HPAS = {"api", "worker-mail", "worker-sub2"}
EXPECTED_PDBS = {"api", "web", "worker-mail", "worker-sub2"}
EXPECTED_SERVICE_ACCOUNTS = {"migrate", *EXPECTED_DEPLOYMENTS}
EXPECTED_CONFIG_MAPS = {
    "platform-api-config",
    "platform-mail-config",
    "platform-sub2-config",
    "platform-provider-origins",
}
EXPECTED_NETWORK_POLICIES = {
    "default-deny",
    "dns-egress",
    "api-ingress",
    "web-ingress",
    "worker-mail-metrics-ingress",
    "worker-sub2-metrics-ingress",
    "migrate-egress",
    "api-egress",
    "worker-mail-egress",
    "worker-sub2-egress",
}
EXPECTED_EGRESS_PORTS = {
    "migrate-egress": {5432},
    "api-egress": {443, 5432, 6379, 8200, 8443},
    "worker-mail-egress": {443, 5432, 8200},
    "worker-sub2-egress": {443, 5432, 6379, 8200},
}
EXPECTED_SECRET_KEYS = {
    "platform-migration-runtime": {"migration-database-url"},
    "platform-api-runtime": {"database-url", "redis-url", "vault-token"},
    "platform-mail-runtime": {"database-url", "vault-token"},
    "platform-sub2-runtime": {"database-url", "redis-url", "vault-token"},
    "platform-internal-ca": {"ca.crt"},
    "platform-api-internal-tls": {"tls.crt", "tls.key"},
    "platform-worker-mail-internal-tls": {"tls.crt", "tls.key"},
    "platform-worker-sub2-internal-tls": {"tls.crt", "tls.key"},
    "platform-web-internal-tls": {"tls.crt", "tls.key"},
}
EXPECTED_WORKLOAD_SECRETS = {
    "api": {
        "platform-api-runtime",
        "platform-internal-ca",
        "platform-api-internal-tls",
    },
    "worker-mail": {
        "platform-mail-runtime",
        "platform-internal-ca",
        "platform-worker-mail-internal-tls",
    },
    "worker-sub2": {
        "platform-sub2-runtime",
        "platform-internal-ca",
        "platform-worker-sub2-internal-tls",
    },
    "web": {"platform-internal-ca", "platform-web-internal-tls"},
    "platform-migrate": {"platform-migration-runtime"},
}
EXPECTED_SECRET_VOLUME_NAMES = {
    "api": {
        "runtime": "platform-api-runtime",
        "internal-ca": "platform-internal-ca",
        "internal-tls": "platform-api-internal-tls",
    },
    "worker-mail": {
        "runtime": "platform-mail-runtime",
        "internal-ca": "platform-internal-ca",
        "internal-tls": "platform-worker-mail-internal-tls",
    },
    "worker-sub2": {
        "runtime": "platform-sub2-runtime",
        "internal-ca": "platform-internal-ca",
        "internal-tls": "platform-worker-sub2-internal-tls",
    },
    "web": {
        "internal-ca": "platform-internal-ca",
        "internal-tls": "platform-web-internal-tls",
    },
    "platform-migrate": {"migration-runtime": "platform-migration-runtime"},
}
EXPECTED_TLS_MOUNTS = [
    {
        "name": "internal-ca",
        "mountPath": "/run/secrets/internal-tls/ca.crt",
        "subPath": "ca.crt",
        "readOnly": True,
    },
    {
        "name": "internal-tls",
        "mountPath": "/run/secrets/internal-tls/tls.crt",
        "subPath": "tls.crt",
        "readOnly": True,
    },
    {
        "name": "internal-tls",
        "mountPath": "/run/secrets/internal-tls/tls.key",
        "subPath": "tls.key",
        "readOnly": True,
    },
]
EXPECTED_ROLLING_UPDATE = {
    "api": {"maxUnavailable": 0, "maxSurge": 1},
    "web": {"maxUnavailable": 0, "maxSurge": 1},
}
FORBIDDEN_INLINE_SETTINGS = {
    "ALEMBIC_DATABASE_URL",
    "PLATFORM_DATABASE_URL",
    "PLATFORM_REDIS_URL",
    "PLATFORM_VAULT_TOKEN",
}
CONFIG_MAP_BY_WORKLOAD = {
    "api": "platform-api-config",
    "worker-mail": "platform-mail-config",
    "worker-sub2": "platform-sub2-config",
}
PORTABLE_DEFAULT_KEYS = {
    "api": {
        "PLATFORM_ENVIRONMENT",
        "PLATFORM_DATABASE_URL_FILE",
        "PLATFORM_RATE_LIMIT_ENABLED",
        "PLATFORM_MAX_ACTIVE_DEVICES_PER_USER",
        "PLATFORM_REDIS_URL_FILE",
        "PLATFORM_AUTH_MODE",
        "PLATFORM_OIDC_AUDIENCE",
        "PLATFORM_OIDC_CLIENT_ID",
        "PLATFORM_OIDC_DESKTOP_CLIENT_ID",
        "PLATFORM_INTERNAL_CA_FILE",
        "PLATFORM_VAULT_NAMESPACE",
        "PLATFORM_VAULT_TIMEOUT_SECONDS",
        "PLATFORM_MAIL_POLL_MODE",
        "PLATFORM_ADMIN_ROLE_CHANGE_ACR",
        "PLATFORM_ADMIN_ROLE_CHANGE_TTL_SECONDS",
        "PLATFORM_SUB2_POLICY_VERSION",
        "PLATFORM_SUB2_GROUP_ID",
        "PLATFORM_SUB2_CONCURRENCY",
    },
    "worker-mail": {
        "PLATFORM_ENVIRONMENT",
        "PLATFORM_DATABASE_URL_FILE",
        "PLATFORM_AUTH_MODE",
        "PLATFORM_OIDC_AUDIENCE",
        "PLATFORM_OIDC_CLIENT_ID",
        "PLATFORM_OIDC_DESKTOP_CLIENT_ID",
        "PLATFORM_INTERNAL_CA_FILE",
        "PLATFORM_VAULT_NAMESPACE",
        "PLATFORM_VAULT_TIMEOUT_SECONDS",
        "PLATFORM_MAIL_POLL_MODE",
        "PLATFORM_MAIL_ALLOWED_ORIGINS_FILE",
        "PLATFORM_MAIL_TIMEOUT_SECONDS",
        "PLATFORM_WORKER_METRICS_HOST",
        "PLATFORM_WORKER_METRICS_PORT",
        "PLATFORM_WORKER_METRICS_TLS_CERT_FILE",
        "PLATFORM_WORKER_METRICS_TLS_KEY_FILE",
        "PLATFORM_WORKER_HEARTBEAT_PATH",
        "PLATFORM_WORKER_HEARTBEAT_MAX_AGE_SECONDS",
    },
    "worker-sub2": {
        "PLATFORM_ENVIRONMENT",
        "PLATFORM_DATABASE_URL_FILE",
        "PLATFORM_REDIS_URL_FILE",
        "PLATFORM_AUTH_MODE",
        "PLATFORM_OIDC_AUDIENCE",
        "PLATFORM_OIDC_CLIENT_ID",
        "PLATFORM_OIDC_DESKTOP_CLIENT_ID",
        "PLATFORM_INTERNAL_CA_FILE",
        "PLATFORM_VAULT_NAMESPACE",
        "PLATFORM_VAULT_TIMEOUT_SECONDS",
        "PLATFORM_SUB2_POLICY_VERSION",
        "PLATFORM_SUB2_GROUP_ID",
        "PLATFORM_SUB2_CONCURRENCY",
        "PLATFORM_SUB2_ALLOWED_ORIGINS_FILE",
        "PLATFORM_WORKER_METRICS_HOST",
        "PLATFORM_WORKER_METRICS_PORT",
        "PLATFORM_WORKER_METRICS_TLS_CERT_FILE",
        "PLATFORM_WORKER_METRICS_TLS_KEY_FILE",
        "PLATFORM_WORKER_HEARTBEAT_PATH",
        "PLATFORM_WORKER_HEARTBEAT_MAX_AGE_SECONDS",
    },
}
REQUIRED_TARGET_INTAKE_IDS = {
    "mail_contract",
    "sub2_contract",
    "card_pci_boundary",
    "oidc_deployment_identity",
    "phase0_boundary_approval",
    "target_platform_inventory",
}
IMAGE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$")
COMPOSE_DEFAULT_PATTERN = re.compile(r"^\$\{[A-Z0-9_]+:-(.*)\}$")


def load_documents(root: Path = KUBERNETES_ROOT) -> list[dict[str, Any]]:
    documents: list[dict[str, Any]] = []
    for path in sorted((root / "base").glob("*.yaml")):
        for value in load_unique_yaml_all(path):
            if isinstance(value, dict):
                documents.append(value)
    return documents


def _named(
    documents: list[dict[str, Any]], kind: str
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for document in documents:
        if document.get("kind") != kind:
            continue
        metadata = document.get("metadata")
        if isinstance(metadata, dict) and isinstance(metadata.get("name"), str):
            result[metadata["name"]] = document
    return result


def _pod_spec(document: dict[str, Any]) -> dict[str, Any] | None:
    spec = document.get("spec")
    if not isinstance(spec, dict):
        return None
    if document.get("kind") == "Deployment":
        template = spec.get("template")
    elif document.get("kind") == "Job":
        template = spec.get("template")
    else:
        return None
    if not isinstance(template, dict) or not isinstance(template.get("spec"), dict):
        return None
    return template["spec"]


def _containers(pod_spec: dict[str, Any]) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for key in ("initContainers", "containers"):
        raw = pod_spec.get(key, [])
        if isinstance(raw, list):
            values.extend(item for item in raw if isinstance(item, dict))
    return values


def _main_container(document: dict[str, Any], name: str) -> dict[str, Any] | None:
    pod_spec = _pod_spec(document)
    containers = pod_spec.get("containers", []) if pod_spec else []
    return next(
        (
            item
            for item in containers
            if isinstance(item, dict) and item.get("name") == name
        ),
        None,
    )


def _effective_environment(
    document: dict[str, Any], config_maps: dict[str, dict[str, Any]], name: str
) -> dict[str, Any]:
    container = _main_container(document, name)
    if container is None:
        return {}
    result: dict[str, Any] = {}
    env_from = container.get("envFrom", [])
    for source in env_from if isinstance(env_from, list) else []:
        reference = source.get("configMapRef") if isinstance(source, dict) else None
        config_name = reference.get("name") if isinstance(reference, dict) else None
        config = config_maps.get(config_name, {}) if isinstance(config_name, str) else {}
        data = config.get("data", {}) if isinstance(config, dict) else {}
        if isinstance(data, dict):
            result.update(data)
    env = container.get("env", [])
    for item in env if isinstance(env, list) else []:
        if (
            isinstance(item, dict)
            and isinstance(item.get("name"), str)
            and "value" in item
        ):
            result[item["name"]] = item["value"]
    return result


def _portable_value(value: Any) -> str:
    text_value = str(value)
    match = COMPOSE_DEFAULT_PATTERN.fullmatch(text_value)
    return match.group(1) if match else text_value


def deployment_alignment_errors(
    documents: list[dict[str, Any]],
    *,
    compose: Any | None = None,
    release_manifest: Any | None = None,
    target_requirements: Any | None = None,
) -> list[str]:
    """Cross-check Kubernetes against existing repository deployment contracts."""

    try:
        compose = (
            load_unique_yaml(COMPOSE)
            if compose is None
            else compose
        )
        release_manifest = (
            load_unique_json(
                RELEASE_MANIFEST,
                max_bytes=MAX_INTAKE_JSON_BYTES,
            )
            if release_manifest is None
            else release_manifest
        )
        target_requirements = (
            load_unique_json(
                TARGET_REQUIREMENTS,
                max_bytes=MAX_INTAKE_JSON_BYTES,
            )
            if target_requirements is None
            else target_requirements
        )
    except (OSError, UnicodeError, json.JSONDecodeError, yaml.YAMLError):
        return ["Kubernetes repository alignment inputs are unavailable"]
    if not all(
        isinstance(value, dict)
        for value in (compose, release_manifest, target_requirements)
    ):
        return ["Kubernetes repository alignment inputs are invalid"]

    errors: list[str] = []
    services = compose.get("services", {})
    release_images = release_manifest.get("compose_images", {})
    required_services = {"migrate", "api", "worker-mail", "worker-sub2", "web"}
    if not isinstance(services, dict) or not required_services.issubset(services):
        errors.append("Kubernetes Compose workload inventory has drifted")
        services = services if isinstance(services, dict) else {}
    if not isinstance(release_images, dict) or not required_services.issubset(
        release_images
    ):
        errors.append("Kubernetes release image inventory has drifted")
        release_images = release_images if isinstance(release_images, dict) else {}
    api_release_images = {
        release_images.get(name)
        for name in ("migrate", "api", "worker-mail", "worker-sub2")
    }
    if len(api_release_images) != 1 or None in api_release_images:
        errors.append("Kubernetes API-family release image identity has drifted")

    deployments = _named(documents, "Deployment")
    job = _named(documents, "Job").get("platform-migrate")
    command_pairs = {
        "api": (deployments.get("api"), "api"),
        "worker-mail": (deployments.get("worker-mail"), "worker-mail"),
        "worker-sub2": (deployments.get("worker-sub2"), "worker-sub2"),
        "migrate": (job, "migrate"),
    }
    for service_name, (document, container_name) in command_pairs.items():
        container = (
            _main_container(document, container_name)
            if isinstance(document, dict)
            else None
        )
        service = services.get(service_name, {})
        if (
            container is None
            or not isinstance(service, dict)
            or container.get("command") != service.get("command")
        ):
            errors.append(f"Kubernetes {service_name} command has drifted from Compose")

    api_family_images = {
        _main_container(document, name).get("image")
        for name, document in deployments.items()
        if name in {"api", "worker-mail", "worker-sub2"}
        and _main_container(document, name) is not None
    }
    migrate_container = _main_container(job, "migrate") if isinstance(job, dict) else None
    if migrate_container is not None:
        api_family_images.add(migrate_container.get("image"))
    if len(api_family_images) != 1 or None in api_family_images:
        errors.append("Kubernetes API-family image identity has drifted")

    config_maps = _named(documents, "ConfigMap")
    for name, config_name in CONFIG_MAP_BY_WORKLOAD.items():
        deployment = deployments.get(name)
        service = services.get(name, {})
        compose_env = service.get("environment", {}) if isinstance(service, dict) else {}
        kubernetes_env = (
            _effective_environment(deployment, config_maps, name)
            if isinstance(deployment, dict)
            else {}
        )
        if not isinstance(compose_env, dict) or set(kubernetes_env) != set(compose_env):
            errors.append(f"Kubernetes {name} environment key inventory has drifted")
            continue
        if not PORTABLE_DEFAULT_KEYS[name].issubset(kubernetes_env):
            errors.append(f"Kubernetes {name} portable default inventory has drifted")
            continue
        if any(
            _portable_value(kubernetes_env[key]) != _portable_value(compose_env[key])
            for key in PORTABLE_DEFAULT_KEYS[name]
        ):
            errors.append(f"Kubernetes {name} portable defaults have drifted")

    requirements = target_requirements.get("requirements", [])
    requirement_ids = {
        item.get("id")
        for item in requirements
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    } if isinstance(requirements, list) else set()
    if not REQUIRED_TARGET_INTAKE_IDS.issubset(requirement_ids):
        errors.append("Kubernetes target intake dependencies have drifted")
    return errors


def _secret_volume_errors(name: str, pod_spec: dict[str, Any]) -> list[str]:
    actual: dict[str, tuple[str, set[tuple[str, str]]]] = {}
    errors: list[str] = []
    volumes = pod_spec.get("volumes", [])
    for volume in volumes if isinstance(volumes, list) else []:
        if not isinstance(volume, dict) or not isinstance(volume.get("secret"), dict):
            continue
        secret = volume["secret"]
        secret_name = secret.get("secretName")
        items = secret.get("items")
        volume_name = volume.get("name")
        if (
            set(secret) != {"secretName", "defaultMode", "items"}
            or secret.get("defaultMode") != 288
            or not isinstance(secret_name, str)
            or not isinstance(volume_name, str)
            or not isinstance(items, list)
            or any(not isinstance(item, dict) or set(item) != {"key", "path"} for item in items)
        ):
            errors.append(f"{name} secret volume schema has drifted")
            continue
        key_paths = {(item["key"], item["path"]) for item in items}
        if len(key_paths) != len(items) or secret_name in actual:
            errors.append(f"{name} secret volume key mapping is ambiguous")
            continue
        actual[secret_name] = (volume_name, key_paths)
    expected_names = EXPECTED_WORKLOAD_SECRETS[name]
    if set(actual) != expected_names:
        errors.append(f"{name} external secret references have drifted")
    expected_volume_names = EXPECTED_SECRET_VOLUME_NAMES[name]
    for secret_name, (volume_name, key_paths) in actual.items():
        expected_keys = EXPECTED_SECRET_KEYS.get(secret_name)
        if key_paths != {(key, key) for key in expected_keys or set()}:
            errors.append(f"{name}/{secret_name} mounted key/path whitelist has drifted")
        if expected_volume_names.get(volume_name) != secret_name:
            errors.append(f"{name}/{secret_name} volume name binding has drifted")

    if name in EXPECTED_DEPLOYMENTS:
        containers = _containers(pod_spec)
        primary = next((item for item in containers if item.get("name") == name), None)
        mounts = primary.get("volumeMounts", []) if isinstance(primary, dict) else []
        tls_mounts = [
            mount
            for mount in mounts if isinstance(mount, dict) and mount.get("name") in {"internal-ca", "internal-tls"}
        ] if isinstance(mounts, list) else []
        if tls_mounts != EXPECTED_TLS_MOUNTS:
            errors.append(f"{name} TLS mount path/subPath/readOnly contract has drifted")
    return errors


def _security_errors(
    name: str, document: dict[str, Any], *, require_schema_gate: bool
) -> list[str]:
    errors: list[str] = []
    pod_spec = _pod_spec(document)
    if pod_spec is None:
        return [f"{name} pod spec is missing"]
    if pod_spec.get("automountServiceAccountToken") is not False:
        errors.append(f"{name} must disable service account token automount")
    security = pod_spec.get("securityContext")
    if not isinstance(security, dict):
        errors.append(f"{name} pod security context is missing")
    else:
        if security.get("runAsNonRoot") is not True:
            errors.append(f"{name} must run as non-root")
        seccomp = security.get("seccompProfile")
        if not isinstance(seccomp, dict) or seccomp.get("type") != "RuntimeDefault":
            errors.append(f"{name} must use RuntimeDefault seccomp")
    containers = _containers(pod_spec)
    if not containers:
        errors.append(f"{name} containers are missing")
    for container in containers:
        container_name = str(container.get("name", "unknown"))
        image = container.get("image")
        if not isinstance(image, str) or not IMAGE_PATTERN.fullmatch(image):
            errors.append(f"{name}/{container_name} image must use an immutable sha256 digest")
        context = container.get("securityContext")
        if not isinstance(context, dict):
            errors.append(f"{name}/{container_name} security context is missing")
            continue
        if context.get("allowPrivilegeEscalation") is not False:
            errors.append(f"{name}/{container_name} must disable privilege escalation")
        if context.get("readOnlyRootFilesystem") is not True:
            errors.append(f"{name}/{container_name} must use a read-only root filesystem")
        capabilities = context.get("capabilities")
        if not isinstance(capabilities, dict) or capabilities.get("drop") != ["ALL"]:
            errors.append(f"{name}/{container_name} must drop all capabilities")
        env = container.get("env", [])
        if isinstance(env, list):
            for item in env:
                if (
                    isinstance(item, dict)
                    and item.get("name") in FORBIDDEN_INLINE_SETTINGS
                ):
                    errors.append(
                        f"{name}/{container_name} has forbidden inline secret setting {item['name']}"
                    )
    if require_schema_gate:
        init = pod_spec.get("initContainers", [])
        schema = next(
            (
                item
                for item in init
                if isinstance(item, dict) and item.get("name") == "schema-current"
            ),
            None,
        )
        if schema is None or schema.get("command") != [
            "python",
            "-m",
            "infra.check_database_schema",
        ]:
            errors.append(f"{name} schema-current init container is missing or invalid")
    return errors


def _contract_errors() -> list[str]:
    try:
        contract = load_unique_json(
            SECRET_CONTRACT,
            max_bytes=MAX_INTAKE_JSON_BYTES,
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        return ["Kubernetes external secret contract is unavailable"]
    if set(contract) != {
        "schema_version",
        "record_type",
        "production_acceptance",
        "provider",
        "secrets",
    }:
        return ["Kubernetes external secret contract schema is invalid"]
    errors: list[str] = []
    if (
        contract.get("schema_version") != 1
        or contract.get("record_type") != "kubernetes_external_secret_contract"
        or contract.get("production_acceptance") is not False
        or contract.get("provider") != "external_secret_manager_csi_or_operator"
    ):
        errors.append("Kubernetes external secret contract identity is invalid")
    secrets = contract.get("secrets")
    actual: dict[str, set[str]] = {}
    if not isinstance(secrets, list):
        return errors + ["Kubernetes external secret entries are invalid"]
    for item in secrets:
        if not isinstance(item, dict) or set(item) != {
            "name",
            "consumer",
            "required_keys",
        }:
            errors.append("Kubernetes external secret entry schema is invalid")
            continue
        name = item.get("name")
        keys = item.get("required_keys")
        if not isinstance(name, str) or not isinstance(keys, list):
            errors.append("Kubernetes external secret entry values are invalid")
            continue
        actual[name] = {str(key) for key in keys}
    if actual != EXPECTED_SECRET_KEYS:
        errors.append("Kubernetes external secret names or keys have drifted")
    return errors


def verification_errors(
    documents: list[dict[str, Any]] | None = None,
) -> list[str]:
    if documents is None:
        try:
            documents = load_documents()
        except (OSError, UnicodeError, yaml.YAMLError):
            return ["Kubernetes portability manifests are unavailable"]
    errors: list[str] = []
    if any(document.get("kind") == "Secret" for document in documents):
        errors.append("Kubernetes repository manifests must not contain Secret objects")

    namespace = _named(documents, "Namespace").get("email-platform")
    annotations = namespace.get("metadata", {}).get("annotations", {}) if namespace else {}
    if (
        namespace is None
        or annotations.get("email-platform.io/template-only") != "true"
        or annotations.get("email-platform.io/production-acceptance") != "false"
    ):
        errors.append("Kubernetes namespace must remain template-only and non-production")

    expected_named = {
        "Deployment": EXPECTED_DEPLOYMENTS,
        "Service": EXPECTED_SERVICES,
        "HorizontalPodAutoscaler": EXPECTED_HPAS,
        "PodDisruptionBudget": EXPECTED_PDBS,
        "ServiceAccount": EXPECTED_SERVICE_ACCOUNTS,
        "ConfigMap": EXPECTED_CONFIG_MAPS,
        "NetworkPolicy": EXPECTED_NETWORK_POLICIES,
        "Job": {"platform-migrate"},
    }
    for kind, expected in expected_named.items():
        actual = set(_named(documents, kind))
        if actual != expected:
            errors.append(f"Kubernetes {kind} inventory has drifted")

    kustomizations = [item for item in documents if item.get("kind") == "Kustomization"]
    if len(kustomizations) != 1:
        errors.append("Kubernetes base must contain one Kustomization")
    else:
        kustomization = kustomizations[0]
        if (
            kustomization.get("namespace") != "email-platform"
            or kustomization.get("resources") != EXPECTED_RESOURCES
        ):
            errors.append("Kubernetes Kustomization resource inventory has drifted")

    deployments = _named(documents, "Deployment")
    for name, deployment in deployments.items():
        spec = deployment.get("spec", {})
        if not isinstance(spec, dict) or not isinstance(spec.get("replicas"), int) or spec["replicas"] < 2:
            errors.append(f"{name} must start with at least two replicas")
        strategy = spec.get("strategy") if isinstance(spec, dict) else None
        if name in {"worker-mail", "worker-sub2"}:
            strategy_valid = strategy == {"type": "Recreate"}
        else:
            strategy_valid = (
                isinstance(strategy, dict)
                and set(strategy) == {"type", "rollingUpdate"}
                and strategy.get("type") == "RollingUpdate"
                and strategy.get("rollingUpdate") == EXPECTED_ROLLING_UPDATE.get(name)
            )
        if not strategy_valid:
            errors.append(
                f"{name} RollingUpdate/Recreate deployment strategy contract has drifted"
            )
        pod_spec = _pod_spec(deployment)
        if pod_spec is None or not pod_spec.get("topologySpreadConstraints"):
            errors.append(f"{name} topology spreading is missing")
        if pod_spec is not None:
            if pod_spec.get("serviceAccountName") != name:
                errors.append(f"{name} service account binding has drifted")
            errors.extend(_secret_volume_errors(name, pod_spec))
        errors.extend(
            _security_errors(
                name,
                deployment,
                require_schema_gate=name in {"api", "worker-mail", "worker-sub2"},
            )
        )

    job = _named(documents, "Job").get("platform-migrate")
    if job is not None:
        job_annotations = job.get("metadata", {}).get("annotations", {})
        if (
            job_annotations.get("email-platform.io/release-bound") != "true"
            or job_annotations.get("email-platform.io/replace-name-per-release")
            != "required"
        ):
            errors.append("Kubernetes release-bound migration annotations are missing")
        pod_spec = _pod_spec(job)
        containers = pod_spec.get("containers", []) if pod_spec else []
        migrate = containers[0] if len(containers) == 1 else None
        if (
            not isinstance(migrate, dict)
            or migrate.get("command")
            != ["alembic", "-c", "/app/alembic.ini", "upgrade", "head"]
        ):
            errors.append("Kubernetes migration Job command is invalid")
        if pod_spec is not None:
            if pod_spec.get("serviceAccountName") != "migrate":
                errors.append("Kubernetes migration service account binding has drifted")
            errors.extend(_secret_volume_errors("platform-migrate", pod_spec))
        errors.extend(_security_errors("platform-migrate", job, require_schema_gate=False))

    for name, service in _named(documents, "Service").items():
        spec = service.get("spec", {})
        if not isinstance(spec, dict) or spec.get("type") != "ClusterIP":
            errors.append(f"{name} Service must remain internal ClusterIP")
    if _named(documents, "Ingress"):
        errors.append("Kubernetes base must not commit a target-specific Ingress")

    for name, config_map in _named(documents, "ConfigMap").items():
        data = config_map.get("data", {})
        if not isinstance(data, dict) or FORBIDDEN_INLINE_SETTINGS.intersection(data):
            errors.append(f"{name} ConfigMap contains a forbidden secret setting")

    hpas = _named(documents, "HorizontalPodAutoscaler")
    for name in EXPECTED_HPAS:
        spec = hpas.get(name, {}).get("spec", {})
        if (
            not isinstance(spec, dict)
            or spec.get("minReplicas") != 2
            or not isinstance(spec.get("maxReplicas"), int)
            or spec["maxReplicas"] <= 2
            or spec.get("scaleTargetRef", {}).get("name") != name
        ):
            errors.append(f"{name} independent autoscaling contract is invalid")

    policies = _named(documents, "NetworkPolicy")
    default_deny = policies.get("default-deny", {}).get("spec", {})
    if (
        default_deny.get("podSelector") != {}
        or set(default_deny.get("policyTypes", [])) != {"Ingress", "Egress"}
    ):
        errors.append("Kubernetes default-deny NetworkPolicy is invalid")
    for name, expected_ports in EXPECTED_EGRESS_PORTS.items():
        rules = policies.get(name, {}).get("spec", {}).get("egress", [])
        actual_ports = {
            port.get("port")
            for rule in rules
            if isinstance(rule, dict)
            for port in rule.get("ports", [])
            if isinstance(port, dict)
        }
        if actual_ports != expected_ports:
            errors.append(f"{name} egress port contract has drifted")
    for policy in policies.values():
        rules = policy.get("spec", {}).get("egress", [])
        for rule in rules if isinstance(rules, list) else []:
            if not isinstance(rule, dict):
                continue
            for target in rule.get("to", []) if isinstance(rule.get("to", []), list) else []:
                if (
                    isinstance(target, dict)
                    and isinstance(target.get("ipBlock"), dict)
                    and target["ipBlock"].get("cidr") in {"0.0.0.0/0", "::/0"}
                ):
                    errors.append("Kubernetes network policy contains a broad egress CIDR")

    errors.extend(deployment_alignment_errors(documents))
    errors.extend(_contract_errors())
    try:
        readme = load_stable_text(
            README,
            max_bytes=MAX_RUNBOOK_BYTES,
        )
    except (OSError, UnicodeError):
        errors.append("Kubernetes portability runbook is unavailable")
    else:
        for required in (
            "Do not apply `base/` directly",
            "external-secret operator or CSI driver",
            "schema-current",
            "server-side dry-run",
            "target-intake-preflight.md",
            "--through-phase 0",
            "--target-intake-manifest",
            "--target-environment",
            "mail_contract",
            "sub2_contract",
            "card_pci_boundary",
            "oidc_deployment_identity",
            "phase0_boundary_approval",
            "target_platform_inventory",
            "production_acceptance=false",
        ):
            if required not in readme:
                errors.append(f"Kubernetes portability runbook is missing: {required}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-intake-manifest", type=Path)
    parser.add_argument("--target-environment")
    arguments = parser.parse_args(argv)
    if (arguments.target_intake_manifest is None) != (
        arguments.target_environment is None
    ):
        print(
            "target intake manifest and environment must be supplied together",
            file=sys.stderr,
        )
        return 2
    errors = verification_errors()
    if arguments.target_intake_manifest is not None:
        errors.extend(
            phase_checkpoint_errors(
                arguments.target_intake_manifest,
                environment=arguments.target_environment,
                through_phase=0,
            )
        )
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    print(
        "kubernetes-portability-ok workloads=4 migration=release-bound "
        "production_acceptance=false target_cluster_evidence=pending"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
