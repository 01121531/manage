"""Closed Compose backend for the controlled TLS leaf-rotation coordinator."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Mapping

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from scripts.backup_output_policy import REPOSITORY_ROOT
from scripts.check_internal_tls_expiry import (
    CA_ENV,
    CERTIFICATE_ENV,
    KEY_ENV,
    CertificateInputError,
    _load_certificate,
    _load_env_file,
    evaluate_inventory,
)
from scripts.external_json import StableFileError, parse_unique_json_bytes, read_stable_bytes
from scripts.rollback_release import PRODUCTION_COMPOSE, PRODUCTION_ENV_FILE, PRODUCTION_PROJECT_NAME
from scripts.tls_rotation_evidence import rotation_plan_digest
from scripts.tls_rotation_runtime import (
    ActionReconciliation,
    ProbeInvocation,
    RotationRuntimeError,
    Runner,
    RuntimeInstanceSnapshot,
    assert_generation_replaced,
    collect_compose_generation,
    collect_peer_observation,
    docker_probe_command,
    force_recreate_compose_service,
    get_compose_probe_executor,
)
from scripts.tls_rotation_runner import SanitizedSubprocessRunner
from scripts.tls_runtime_identity import parse_tls_probe_observation


ROLLING_COMPOSE = REPOSITORY_ROOT / "docker-compose.rolling.yml"
PROFILE_KIND = "compose_tls_rotation_backend"
PROFILE_SCHEMA_VERSION = 3
MAX_PROFILE_BYTES = 64 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OCI_IMAGE = re.compile(r"^[^\s:@]+(?:/[^\s:@]+)+@sha256:[0-9a-f]{64}$")
_PROFILE_FIELDS = {
    "schema_version",
    "profile_kind",
    "live_capture_sha256",
    "target_environment",
    "service",
    "expected_instance_count",
    "required_observers",
    "env_file_sha256",
    "expected_image",
    "compose_kind",
    "direct_probe",
    "route_observers",
    "blocked_observers",
}
_PROBE_FIELDS = {
    "logical_name", "executor_service", "expected_image", "url", "ca_file"
}
_DIRECT_FIELDS = {
    "executor_service", "expected_image", "url", "ca_file", "network"
}
_PYTHON_EXECUTORS = frozenset({"api", "api-green", "worker-mail", "worker-sub2"})
_CA_FILE = "/run/secrets/internal-tls/ca.crt"
_MOUNT_DESTINATIONS = {
    CA_ENV: _CA_FILE,
    "certificate": "/run/secrets/internal-tls/tls.crt",
    "key": "/run/secrets/internal-tls/tls.key",
}


@dataclass(frozen=True)
class _TargetContract:
    compose_kind: str
    direct_executor: str
    url: str
    direct_network: str
    required_observers: tuple[str, ...]


_TARGETS = {
    "api": _TargetContract("base", "worker-sub2", "https://api:8443/readyz", "email-platform-metrics", ("edge", "prometheus")),
    "web": _TargetContract("base", "api", "https://web:8443/", "email-platform-frontend", ("edge",)),
    "api-green": _TargetContract("rolling", "api-green", "https://api-green:8443/readyz", "email-platform-metrics", ("edge",)),
    "web-green": _TargetContract("rolling", "api-green", "https://web-green:8443/", "email-platform-frontend", ("edge",)),
    "keycloak": _TargetContract(
        "base",
        "api",
        "https://keycloak:8443/realms/email-platform/.well-known/openid-configuration",
        "email-platform-frontend",
        ("api", "api-green", "edge", "prometheus", "worker-mail", "worker-sub2"),
    ),
    "worker-mail": _TargetContract("base", "api", "https://worker-mail:9101/metrics", "email-platform-metrics", ("prometheus",)),
    "worker-sub2": _TargetContract("base", "api", "https://worker-sub2:9102/metrics", "email-platform-metrics", ("prometheus",)),
    "prometheus": _TargetContract("base", "api", "https://prometheus:9090/-/ready", "email-platform-metrics", ("operator",)),
    "alertmanager": _TargetContract("base", "host", "https://alertmanager:9093/metrics", "email-platform-alerting", ("prometheus",)),
}


class ComposeRotationBackendError(RotationRuntimeError):
    """The reviewed Compose runtime profile cannot be executed safely."""


@dataclass(frozen=True)
class RouteObserver:
    logical_name: str
    executor_service: str
    expected_image: str
    url: str
    ca_file: str


@dataclass(frozen=True)
class ComposeRotationProfile:
    live_capture_sha256: str
    target_environment: str
    service: str
    expected_instance_count: int
    required_observers: tuple[str, ...]
    env_file_sha256: str
    expected_image: str
    compose_kind: str
    direct_executor: str
    direct_executor_image: str
    direct_url: str
    direct_ca_file: str
    direct_network: str
    route_observers: tuple[RouteObserver, ...]
    blocked_observers: tuple[str, ...]
    profile_sha256: str


def _canonical_digest(value: Mapping[str, object]) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _closed_mapping(value: object, fields: set[str], context: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ComposeRotationBackendError(f"invalid {context}")
    return value


def _external_path(path: Path) -> Path:
    if not path.is_absolute():
        raise ComposeRotationBackendError("runtime profile path is invalid")
    try:
        path.resolve(strict=False).relative_to(REPOSITORY_ROOT.resolve())
    except ValueError:
        return path
    raise ComposeRotationBackendError("runtime profile path is invalid")


def load_compose_rotation_profile(path: Path) -> ComposeRotationProfile:
    try:
        raw = read_stable_bytes(_external_path(path), max_bytes=MAX_PROFILE_BYTES)
        value = parse_unique_json_bytes(raw)
    except (StableFileError, UnicodeError, json.JSONDecodeError, ValueError):
        raise ComposeRotationBackendError("runtime profile cannot be read") from None
    return validate_compose_rotation_profile(value)


def validate_compose_rotation_profile(value: object) -> ComposeRotationProfile:
    profile = _closed_mapping(value, _PROFILE_FIELDS, "Compose rotation profile")
    service = profile["service"]
    contract = _TARGETS.get(service) if isinstance(service, str) else None
    required = profile["required_observers"]
    blocked = profile["blocked_observers"]
    routes = profile["route_observers"]
    direct = _closed_mapping(profile["direct_probe"], _DIRECT_FIELDS, "direct probe profile")
    if (
        profile["schema_version"] != PROFILE_SCHEMA_VERSION
        or profile["profile_kind"] != PROFILE_KIND
        or not isinstance(profile["live_capture_sha256"], str)
        or _SHA256.fullmatch(profile["live_capture_sha256"]) is None
        or contract is None
        or profile["expected_instance_count"] != 1
        or profile["compose_kind"] != contract.compose_kind
        or direct.get("executor_service") != contract.direct_executor
        or direct.get("url") != contract.url
        or direct.get("ca_file") != _CA_FILE
        or direct.get("network") != contract.direct_network
        or not isinstance(direct.get("expected_image"), str)
        or _OCI_IMAGE.fullmatch(direct["expected_image"]) is None
        or contract.direct_executor not in _PYTHON_EXECUTORS
        or not isinstance(required, list)
        or required != list(contract.required_observers)
        or not isinstance(blocked, list)
        or blocked != sorted(set(blocked))
        or not isinstance(routes, list)
        or not isinstance(profile["target_environment"], str)
        or not profile["target_environment"]
        or not isinstance(profile["env_file_sha256"], str)
        or _SHA256.fullmatch(profile["env_file_sha256"]) is None
        or not isinstance(profile["expected_image"], str)
        or _OCI_IMAGE.fullmatch(profile["expected_image"]) is None
    ):
        raise ComposeRotationBackendError("Compose rotation profile identity is invalid")
    parsed_routes: list[RouteObserver] = []
    for item in routes:
        route = _closed_mapping(item, _PROBE_FIELDS, "route observer profile")
        if (
            route["logical_name"] not in required
            or route["executor_service"] != route["logical_name"]
            or route["executor_service"] not in _PYTHON_EXECUTORS
            or not isinstance(route["expected_image"], str)
            or _OCI_IMAGE.fullmatch(route["expected_image"]) is None
            or route["url"] != contract.url
            or route["ca_file"] != _CA_FILE
        ):
            raise ComposeRotationBackendError("route observer profile is invalid")
        parsed_routes.append(RouteObserver(**route))
    route_names = [item.logical_name for item in parsed_routes]
    if (
        route_names != sorted(set(route_names))
        or sorted(route_names + list(blocked)) != list(required)
    ):
        raise ComposeRotationBackendError("Compose observer inventory is incomplete")
    return ComposeRotationProfile(
        live_capture_sha256=str(profile["live_capture_sha256"]),
        target_environment=str(profile["target_environment"]),
        service=service,
        expected_instance_count=1,
        required_observers=tuple(required),
        env_file_sha256=str(profile["env_file_sha256"]),
        expected_image=str(profile["expected_image"]),
        compose_kind=str(profile["compose_kind"]),
        direct_executor=str(direct["executor_service"]),
        direct_executor_image=str(direct["expected_image"]),
        direct_url=str(direct["url"]),
        direct_ca_file=str(direct["ca_file"]),
        direct_network=str(direct["network"]),
        route_observers=tuple(parsed_routes),
        blocked_observers=tuple(blocked),
        profile_sha256=_canonical_digest(profile),
    )


def compose_prefix(profile: ComposeRotationProfile) -> tuple[str, ...]:
    prefix = (
        "docker",
        "compose",
        "--project-directory",
        str(REPOSITORY_ROOT),
        "--env-file",
        str(PRODUCTION_ENV_FILE),
        "--project-name",
        PRODUCTION_PROJECT_NAME,
        "-f",
        str(PRODUCTION_COMPOSE),
    )
    return prefix if profile.compose_kind == "base" else (*prefix, "-f", str(ROLLING_COMPOSE))


def _current_leaf_identity(service: str) -> tuple[str, str]:
    env = _load_env_file(PRODUCTION_ENV_FILE)
    certificate = _load_certificate(service, Path(env[CERTIFICATE_ENV[service]]))
    leaf = certificate.fingerprint(hashes.SHA256()).hex()
    public_key = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return leaf, hashlib.sha256(public_key).hexdigest()


class ComposeRotationBackend:
    runtime_kind = "compose"

    def __init__(self, profile: ComposeRotationProfile, runner: Runner) -> None:
        self.profile = profile
        self.runner = runner
        self._prefix = compose_prefix(profile)
        self._mounts: dict[str, Path] = {}
        self._routes = {item.logical_name: item for item in profile.route_observers}
        self._direct_executor_image: str | None = None

    def preflight(self, projection: Mapping[str, object]) -> None:
        expected = {
            "target_environment": self.profile.target_environment,
            "runtime_kind": "compose",
            "service": self.profile.service,
            "expected_instance_count": 1,
            "required_observers": list(self.profile.required_observers),
            "runtime_profile_sha256": self.profile.profile_sha256,
            "old_leaf_sha256": projection["old_leaf_sha256"],
            "new_leaf_sha256": projection["new_leaf_sha256"],
            "old_spki_sha256": projection["old_spki_sha256"],
            "new_spki_sha256": projection["new_spki_sha256"],
        }
        if rotation_plan_digest(expected) != rotation_plan_digest(projection):
            raise ComposeRotationBackendError("runtime profile does not match rotation plan")
        if self.profile.blocked_observers:
            raise ComposeRotationBackendError("required real observer probe runtime is unavailable")
        if self.profile.compose_kind != "base":
            raise ComposeRotationBackendError("standalone rolling service rotation is unavailable")
        try:
            resolved_images = self.runner.run(
                [*self._prefix, "config", "--images", self.profile.service],
                capture_output=True,
            ).splitlines()
            if resolved_images != [self.profile.expected_image]:
                raise ComposeRotationBackendError("Compose image resolution has drifted")
            executor_images = self.runner.run(
                [*self._prefix, "config", "--images", self.profile.direct_executor],
                capture_output=True,
            ).splitlines()
            if executor_images != [self.profile.direct_executor_image]:
                raise ComposeRotationBackendError("Compose probe executor image is invalid")
            self._direct_executor_image = self.profile.direct_executor_image
            raw_env = read_stable_bytes(PRODUCTION_ENV_FILE, max_bytes=64 * 1024)
            if not hmac.compare_digest(hashlib.sha256(raw_env).hexdigest(), self.profile.env_file_sha256):
                raise ComposeRotationBackendError("production environment identity has drifted")
            evaluate_inventory(PRODUCTION_ENV_FILE, now=datetime.now(timezone.utc))
            env = _load_env_file(PRODUCTION_ENV_FILE)
            leaf, spki = _current_leaf_identity(self.profile.service)
            if not hmac.compare_digest(leaf, str(projection["new_leaf_sha256"])) or not hmac.compare_digest(
                spki, str(projection["new_spki_sha256"])
            ):
                raise ComposeRotationBackendError("reviewed replacement certificate identity has drifted")
            self._mounts = {
                _MOUNT_DESTINATIONS[CA_ENV]: Path(env[CA_ENV]),
                _MOUNT_DESTINATIONS["certificate"]: Path(env[CERTIFICATE_ENV[self.profile.service]]),
                _MOUNT_DESTINATIONS["key"]: Path(env[KEY_ENV[self.profile.service]]),
            }
            for route in self.profile.route_observers:
                route_images = self.runner.run(
                    [*self._prefix, "config", "--images", route.executor_service],
                    capture_output=True,
                ).splitlines()
                if route_images != [route.expected_image]:
                    raise ComposeRotationBackendError("Compose observer image has drifted")
                target = self.snapshot()[0]
                if target.connect_host is None or target.network_identity is None:
                    raise ComposeRotationBackendError("Compose target identity has drifted")
                executor = get_compose_probe_executor(
                    self.runner,
                    self._prefix,
                    service=route.executor_service,
                    expected_image=route.expected_image,
                    expected_network=self.profile.direct_network,
                    expected_network_identity=target.network_identity,
                )
                command = docker_probe_command(
                    executor,
                    url=route.url,
                    ca_file=route.ca_file,
                    connect_host=target.connect_host,
                )
                parse_tls_probe_observation(
                    self.runner.run(
                        command.command,
                        capture_output=True,
                        input_text=command.input_text,
                    ),
                    expected_sha256=str(projection["old_leaf_sha256"]),
                )
                if (
                    get_compose_probe_executor(
                        self.runner,
                        self._prefix,
                        service=route.executor_service,
                        expected_image=route.expected_image,
                        expected_network=self.profile.direct_network,
                        expected_network_identity=target.network_identity,
                    )
                    != executor
                    or self.snapshot() != [target]
                ):
                    raise ComposeRotationBackendError("Compose observer identity has drifted")
        except (CertificateInputError, KeyError, OSError, ValueError):
            raise ComposeRotationBackendError("Compose TLS input preflight failed") from None

    def snapshot(self) -> list[RuntimeInstanceSnapshot]:
        return collect_compose_generation(
            self.runner,
            self._prefix,
            service=self.profile.service,
            expected_tls_mounts=self._mounts,
            expected_image=self.profile.expected_image,
            expected_network=self.profile.direct_network,
        )

    def probe_instance(self, instance, *, expected_sha256, phase, observed_at):
        if (
            self._direct_executor_image is None
            or instance.connect_host is None
            or instance.network_identity is None
            or self.snapshot() != [instance]
        ):
            raise ComposeRotationBackendError("Compose target identity has drifted")
        executor = get_compose_probe_executor(
            self.runner,
            self._prefix,
            service=self.profile.direct_executor,
            expected_image=self._direct_executor_image,
            expected_network=self.profile.direct_network,
            expected_network_identity=instance.network_identity,
        )
        command = docker_probe_command(
            executor,
            url=self.profile.direct_url,
            ca_file=self.profile.direct_ca_file,
            connect_host=instance.connect_host,
        )
        observation = collect_peer_observation(
            self.runner,
            command,
            phase=phase,
            observer="direct-instance",
            instance_id=instance.evidence["instance_id"],
            attempt=1,
            expected_sha256=expected_sha256,
            observed_at=observed_at,
        )
        if (
            get_compose_probe_executor(
                self.runner,
                self._prefix,
                service=self.profile.direct_executor,
                expected_image=self._direct_executor_image,
                expected_network=self.profile.direct_network,
                expected_network_identity=instance.network_identity,
            )
            != executor
            or self.snapshot() != [instance]
        ):
            raise ComposeRotationBackendError("Compose target identity has drifted")
        return observation

    def act(self) -> None:
        force_recreate_compose_service(
            self.runner,
            self._prefix,
            service=self.profile.service,
        )

    def reconcile_action(
        self,
        before,
        *,
        old_sha256,
        new_sha256,
        observed_at,
    ) -> ActionReconciliation:
        """Classify an indeterminate CLI return using only inventory and probes."""

        try:
            first = self.snapshot()
            if first == list(before):
                result = "verified_old"
                expected = old_sha256
                phase = "action_reconcile_old"
            else:
                assert_generation_replaced(before, first, expected_count=1)
                result = "verified_new"
                expected = new_sha256
                phase = "action_reconcile_new"
        except Exception:
            return ActionReconciliation("unknown", reason_code="runtime_read_failed")
        try:
            observations = tuple(
                self.probe_instance(
                    instance,
                    expected_sha256=expected,
                    phase=phase,
                    observed_at=observed_at,
                )
                for instance in first
            )
        except Exception:
            return ActionReconciliation("unknown", reason_code="peer_unconfirmed")
        try:
            if self.snapshot() != first:
                raise ComposeRotationBackendError("Compose generation drifted during reconciliation")
            return ActionReconciliation(result, tuple(first), observations)
        except Exception:
            return ActionReconciliation("unknown", reason_code="inventory_unstable")

    def probe_route(self, observer, *, attempt, expected_sha256, observed_at):
        route = self._routes.get(observer)
        if route is None:
            raise ComposeRotationBackendError("route observer is not reviewed")
        target = self.snapshot()[0]
        if target.connect_host is None or target.network_identity is None:
            raise ComposeRotationBackendError("Compose target identity has drifted")
        executor = get_compose_probe_executor(
            self.runner,
            self._prefix,
            service=route.executor_service,
            expected_image=route.expected_image,
            expected_network=self.profile.direct_network,
            expected_network_identity=target.network_identity,
        )
        command = docker_probe_command(
            executor,
            url=route.url,
            ca_file=route.ca_file,
            connect_host=target.connect_host,
        )
        observation = collect_peer_observation(
            self.runner,
            command,
            phase="retirement_route",
            observer=observer,
            instance_id=None,
            attempt=attempt,
            expected_sha256=expected_sha256,
            observed_at=observed_at,
        )
        if (
            get_compose_probe_executor(
                self.runner,
                self._prefix,
                service=route.executor_service,
                expected_image=route.expected_image,
                expected_network=self.profile.direct_network,
                expected_network_identity=target.network_identity,
            )
            != executor
            or self.snapshot() != [target]
        ):
            raise ComposeRotationBackendError("Compose observer identity has drifted")
        return observation

    def contain(self) -> None:
        self.runner.run([*self._prefix, "stop", "--timeout", "30", self.profile.service])
        remaining = self.runner.run(
            [*self._prefix, "ps", "-q", self.profile.service],
            capture_output=True,
        ).strip()
        if remaining:
            raise ComposeRotationBackendError("Compose service stop is unconfirmed")

    def close(self) -> None:
        """Compose owns no temporary secret resource."""


def build_compose_rotation_backend(
    profile_path: Path,
    projection: Mapping[str, object],
    *,
    shell_environment: Mapping[str, str],
    runner_factory=SanitizedSubprocessRunner,
) -> ComposeRotationBackend:
    profile = load_compose_rotation_profile(profile_path)
    if (
        projection.get("runtime_kind") != "compose"
        or projection.get("target_environment") != profile.target_environment
        or projection.get("service") != profile.service
        or projection.get("expected_instance_count") != profile.expected_instance_count
        or projection.get("required_observers") != list(profile.required_observers)
        or projection.get("runtime_profile_sha256") != profile.profile_sha256
    ):
        raise ComposeRotationBackendError("runtime profile does not match rotation plan")
    if profile.blocked_observers:
        raise ComposeRotationBackendError("required real observer probe runtime is unavailable")
    if profile.compose_kind != "base":
        raise ComposeRotationBackendError("standalone rolling service rotation is unavailable")
    return ComposeRotationBackend(profile, runner_factory(shell_environment))
