"""Read-only Compose/Kubernetes collectors for TLS runtime profile capture."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace
from typing import Mapping, Sequence

from scripts.check_internal_tls_expiry import (
    CA_ENV,
    CERTIFICATE_ENV,
    KEY_ENV,
    _load_env_file,
)
from scripts.compose_tls_rotation_backend import (
    PROFILE_KIND as COMPOSE_PROFILE_KIND,
    PROFILE_SCHEMA_VERSION as COMPOSE_PROFILE_SCHEMA,
    _CA_FILE as COMPOSE_CA_FILE,
    _MOUNT_DESTINATIONS,
    _PYTHON_EXECUTORS,
    _TARGETS as COMPOSE_TARGETS,
    compose_prefix,
)
from scripts.external_json import parse_unique_json_bytes, read_stable_bytes
from scripts.kubernetes_tls_rotation_backend import (
    PROFILE_KIND as KUBERNETES_PROFILE_KIND,
    PROFILE_SCHEMA_VERSION as KUBERNETES_PROFILE_SCHEMA,
    _CA_FILE as KUBERNETES_CA_FILE,
    _TARGETS as KUBERNETES_TARGETS,
    kubectl_prefix,
)
from scripts.kubernetes_kubeconfig_intake import (
    KubernetesKubeconfigIntakeError,
    validate_self_contained_kubeconfig,
)
from scripts.private_secret_file import read_private_secret_bytes
from scripts.private_secret_materialization import (
    MaterializedPrivateSecret,
    PrivateSecretMaterializationError,
    materialize_private_secret_bytes,
)
from scripts.rollback_release import PRODUCTION_ENV_FILE
from scripts.tls_rotation_profile_capture import TlsRotationProfileCaptureError
from scripts.tls_rotation_runner import SanitizedSubprocessRunner
from scripts.tls_rotation_runtime import (
    RotationRuntimeError,
    collect_compose_generation,
    collect_kubernetes_generation,
    get_compose_probe_executor,
    get_kubernetes_deployment_snapshot,
    get_kubernetes_namespace_uid,
)


_OCI_IMAGE = re.compile(r"^[^\s:@]+(?:/[^\s:@]+)+@sha256:[0-9a-f]{64}$")
_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_UID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_KUBERNETES_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_KUBERNETES_SELECTOR = re.compile(
    r"^app\.kubernetes\.io/name=email-platform,"
    r"app\.kubernetes\.io/component=[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_READONLY_DOCKER_INSPECT_FORMATS = frozenset({
    "{{.Id}}", "{{.State.Running}}", "{{.State.StartedAt}}",
    "{{.Config.Image}}", "{{json .Mounts}}",
    "{{json .NetworkSettings.Networks}}",
})
_KUBERNETES_NAMED_RESOURCES = frozenset({
    "namespace", "deployment", "pod", "replicaset"
})


class ReadOnlyCaptureRunner:
    """Reject every runtime command outside the fixed metadata-read allowlist."""

    def __init__(self, delegate=None) -> None:
        self._delegate = delegate or SanitizedSubprocessRunner()

    def run(
        self,
        command: Sequence[str],
        *,
        capture_output: bool = False,
        input_text: str | None = None,
    ) -> str:
        values = list(command)
        allowed = False
        if len(values) >= 2 and values[:2] == ["docker", "compose"]:
            forbidden = {
                "up", "down", "start", "stop", "restart", "kill", "rm",
                "create", "run", "exec", "pull", "push", "build", "cp",
                "pause", "unpause", "scale", "events", "logs", "top",
            }
            allowed = (
                not forbidden.intersection(values)
                and len(values) >= 5
                and values[-3] == "config"
                and values[-2] == "--images"
                and values.count("config") == 1
            ) or (
                not forbidden.intersection(values)
                and len(values) >= 6
                and values[-4:-1] == ["ps", "--all", "-q"]
                and values.count("ps") == 1
            )
        elif len(values) == 5 and values[:3] == ["docker", "inspect", "--format"]:
            allowed = values[3] in _READONLY_DOCKER_INSPECT_FORMATS
        elif values and values[0] == "kubectl":
            allowed = self._allowed_kubernetes_get(values)
        if not allowed or input_text is not None or not capture_output:
            raise TlsRotationProfileCaptureError("runtime profile capture command is invalid")
        return self._delegate.run(values, capture_output=True)

    @staticmethod
    def _allowed_kubernetes_get(values: list[str]) -> bool:
        try:
            get_index = values.index("get")
        except ValueError:
            return False
        if values.count("get") != 1:
            return False
        prefix = values[1:get_index]
        if len(prefix) not in {5, 7}:
            return False
        if (
            prefix[:1] != ["--kubeconfig"]
            or not prefix[1]
            or prefix[2:3] != ["--context"]
            or not prefix[3]
            or prefix[4] != "--request-timeout=30s"
            or (
                len(prefix) == 7
                and (prefix[5] != "--namespace" or not prefix[6])
            )
        ):
            return False
        suffix = values[get_index + 1:]
        if len(suffix) == 4 and suffix[0] in _KUBERNETES_NAMED_RESOURCES:
            return (
                _KUBERNETES_NAME.fullmatch(suffix[1]) is not None
                and suffix[2:] == ["-o", "json"]
            )
        return (
            len(suffix) == 5
            and suffix[0] == "pods"
            and suffix[1] == "-l"
            and _KUBERNETES_SELECTOR.fullmatch(suffix[2]) is not None
            and suffix[3:] == ["-o", "json"]
        )


def _compose_image(runner, prefix: Sequence[str], service: str) -> str:
    values = runner.run(
        [*prefix, "config", "--images", service], capture_output=True
    ).splitlines()
    if len(values) != 1 or _OCI_IMAGE.fullmatch(values[0]) is None:
        raise TlsRotationProfileCaptureError("Compose capture image is invalid")
    return values[0]


def _compose_service_identity(
    runner, prefix: Sequence[str], service: str, expected_image: str
) -> tuple[str, str, str]:
    identifier = runner.run(
        [*prefix, "ps", "--all", "-q", service], capture_output=True
    ).strip()
    if _CONTAINER_ID.fullmatch(identifier) is None:
        raise TlsRotationProfileCaptureError("Compose capture identity is invalid")
    inspected = runner.run(
        ["docker", "inspect", "--format", "{{.Id}}", identifier],
        capture_output=True,
    ).strip()
    running = runner.run(
        ["docker", "inspect", "--format", "{{.State.Running}}", identifier],
        capture_output=True,
    ).strip()
    started = runner.run(
        ["docker", "inspect", "--format", "{{.State.StartedAt}}", identifier],
        capture_output=True,
    ).strip()
    image = runner.run(
        ["docker", "inspect", "--format", "{{.Config.Image}}", identifier],
        capture_output=True,
    ).strip()
    if inspected != identifier or running != "true" or image != expected_image:
        raise TlsRotationProfileCaptureError("Compose capture identity has drifted")
    return identifier, started, image


def _compose_capture(request: Mapping[str, object], runner):
    service = str(request["service"])
    contract = COMPOSE_TARGETS[service]
    if contract.direct_executor not in _PYTHON_EXECUTORS:
        raise TlsRotationProfileCaptureError("Compose direct observer is unavailable")
    prefix = compose_prefix(SimpleNamespace(compose_kind=contract.compose_kind))
    first_env = read_stable_bytes(PRODUCTION_ENV_FILE, max_bytes=64 * 1024)
    env = _load_env_file(PRODUCTION_ENV_FILE)
    mounts = {
        _MOUNT_DESTINATIONS[CA_ENV]: Path(env[CA_ENV]),
        _MOUNT_DESTINATIONS["certificate"]: Path(env[CERTIFICATE_ENV[service]]),
        _MOUNT_DESTINATIONS["key"]: Path(env[KEY_ENV[service]]),
    }
    target_image = _compose_image(runner, prefix, service)
    direct_image = _compose_image(runner, prefix, contract.direct_executor)
    target_first = collect_compose_generation(
        runner,
        prefix,
        service=service,
        expected_tls_mounts=mounts,
        expected_image=target_image,
        expected_network=contract.direct_network,
    )
    target = target_first[0]
    if target.network_identity is None:
        raise TlsRotationProfileCaptureError("Compose target network is invalid")
    direct_first = get_compose_probe_executor(
        runner,
        prefix,
        service=contract.direct_executor,
        expected_image=direct_image,
        expected_network=contract.direct_network,
        expected_network_identity=target.network_identity,
    )
    routes = []
    blocked = []
    route_identities: dict[str, tuple[str, str, str]] = {}
    for observer in contract.required_observers:
        if observer not in _PYTHON_EXECUTORS:
            blocked.append(observer)
            continue
        image = _compose_image(runner, prefix, observer)
        route_identities[observer] = _compose_service_identity(
            runner, prefix, observer, image
        )
        routes.append({
            "logical_name": observer,
            "executor_service": observer,
            "expected_image": image,
            "url": contract.url,
            "ca_file": COMPOSE_CA_FILE,
        })

    second_env = read_stable_bytes(PRODUCTION_ENV_FILE, max_bytes=64 * 1024)
    target_image_second = _compose_image(runner, prefix, service)
    direct_image_second = _compose_image(runner, prefix, contract.direct_executor)
    target_second = collect_compose_generation(
        runner,
        prefix,
        service=service,
        expected_tls_mounts=mounts,
        expected_image=target_image,
        expected_network=contract.direct_network,
    )
    direct_second = get_compose_probe_executor(
        runner,
        prefix,
        service=contract.direct_executor,
        expected_image=direct_image,
        expected_network=contract.direct_network,
        expected_network_identity=target.network_identity,
    )
    route_second = {
        item["logical_name"]: _compose_service_identity(
            runner, prefix, item["executor_service"], item["expected_image"]
        )
        for item in routes
    }
    if (
        first_env != second_env
        or target_image != target_image_second
        or direct_image != direct_image_second
        or target_first != target_second
        or direct_first != direct_second
        or route_identities != route_second
    ):
        raise TlsRotationProfileCaptureError("Compose capture identity is unstable")
    candidate = {
        "schema_version": COMPOSE_PROFILE_SCHEMA,
        "profile_kind": COMPOSE_PROFILE_KIND,
        "target_environment": request["target_environment"],
        "service": service,
        "expected_instance_count": 1,
        "required_observers": list(contract.required_observers),
        "env_file_sha256": hashlib.sha256(first_env).hexdigest(),
        "expected_image": target_image,
        "compose_kind": contract.compose_kind,
        "direct_probe": {
            "executor_service": contract.direct_executor,
            "expected_image": direct_image,
            "url": contract.url,
            "ca_file": COMPOSE_CA_FILE,
            "network": contract.direct_network,
        },
        "route_observers": routes,
        "blocked_observers": sorted(blocked),
    }
    summary = {
        "instances": [dict(target.evidence)],
        "captured_observers": sorted(
            ["direct-instance", *[item["logical_name"] for item in routes]]
        ),
        "blocked_observers": sorted(blocked),
    }
    return candidate, summary


@dataclass(frozen=True)
class _ObserverDeployment:
    uid: str
    generation: int
    revision: int
    image: str


def _runtime_json(output: str) -> object:
    try:
        raw = output.encode("utf-8")
        if not raw or len(raw) > 1024 * 1024:
            raise ValueError
        return parse_unique_json_bytes(raw)
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise TlsRotationProfileCaptureError("Kubernetes capture response is invalid") from None


def _observer_deployment(runner, prefix, deployment: str, container: str):
    value = _runtime_json(runner.run(
        [*prefix, "get", "deployment", deployment, "-o", "json"],
        capture_output=True,
    ))
    metadata = value.get("metadata") if isinstance(value, dict) else None
    spec = value.get("spec") if isinstance(value, dict) else None
    status = value.get("status") if isinstance(value, dict) else None
    annotations = metadata.get("annotations") if isinstance(metadata, dict) else None
    template = spec.get("template") if isinstance(spec, dict) else None
    pod_spec = template.get("spec") if isinstance(template, dict) else None
    containers = pod_spec.get("containers") if isinstance(pod_spec, dict) else None
    selected = [
        item for item in containers
        if isinstance(item, dict) and item.get("name") == container
    ] if isinstance(containers, list) else []
    try:
        revision = int(annotations.get("deployment.kubernetes.io/revision"))
    except (AttributeError, TypeError, ValueError):
        raise TlsRotationProfileCaptureError("Kubernetes observer is invalid") from None
    uid = metadata.get("uid") if isinstance(metadata, dict) else None
    generation = metadata.get("generation") if isinstance(metadata, dict) else None
    image = selected[0].get("image") if len(selected) == 1 else None
    if (
        not all(isinstance(item, dict) for item in (metadata, spec, status))
        or not isinstance(uid, str)
        or _UID.fullmatch(uid) is None
        or type(generation) is not int
        or generation < 1
        or revision < 1
        or not isinstance(image, str)
        or _OCI_IMAGE.fullmatch(image) is None
        or spec.get("replicas") != 1
        or status.get("observedGeneration") != generation
        or status.get("replicas") != 1
        or status.get("updatedReplicas") != 1
        or status.get("readyReplicas") != 1
        or status.get("availableReplicas") != 1
        or status.get("unavailableReplicas", 0) != 0
    ):
        raise TlsRotationProfileCaptureError("Kubernetes observer is invalid")
    return _ObserverDeployment(uid, generation, revision, image)


def _observer_profile(runner, base_prefix, locator):
    namespace = locator["namespace"]
    namespace_uid = get_kubernetes_namespace_uid(
        runner, base_prefix, namespace=namespace
    )
    prefix = (*base_prefix, "--namespace", namespace)
    deployment = _observer_deployment(
        runner, prefix, locator["deployment"], locator["container"]
    )
    instances = collect_kubernetes_generation(
        runner,
        prefix,
        deployment=locator["deployment"],
        expected_count=1,
        deployment_uid=deployment.uid,
        target_revision=deployment.revision,
    )
    instance = instances[0]
    runtime_image = (
        instance.image_identity.removeprefix("docker-pullable://").removeprefix("containerd://")
        if isinstance(instance.image_identity, str) else None
    )
    if (
        instance.controller_id is None
        or instance.runtime_name is None
        or runtime_image != deployment.image
    ):
        raise TlsRotationProfileCaptureError("Kubernetes observer identity is invalid")
    return {
        "logical_name": locator["logical_name"],
        "namespace": namespace,
        "namespace_uid": namespace_uid,
        "deployment": locator["deployment"],
        "deployment_uid": deployment.uid,
        "pod": instance.runtime_name,
        "pod_uid": instance.evidence["instance_id"],
        "replicaset_uid": instance.controller_id,
        "revision": deployment.revision,
        "container": locator["container"],
        "expected_image": instance.image_identity,
        "url": "",
        "ca_file": KUBERNETES_CA_FILE,
    }, deployment, instance


def _kubernetes_capture_materialized(
    request: Mapping[str, object],
    runner,
    *,
    kubeconfig: Path,
    first_kubeconfig: bytes,
    first_kubeconfig_sha256: str,
    materialized: MaterializedPrivateSecret,
):
    service = str(request["service"])
    contract = KUBERNETES_TARGETS[service]
    base_prefix = kubectl_prefix(
        materialized.path,
        context=str(request["context"]),
    )
    target_prefix = kubectl_prefix(
        materialized.path,
        context=str(request["context"]),
        namespace=str(request["namespace"]),
    )

    def snapshot():
        namespace_uid = get_kubernetes_namespace_uid(
            runner, base_prefix, namespace=str(request["namespace"])
        )
        deployment = get_kubernetes_deployment_snapshot(
            runner,
            target_prefix,
            deployment=service,
            expected_count=2,
        )
        if deployment.tls_secret_name != contract.tls_secret_name:
            raise TlsRotationProfileCaptureError("Kubernetes target identity is invalid")
        instances = collect_kubernetes_generation(
            runner,
            target_prefix,
            deployment=service,
            expected_count=2,
            deployment_uid=deployment.uid,
            target_revision=deployment.revision,
        )
        if len({item.controller_id for item in instances}) != 1:
            raise TlsRotationProfileCaptureError(
                "Kubernetes target ReplicaSet identity is ambiguous"
            )
        if any(
            not isinstance(item.image_identity, str)
            or item.image_identity.removeprefix("docker-pullable://").removeprefix("containerd://")
            != deployment.image_identity
            for item in instances
        ):
            raise TlsRotationProfileCaptureError("Kubernetes target image has drifted")
        direct, direct_deployment, direct_instance = _observer_profile(
            runner, base_prefix, request["direct_observer"]
        )
        direct["url"] = contract.url
        routes = []
        route_state = []
        for locator in request["route_observers"]:
            route, route_deployment, route_instance = _observer_profile(
                runner, base_prefix, locator
            )
            route["url"] = contract.url
            routes.append(route)
            route_state.append((route_deployment, route_instance))
        return (
            namespace_uid, deployment, tuple(instances), direct,
            direct_deployment, direct_instance, tuple(routes), tuple(route_state),
        )

    materialized.verify()
    first = snapshot()
    materialized.verify()
    second = snapshot()
    materialized.verify()
    second_kubeconfig = read_private_secret_bytes(
        kubeconfig, max_bytes=1024 * 1024, require_read_only=True
    )
    try:
        second_kubeconfig_sha256 = validate_self_contained_kubeconfig(
            second_kubeconfig,
            expected_context=str(request["context"]),
            expected_namespace=str(request["namespace"]),
        )
    except KubernetesKubeconfigIntakeError:
        raise TlsRotationProfileCaptureError(
            "Kubernetes kubeconfig intake is invalid"
        ) from None
    if (
        first != second
        or first_kubeconfig != second_kubeconfig
        or first_kubeconfig_sha256 != second_kubeconfig_sha256
    ):
        raise TlsRotationProfileCaptureError("Kubernetes capture identity is unstable")
    namespace_uid, deployment, instances, direct, _, _, routes, _ = first
    candidate = {
        "schema_version": KUBERNETES_PROFILE_SCHEMA,
        "profile_kind": KUBERNETES_PROFILE_KIND,
        "target_environment": request["target_environment"],
        "service": service,
        "expected_instance_count": 2,
        "required_observers": list(contract.required_observers),
        "kubeconfig_path": str(kubeconfig),
        "kubeconfig_sha256": first_kubeconfig_sha256,
        "context": request["context"],
        "namespace": request["namespace"],
        "namespace_uid": namespace_uid,
        "deployment_uid": deployment.uid,
        "expected_image": deployment.image_identity,
        "direct_probe": direct,
        "route_observers": list(routes),
        "blocked_observers": [],
    }
    summary = {
        "instances": [dict(item.evidence) for item in instances],
        "captured_observers": sorted(
            ["direct-instance", *[item["logical_name"] for item in routes]]
        ),
        "blocked_observers": [],
    }
    return candidate, summary


def _kubernetes_capture(request: Mapping[str, object], runner):
    kubeconfig = Path(str(request["kubeconfig_path"]))
    first_kubeconfig = read_private_secret_bytes(
        kubeconfig, max_bytes=1024 * 1024, require_read_only=True
    )
    try:
        first_kubeconfig_sha256 = validate_self_contained_kubeconfig(
            first_kubeconfig,
            expected_context=str(request["context"]),
            expected_namespace=str(request["namespace"]),
        )
        with materialize_private_secret_bytes(
            first_kubeconfig,
            first_kubeconfig_sha256,
        ) as materialized:
            return _kubernetes_capture_materialized(
                request,
                runner,
                kubeconfig=kubeconfig,
                first_kubeconfig=first_kubeconfig,
                first_kubeconfig_sha256=first_kubeconfig_sha256,
                materialized=materialized,
            )
    except KubernetesKubeconfigIntakeError:
        raise TlsRotationProfileCaptureError(
            "Kubernetes kubeconfig intake is invalid"
        ) from None
    except PrivateSecretMaterializationError:
        raise TlsRotationProfileCaptureError(
            "Kubernetes kubeconfig materialization failed"
        ) from None


def capture_runtime_profile(request: Mapping[str, object]):
    runner = ReadOnlyCaptureRunner()
    try:
        if request["runtime_kind"] == "compose":
            return _compose_capture(request, runner)
        if request["runtime_kind"] == "kubernetes":
            return _kubernetes_capture(request, runner)
    except (
        KeyError,
        OSError,
        TypeError,
        ValueError,
        RotationRuntimeError,
    ):
        raise TlsRotationProfileCaptureError("runtime profile live capture failed") from None
    raise TlsRotationProfileCaptureError("runtime profile live capture failed")
