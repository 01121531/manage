"""Collect fail-closed runtime generations for TLS leaf rotation evidence.

The returned records intentionally omit pod names, pod IPs, host paths, URLs, and
secret material. Connection addresses remain process-local so they can be used by
the shared same-connection TLS probe without entering published evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
from typing import Mapping, Protocol, Sequence

from scripts.external_json import parse_unique_json_bytes
from scripts.tls_runtime_identity import (
    TLS_HTTP_PROBE_PROGRAM,
    parse_tls_probe_observation,
)


_COMPOSE_ID = re.compile(r"^[0-9a-f]{64}$")
_COMPOSE_NETWORK_ID = re.compile(r"^[0-9a-f]{64}$")
_KUBERNETES_UID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_CONTAINER_ID = re.compile(r"^(?:containerd|docker|cri-o)://[0-9a-f]{64}$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_MAX_RUNTIME_JSON_BYTES = 1024 * 1024
_MAX_PROBE_INPUT_BYTES = 4096
ACTION_RECONCILIATION_REASON_CODES = frozenset(
    {
        "runtime_read_failed",
        "deployment_unobserved",
        "rollout_markers_ambiguous",
        "mixed_replicasets",
        "pod_terminating",
        "pod_unready",
        "replica_count_mismatch",
        "owner_chain_invalid",
        "peer_unconfirmed",
        "inventory_unstable",
        "reconcile_contract_invalid",
    }
)

TLS_STDIN_HTTP_PROBE_PROGRAM = TLS_HTTP_PROBE_PROGRAM.replace(
    "url = urllib.parse.urlsplit(sys.argv[1])",
    """\
def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SystemExit(19)
        value[key] = item
    return value
raw_config = sys.stdin.buffer.read(4097)
if not raw_config or len(raw_config) > 4096:
    raise SystemExit(19)
try:
    config = json.loads(raw_config.decode("utf-8"), object_pairs_hook=unique_object)
except (UnicodeDecodeError, ValueError):
    raise SystemExit(19)
if not isinstance(config, dict) or set(config) != {
    "url", "ca_file", "max_body_bytes", "content_type", "require_nonempty",
    "expected_json", "connect_host"
}:
    raise SystemExit(19)
url = urllib.parse.urlsplit(config["url"])""",
).replace(
    'ca_file = None if sys.argv[2] == "-" else sys.argv[2]\nmaximum = int(sys.argv[3])\ncontent_type = None if sys.argv[4] == "-" else sys.argv[4]\nrequire_nonempty = sys.argv[5] == "1"\nexpected_json = None if sys.argv[6] == "-" else json.loads(sys.argv[6])\nif len(sys.argv) not in {7, 8}:\n    raise SystemExit(17)\nconnect_host = url.hostname if len(sys.argv) == 7 else sys.argv[7]',
    'ca_file = config["ca_file"]\nmaximum = config["max_body_bytes"]\ncontent_type = config["content_type"]\nrequire_nonempty = config["require_nonempty"]\nexpected_json = config["expected_json"]\nconnect_host = config["connect_host"] or url.hostname',
)


class RotationRuntimeError(ValueError):
    """The runtime cannot prove the requested replacement generation."""


class Runner(Protocol):
    def run(
        self,
        command: Sequence[str],
        *,
        capture_output: bool = False,
        input_text: str | None = None,
    ) -> str: ...


@dataclass(frozen=True)
class RuntimeInstanceSnapshot:
    evidence: dict[str, str]
    connect_host: str | None = None
    runtime_name: str | None = None
    controller_id: str | None = None
    image_identity: str | None = None
    network_identity: str | None = None


@dataclass(frozen=True)
class KubernetesDeploymentSnapshot:
    uid: str
    generation: int
    observed_generation: int
    revision: int
    restarted_at: str | None
    paused: bool
    image_identity: str
    tls_secret_name: str


@dataclass(frozen=True)
class ProbeInvocation:
    command: tuple[str, ...]
    input_text: str


@dataclass(frozen=True)
class ActionReconciliation:
    result: str
    instances: tuple[RuntimeInstanceSnapshot, ...] = ()
    peer_observations: tuple[dict[str, object], ...] = ()
    reason_code: str | None = None


def _name(value: str, context: str) -> str:
    if not isinstance(value, str) or _DNS_LABEL.fullmatch(value) is None:
        raise RotationRuntimeError(f"invalid {context}")
    return value


def _json_output(output: str, context: str) -> object:
    try:
        raw = output.encode("utf-8")
    except UnicodeEncodeError as error:
        raise RotationRuntimeError(f"invalid {context}") from error
    if not raw or len(raw) > _MAX_RUNTIME_JSON_BYTES:
        raise RotationRuntimeError(f"invalid {context}")
    try:
        return parse_unique_json_bytes(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RotationRuntimeError(f"invalid {context}") from error


def normalize_started_at(value: object) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RotationRuntimeError("invalid runtime start timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise RotationRuntimeError("invalid runtime start timestamp") from error
    if parsed.tzinfo != timezone.utc:
        raise RotationRuntimeError("invalid runtime start timestamp")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _same_path(left: object, right: Path) -> bool:
    if not isinstance(left, str) or not left:
        return False
    try:
        actual = Path(left).resolve(strict=True)
        reviewed = right.resolve(strict=True)
    except OSError:
        return False
    return os.path.normcase(str(actual)) == os.path.normcase(str(reviewed))


def collect_compose_generation(
    runner: Runner,
    compose_prefix: Sequence[str],
    *,
    service: str,
    expected_tls_mounts: Mapping[str, Path],
    expected_image: str,
    expected_network: str,
) -> list[RuntimeInstanceSnapshot]:
    service = _name(service, "Compose service")
    expected_network = _name(expected_network, "Compose network")
    if not compose_prefix or not expected_tls_mounts or not expected_image:
        raise RotationRuntimeError("Compose rotation contract is incomplete")
    identifier = runner.run(
        [*compose_prefix, "ps", "--all", "-q", service], capture_output=True
    ).strip()
    if _COMPOSE_ID.fullmatch(identifier) is None:
        raise RotationRuntimeError("Compose runtime identity is invalid")
    inspected_id = runner.run(
        ["docker", "inspect", "--format", "{{.Id}}", identifier],
        capture_output=True,
    ).strip()
    running = runner.run(
        ["docker", "inspect", "--format", "{{.State.Running}}", identifier],
        capture_output=True,
    ).strip()
    started_at = runner.run(
        ["docker", "inspect", "--format", "{{.State.StartedAt}}", identifier],
        capture_output=True,
    ).strip()
    mounts = _json_output(
        runner.run(
            ["docker", "inspect", "--format", "{{json .Mounts}}", identifier],
            capture_output=True,
        ),
        "Compose mount inventory",
    )
    image_identity = runner.run(
        ["docker", "inspect", "--format", "{{.Config.Image}}", identifier],
        capture_output=True,
    ).strip()
    networks = _json_output(
        runner.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{json .NetworkSettings.Networks}}",
                identifier,
            ],
            capture_output=True,
        ),
        "Compose network inventory",
    )
    if inspected_id != identifier or running != "true" or not isinstance(mounts, list):
        raise RotationRuntimeError("Compose runtime is not running")
    if image_identity != expected_image:
        raise RotationRuntimeError("Compose image identity has drifted")
    network = networks.get(expected_network) if isinstance(networks, dict) else None
    address = network.get("IPAddress") if isinstance(network, dict) else None
    network_identity = network.get("NetworkID") if isinstance(network, dict) else None
    try:
        parsed_address = ipaddress.ip_address(address) if isinstance(address, str) else None
    except ValueError as error:
        raise RotationRuntimeError("Compose direct network identity is invalid") from error
    if (
        parsed_address is None
        or not isinstance(network_identity, str)
        or _COMPOSE_NETWORK_ID.fullmatch(network_identity) is None
        or parsed_address.is_unspecified
        or parsed_address.is_loopback
        or parsed_address.is_multicast
        or parsed_address.is_link_local
    ):
        raise RotationRuntimeError("Compose direct network identity is invalid")
    for destination, reviewed_source in expected_tls_mounts.items():
        matching = [
            item
            for item in mounts
            if isinstance(item, dict) and item.get("Destination") == destination
        ]
        if (
            len(matching) != 1
            or matching[0].get("Type") != "bind"
            or matching[0].get("RW") is not False
            or not _same_path(matching[0].get("Source"), reviewed_source)
        ):
            raise RotationRuntimeError("Compose reviewed TLS mount contract has drifted")
    return [
        RuntimeInstanceSnapshot(
            evidence={
                "instance_id": identifier,
                "container_id": identifier,
                "started_at": normalize_started_at(started_at),
            },
            connect_host=address,
            image_identity=image_identity,
            network_identity=network_identity,
        )
    ]


def get_compose_probe_executor(
    runner: Runner,
    compose_prefix: Sequence[str],
    *,
    service: str,
    expected_image: str,
    expected_network: str,
    expected_network_identity: str,
) -> str:
    """Return one exact running probe container on the target network."""

    service = _name(service, "Compose probe executor")
    expected_network = _name(expected_network, "Compose network")
    if (
        not compose_prefix
        or not expected_image
        or _COMPOSE_NETWORK_ID.fullmatch(expected_network_identity) is None
    ):
        raise RotationRuntimeError("Compose probe executor contract is incomplete")
    identifier = runner.run(
        [*compose_prefix, "ps", "--all", "-q", service], capture_output=True
    ).strip()
    if _COMPOSE_ID.fullmatch(identifier) is None:
        raise RotationRuntimeError("Compose probe executor identity is invalid")
    inspected_id = runner.run(
        ["docker", "inspect", "--format", "{{.Id}}", identifier],
        capture_output=True,
    ).strip()
    running = runner.run(
        ["docker", "inspect", "--format", "{{.State.Running}}", identifier],
        capture_output=True,
    ).strip()
    image_identity = runner.run(
        ["docker", "inspect", "--format", "{{.Config.Image}}", identifier],
        capture_output=True,
    ).strip()
    networks = _json_output(
        runner.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{json .NetworkSettings.Networks}}",
                identifier,
            ],
            capture_output=True,
        ),
        "Compose probe executor network inventory",
    )
    network = networks.get(expected_network) if isinstance(networks, dict) else None
    network_identity = network.get("NetworkID") if isinstance(network, dict) else None
    if (
        inspected_id != identifier
        or running != "true"
        or image_identity != expected_image
        or network_identity != expected_network_identity
    ):
        raise RotationRuntimeError("Compose probe executor identity has drifted")
    return identifier


def force_recreate_compose_service(
    runner: Runner,
    compose_prefix: Sequence[str],
    *,
    service: str,
) -> None:
    runner.run(
        [
            *compose_prefix,
            "up",
            "-d",
            "--no-deps",
            "--no-build",
            "--pull",
            "never",
            "--force-recreate",
            _name(service, "Compose service"),
        ]
    )


def _pod_ready(item: dict[str, object]) -> bool:
    status = item.get("status")
    if not isinstance(status, dict) or status.get("phase") != "Running":
        return False
    conditions = status.get("conditions")
    return isinstance(conditions, list) and any(
        isinstance(condition, dict)
        and condition.get("type") == "Ready"
        and condition.get("status") == "True"
        for condition in conditions
    )


def _kubernetes_pod_snapshot(
    runner: Runner,
    kubectl_prefix: Sequence[str],
    *,
    pod: object,
    deployment: str,
    deployment_uid: str,
    target_revision: int | None = None,
    target_replicaset_uid: str | None = None,
) -> RuntimeInstanceSnapshot:
    if (
        not kubectl_prefix
        or not isinstance(deployment_uid, str)
        or _KUBERNETES_UID.fullmatch(deployment_uid) is None
        or (target_revision is not None and (type(target_revision) is not int or target_revision < 1))
        or (
            target_replicaset_uid is not None
            and (
                not isinstance(target_replicaset_uid, str)
                or _KUBERNETES_UID.fullmatch(target_replicaset_uid) is None
            )
        )
    ):
        raise RotationRuntimeError("Kubernetes rotation contract is incomplete")
    if not isinstance(pod, dict) or not _pod_ready(pod):
        raise RotationRuntimeError("Kubernetes Pod is not ready")
    metadata = pod.get("metadata")
    if not isinstance(metadata, dict):
        raise RotationRuntimeError("Kubernetes Pod identity is invalid")
    pod_name = metadata.get("name")
    if not isinstance(pod_name, str):
        raise RotationRuntimeError("Kubernetes Pod identity is invalid")
    exact_pod = _json_output(
        runner.run(
            [*kubectl_prefix, "get", "pod", _name(pod_name, "Kubernetes Pod"), "-o", "json"],
            capture_output=True,
        ),
        "Kubernetes Pod identity",
    )
    exact_metadata = exact_pod.get("metadata") if isinstance(exact_pod, dict) else None
    status = exact_pod.get("status") if isinstance(exact_pod, dict) else None
    if (
        not isinstance(exact_metadata, dict)
        or exact_metadata.get("uid") != metadata.get("uid")
        or exact_metadata.get("name") != pod_name
        or not _pod_ready(exact_pod)
        or not isinstance(status, dict)
    ):
        raise RotationRuntimeError("Kubernetes Pod identity is invalid")
    owners = exact_metadata.get("ownerReferences")
    controlled_owners = [
        owner
        for owner in owners
        if (
            isinstance(owner, dict)
            and owner.get("apiVersion") == "apps/v1"
            and owner.get("kind") == "ReplicaSet"
            and owner.get("controller") is True
            and isinstance(owner.get("name"), str)
            and isinstance(owner.get("uid"), str)
            and _KUBERNETES_UID.fullmatch(owner["uid"]) is not None
        )
    ] if isinstance(owners, list) else []
    uid = exact_metadata.get("uid")
    address = status.get("podIP")
    statuses = status.get("containerStatuses")
    if (
        exact_metadata.get("deletionTimestamp") is not None
        or len(controlled_owners) != 1
        or not isinstance(uid, str)
        or _KUBERNETES_UID.fullmatch(uid) is None
        or not isinstance(address, str)
        or not isinstance(statuses, list)
    ):
        raise RotationRuntimeError("Kubernetes Pod identity is invalid")
    replica_owner = controlled_owners[0]
    if target_replicaset_uid is not None and replica_owner["uid"] != target_replicaset_uid:
        raise RotationRuntimeError("Kubernetes ReplicaSet ownership is invalid")
    replica_value = _json_output(
        runner.run(
            [*kubectl_prefix, "get", "replicaset", replica_owner["name"], "-o", "json"],
            capture_output=True,
        ),
        "Kubernetes ReplicaSet identity",
    )
    replica_metadata = replica_value.get("metadata") if isinstance(replica_value, dict) else None
    replica_owners = replica_metadata.get("ownerReferences") if isinstance(replica_metadata, dict) else None
    deployment_owners = [
        owner
        for owner in replica_owners
        if (
            isinstance(owner, dict)
            and owner.get("apiVersion") == "apps/v1"
            and owner.get("kind") == "Deployment"
            and owner.get("controller") is True
            and owner.get("name") == deployment
            and owner.get("uid") == deployment_uid
        )
    ] if isinstance(replica_owners, list) else []
    annotations = replica_metadata.get("annotations") if isinstance(replica_metadata, dict) else None
    if (
        not isinstance(replica_metadata, dict)
        or replica_metadata.get("uid") != replica_owner["uid"]
        or len(deployment_owners) != 1
        or (
            target_revision is not None
            and (
                not isinstance(annotations, dict)
                or annotations.get("deployment.kubernetes.io/revision") != str(target_revision)
            )
        )
    ):
        raise RotationRuntimeError("Kubernetes ReplicaSet ownership is invalid")
    try:
        ipaddress.ip_address(address)
    except ValueError as error:
        raise RotationRuntimeError("Kubernetes Pod address is invalid") from error
    primary = [entry for entry in statuses if isinstance(entry, dict) and entry.get("name") == deployment]
    if len(primary) != 1:
        raise RotationRuntimeError("Kubernetes container identity is invalid")
    container = primary[0]
    running = container.get("state", {}).get("running") if isinstance(container.get("state"), dict) else None
    container_id = container.get("containerID")
    image_identity = container.get("imageID")
    if (
        container.get("ready") is not True
        or type(container.get("restartCount")) is not int
        or container["restartCount"] < 0
        or not isinstance(running, dict)
        or not isinstance(container_id, str)
        or _CONTAINER_ID.fullmatch(container_id) is None
        or not isinstance(image_identity, str)
        or not image_identity
        or len(image_identity) > 512
    ):
        raise RotationRuntimeError("Kubernetes container identity is invalid")
    return RuntimeInstanceSnapshot(
        evidence={
            "instance_id": uid,
            "container_id": container_id,
            "started_at": normalize_started_at(running.get("startedAt")),
        },
        connect_host=address,
        runtime_name=pod_name,
        controller_id=replica_owner["uid"],
        image_identity=image_identity,
    )


def collect_kubernetes_generation(
    runner: Runner,
    kubectl_prefix: Sequence[str],
    *,
    deployment: str,
    expected_count: int,
    deployment_uid: str,
    target_revision: int | None = None,
    target_replicaset_uid: str | None = None,
) -> list[RuntimeInstanceSnapshot]:
    deployment = _name(deployment, "Kubernetes Deployment")
    if type(expected_count) is not int or not 1 <= expected_count <= 16:
        raise RotationRuntimeError("Kubernetes rotation contract is incomplete")
    value = _json_output(
        runner.run(
            [
                *kubectl_prefix,
                "get",
                "pods",
                "-l",
                f"app.kubernetes.io/name=email-platform,app.kubernetes.io/component={deployment}",
                "-o",
                "json",
            ],
            capture_output=True,
        ),
        "Kubernetes Pod inventory",
    )
    items = value.get("items") if isinstance(value, dict) else None
    if not isinstance(items, list) or len(items) != expected_count:
        raise RotationRuntimeError("Kubernetes ready Pod count is invalid")
    snapshots = [
        _kubernetes_pod_snapshot(
            runner,
            kubectl_prefix,
            pod=item,
            deployment=deployment,
            deployment_uid=deployment_uid,
            target_revision=target_revision,
            target_replicaset_uid=target_replicaset_uid,
        )
        for item in items
    ]
    if len({item.evidence["instance_id"] for item in snapshots}) != expected_count:
        raise RotationRuntimeError("Kubernetes Pod identity is ambiguous")
    return sorted(snapshots, key=lambda item: item.evidence["instance_id"])


def classify_kubernetes_reconcile_inventory(
    runner: Runner,
    kubectl_prefix: Sequence[str],
    *,
    deployment: str,
    expected_count: int,
) -> str | None:
    """Classify normal rolling intermediates without accepting them as ready."""

    deployment = _name(deployment, "Kubernetes Deployment")
    if type(expected_count) is not int or not 1 <= expected_count <= 16:
        raise RotationRuntimeError("Kubernetes rotation contract is incomplete")
    value = _json_output(
        runner.run(
            [
                *kubectl_prefix,
                "get",
                "pods",
                "-l",
                f"app.kubernetes.io/name=email-platform,app.kubernetes.io/component={deployment}",
                "-o",
                "json",
            ],
            capture_output=True,
        ),
        "Kubernetes reconciliation Pod inventory",
    )
    items = value.get("items") if isinstance(value, dict) else None
    if not isinstance(items, list) or len(items) > 16:
        raise RotationRuntimeError("Kubernetes reconciliation inventory is invalid")
    controllers: set[str] = set()
    terminating = False
    unready = False
    for pod in items:
        metadata = pod.get("metadata") if isinstance(pod, dict) else None
        owners = metadata.get("ownerReferences") if isinstance(metadata, dict) else None
        controlled = [
            owner
            for owner in owners
            if (
                isinstance(owner, dict)
                and owner.get("apiVersion") == "apps/v1"
                and owner.get("kind") == "ReplicaSet"
                and owner.get("controller") is True
                and isinstance(owner.get("uid"), str)
                and _KUBERNETES_UID.fullmatch(owner["uid"]) is not None
            )
        ] if isinstance(owners, list) else []
        if len(controlled) != 1:
            return "owner_chain_invalid"
        controllers.add(controlled[0]["uid"])
        terminating = terminating or metadata.get("deletionTimestamp") is not None
        unready = unready or not _pod_ready(pod)
    if len(controllers) > 1:
        return "mixed_replicasets"
    if terminating:
        return "pod_terminating"
    if unready:
        return "pod_unready"
    if len(items) != expected_count:
        return "replica_count_mismatch"
    return None


def get_kubernetes_namespace_uid(
    runner: Runner, kubectl_prefix: Sequence[str], *, namespace: str
) -> str:
    value = _json_output(
        runner.run(
            [*kubectl_prefix, "get", "namespace", _name(namespace, "Kubernetes Namespace"), "-o", "json"],
            capture_output=True,
        ),
        "Kubernetes Namespace identity",
    )
    metadata = value.get("metadata") if isinstance(value, dict) else None
    uid = metadata.get("uid") if isinstance(metadata, dict) else None
    if not isinstance(uid, str) or _KUBERNETES_UID.fullmatch(uid) is None:
        raise RotationRuntimeError("Kubernetes Namespace identity is invalid")
    return uid


def get_kubernetes_deployment_snapshot(
    runner: Runner,
    kubectl_prefix: Sequence[str],
    *,
    deployment: str,
    expected_count: int,
    require_ready: bool = True,
) -> KubernetesDeploymentSnapshot:
    deployment = _name(deployment, "Kubernetes Deployment")
    value = _json_output(
        runner.run(
            [*kubectl_prefix, "get", "deployment", deployment, "-o", "json"],
            capture_output=True,
        ),
        "Kubernetes Deployment status",
    )
    metadata = value.get("metadata") if isinstance(value, dict) else None
    spec = value.get("spec") if isinstance(value, dict) else None
    status = value.get("status") if isinstance(value, dict) else None
    if not all(isinstance(item, dict) for item in (metadata, spec, status)):
        raise RotationRuntimeError("Kubernetes Deployment status is invalid")
    uid = metadata.get("uid")
    generation = metadata.get("generation")
    annotations = metadata.get("annotations")
    revision_value = annotations.get("deployment.kubernetes.io/revision") if isinstance(annotations, dict) else None
    template = spec.get("template")
    template_metadata = template.get("metadata") if isinstance(template, dict) else None
    template_annotations = template_metadata.get("annotations") if isinstance(template_metadata, dict) else None
    restarted_at = template_annotations.get("kubectl.kubernetes.io/restartedAt") if isinstance(template_annotations, dict) else None
    pod_spec = template.get("spec") if isinstance(template, dict) else None
    containers = pod_spec.get("containers") if isinstance(pod_spec, dict) else None
    volumes = pod_spec.get("volumes") if isinstance(pod_spec, dict) else None
    primary = [
        item
        for item in containers
        if isinstance(item, dict) and item.get("name") == deployment
    ] if isinstance(containers, list) else []
    tls_volumes = [
        item
        for item in volumes
        if isinstance(item, dict) and item.get("name") == "internal-tls"
    ] if isinstance(volumes, list) else []
    primary_mounts = primary[0].get("volumeMounts") if len(primary) == 1 else None
    required_mounts = {
        (item.get("mountPath"), item.get("subPath"), item.get("readOnly"))
        for item in primary_mounts
        if isinstance(item, dict) and item.get("name") == "internal-tls"
    } if isinstance(primary_mounts, list) else set()
    tls_secret = tls_volumes[0].get("secret") if len(tls_volumes) == 1 else None
    image_identity = primary[0].get("image") if len(primary) == 1 else None
    tls_secret_name = tls_secret.get("secretName") if isinstance(tls_secret, dict) else None
    try:
        revision = int(revision_value)
    except (TypeError, ValueError):
        raise RotationRuntimeError("Kubernetes Deployment status is invalid") from None
    if (
        not isinstance(uid, str)
        or _KUBERNETES_UID.fullmatch(uid) is None
        or type(generation) is not int
        or generation < 1
        or revision < 1
        or (restarted_at is not None and not isinstance(restarted_at, str))
        or type(spec.get("paused", False)) is not bool
        or type(status.get("observedGeneration")) is not int
        or status.get("observedGeneration") > generation
        or spec.get("replicas") != expected_count
        or not isinstance(image_identity, str)
        or not image_identity
        or not isinstance(tls_secret_name, str)
        or _DNS_LABEL.fullmatch(tls_secret_name) is None
        or required_mounts != {
            ("/run/secrets/internal-tls/tls.crt", "tls.crt", True),
            ("/run/secrets/internal-tls/tls.key", "tls.key", True),
        }
        or (
            require_ready
            and (
                status.get("observedGeneration") != generation
                or spec.get("replicas") != expected_count
                or status.get("replicas") != expected_count
                or status.get("updatedReplicas") != expected_count
                or status.get("readyReplicas") != expected_count
                or status.get("availableReplicas") != expected_count
                or status.get("unavailableReplicas", 0) != 0
            )
        )
    ):
        raise RotationRuntimeError("Kubernetes Deployment generation is unconfirmed")
    return KubernetesDeploymentSnapshot(
        uid=uid,
        generation=generation,
        observed_generation=status["observedGeneration"],
        revision=revision,
        restarted_at=(normalize_started_at(restarted_at) if restarted_at is not None else None),
        paused=spec.get("paused", False),
        image_identity=image_identity,
        tls_secret_name=tls_secret_name,
    )


def assert_kubernetes_deployment_ready(
    runner: Runner,
    kubectl_prefix: Sequence[str],
    *,
    deployment: str,
    expected_count: int,
) -> None:
    get_kubernetes_deployment_snapshot(
        runner, kubectl_prefix, deployment=deployment, expected_count=expected_count
    )


def get_kubernetes_named_pod_snapshot(
    runner: Runner,
    kubectl_prefix: Sequence[str],
    *,
    pod: str,
    deployment: str,
    deployment_uid: str,
    target_revision: int,
    target_replicaset_uid: str,
) -> RuntimeInstanceSnapshot:
    pod_name = _name(pod, "Kubernetes Pod")
    value = _json_output(
        runner.run(
            [*kubectl_prefix, "get", "pod", pod_name, "-o", "json"],
            capture_output=True,
        ),
        "Kubernetes Pod identity",
    )
    return _kubernetes_pod_snapshot(
        runner,
        kubectl_prefix,
        pod=value,
        deployment=_name(deployment, "Kubernetes Deployment"),
        deployment_uid=deployment_uid,
        target_revision=target_revision,
        target_replicaset_uid=target_replicaset_uid,
    )


def restart_kubernetes_deployment(
    runner: Runner,
    kubectl_prefix: Sequence[str],
    *,
    deployment: str,
) -> None:
    deployment = _name(deployment, "Kubernetes Deployment")
    runner.run([*kubectl_prefix, "rollout", "restart", f"deployment/{deployment}"])


def wait_kubernetes_rollout_revision(
    runner: Runner,
    kubectl_prefix: Sequence[str],
    *,
    deployment: str,
    revision: int,
) -> None:
    deployment = _name(deployment, "Kubernetes Deployment")
    if type(revision) is not int or revision < 1:
        raise RotationRuntimeError("Kubernetes rollout revision is invalid")
    runner.run(
        [
            *kubectl_prefix,
            "rollout",
            "status",
            f"deployment/{deployment}",
            f"--revision={revision}",
            "--timeout=10m",
        ]
    )


def assert_kubernetes_uids_absent(
    runner: Runner,
    kubectl_prefix: Sequence[str],
    *,
    old_uids: Sequence[str],
) -> None:
    if not old_uids or any(
        not isinstance(value, str) or _KUBERNETES_UID.fullmatch(value) is None
        for value in old_uids
    ):
        raise RotationRuntimeError("Kubernetes old Pod identity is invalid")
    value = _json_output(
        runner.run([*kubectl_prefix, "get", "pods", "-o", "json"], capture_output=True),
        "Kubernetes Pod inventory",
    )
    items = value.get("items") if isinstance(value, dict) else None
    if not isinstance(items, list):
        raise RotationRuntimeError("Kubernetes Pod inventory is invalid")
    remaining = {
        item.get("metadata", {}).get("uid")
        for item in items
        if isinstance(item, dict) and isinstance(item.get("metadata"), dict)
    }
    if remaining.intersection(old_uids):
        raise RotationRuntimeError("old Kubernetes Pod identity is still present")


def pause_kubernetes_deployment(
    runner: Runner,
    kubectl_prefix: Sequence[str],
    *,
    deployment: str,
) -> None:
    runner.run(
        [
            *kubectl_prefix,
            "rollout",
            "pause",
            f"deployment/{_name(deployment, 'Kubernetes Deployment')}",
        ]
    )


def assert_generation_replaced(
    before: Sequence[RuntimeInstanceSnapshot],
    after: Sequence[RuntimeInstanceSnapshot],
    *,
    expected_count: int,
) -> None:
    if len(before) != expected_count or len(after) != expected_count:
        raise RotationRuntimeError("runtime replica count changed during rotation")
    before_instances = {item.evidence["instance_id"] for item in before}
    after_instances = {item.evidence["instance_id"] for item in after}
    before_containers = {item.evidence["container_id"] for item in before}
    after_containers = {item.evidence["container_id"] for item in after}
    if before_instances & after_instances or before_containers & after_containers:
        raise RotationRuntimeError("runtime generation was not fully replaced")


def compose_probe_command(
    compose_prefix: Sequence[str],
    *,
    observer: str,
    url: str,
    ca_file: str,
    connect_host: str | None = None,
) -> ProbeInvocation:
    command = (
        *compose_prefix,
        "exec",
        "-T",
        _name(observer, "Compose observer"),
        "python",
        "-c",
        TLS_STDIN_HTTP_PROBE_PROGRAM,
    )
    input_text = json.dumps(
        {
            "url": url,
            "ca_file": ca_file,
            "max_body_bytes": 1024 * 1024,
            "content_type": None,
            "require_nonempty": False,
            "expected_json": None,
            "connect_host": connect_host,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(input_text.encode("utf-8")) > _MAX_PROBE_INPUT_BYTES:
        raise RotationRuntimeError("TLS probe input is invalid")
    return ProbeInvocation(command=command, input_text=input_text)


def docker_probe_command(
    container: str,
    *,
    url: str,
    ca_file: str,
    connect_host: str,
) -> ProbeInvocation:
    """Build a stdin-only TLS probe bound to one exact Compose container ID."""

    if _COMPOSE_ID.fullmatch(container) is None:
        raise RotationRuntimeError("Compose probe executor identity is invalid")
    command = (
        "docker",
        "exec",
        "-i",
        container,
        "python",
        "-c",
        TLS_STDIN_HTTP_PROBE_PROGRAM,
    )
    input_text = json.dumps(
        {
            "url": url,
            "ca_file": ca_file,
            "max_body_bytes": 1024 * 1024,
            "content_type": None,
            "require_nonempty": False,
            "expected_json": None,
            "connect_host": connect_host,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(input_text.encode("utf-8")) > _MAX_PROBE_INPUT_BYTES:
        raise RotationRuntimeError("TLS probe input is invalid")
    return ProbeInvocation(command=command, input_text=input_text)


def kubernetes_probe_command(
    kubectl_prefix: Sequence[str],
    *,
    observer: str,
    container: str,
    url: str,
    ca_file: str,
    connect_host: str | None = None,
) -> ProbeInvocation:
    command = (
        *kubectl_prefix,
        "exec",
        "-i",
        _name(observer, "Kubernetes observer Pod"),
        "-c",
        _name(container, "Kubernetes observer container"),
        "--",
        "python",
        "-c",
        TLS_STDIN_HTTP_PROBE_PROGRAM,
    )
    input_text = json.dumps(
        {
            "url": url,
            "ca_file": ca_file,
            "max_body_bytes": 1024 * 1024,
            "content_type": None,
            "require_nonempty": False,
            "expected_json": None,
            "connect_host": connect_host,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(input_text.encode("utf-8")) > _MAX_PROBE_INPUT_BYTES:
        raise RotationRuntimeError("TLS probe input is invalid")
    return ProbeInvocation(command=command, input_text=input_text)


def collect_peer_observation(
    runner: Runner,
    command: ProbeInvocation,
    *,
    phase: str,
    observer: str,
    instance_id: str | None,
    attempt: int,
    expected_sha256: str,
    observed_at: str,
) -> dict[str, object]:
    try:
        verified = parse_tls_probe_observation(
            runner.run(
                command.command,
                capture_output=True,
                input_text=command.input_text,
            ),
            expected_sha256=expected_sha256,
        )
        timestamp = normalize_started_at(observed_at)
    except (TypeError, ValueError) as error:
        raise RotationRuntimeError("live TLS peer observation failed") from error
    return {
        "phase": phase,
        "observer": observer,
        "instance_id": instance_id,
        "attempt": attempt,
        **verified,
        "observed_at": timestamp,
    }
