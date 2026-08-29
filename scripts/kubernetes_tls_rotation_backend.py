"""Closed Kubernetes backend for the controlled TLS leaf-rotation coordinator."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Mapping

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from scripts.backup_output_policy import REPOSITORY_ROOT
from scripts.external_json import StableFileError, parse_unique_json_bytes, read_stable_bytes
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
from scripts.tls_rotation_evidence import rotation_plan_digest
from scripts.tls_runtime_identity import parse_tls_probe_observation
from scripts.tls_rotation_runtime import (
    ActionReconciliation,
    KubernetesDeploymentSnapshot,
    RotationRuntimeError,
    Runner,
    RuntimeInstanceSnapshot,
    assert_generation_replaced,
    assert_kubernetes_uids_absent,
    classify_kubernetes_reconcile_inventory,
    collect_kubernetes_generation,
    collect_peer_observation,
    get_kubernetes_deployment_snapshot,
    get_kubernetes_named_pod_snapshot,
    get_kubernetes_namespace_uid,
    kubernetes_probe_command,
    pause_kubernetes_deployment,
    restart_kubernetes_deployment,
    wait_kubernetes_rollout_revision,
)
from scripts.tls_rotation_runner import SanitizedSubprocessRunner


PROFILE_KIND = "kubernetes_tls_rotation_backend"
PROFILE_SCHEMA_VERSION = 2
MAX_PROFILE_BYTES = 64 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_CONTEXT = re.compile(r"^[A-Za-z0-9._:/@-]{1,128}$")
_OCI_IMAGE = re.compile(r"^[^\s:@]+(?:/[^\s:@]+)+@sha256:[0-9a-f]{64}$")
_RUNTIME_IMAGE = re.compile(r"^(?:(?:docker-pullable|containerd)://)?[^\s@]+@sha256:[0-9a-f]{64}$")
_CA_FILE = "/run/secrets/internal-tls/ca.crt"
_PROFILE_FIELDS = {
    "schema_version",
    "profile_kind",
    "live_capture_sha256",
    "target_environment",
    "service",
    "expected_instance_count",
    "required_observers",
    "kubeconfig_path",
    "kubeconfig_sha256",
    "context",
    "namespace",
    "namespace_uid",
    "deployment_uid",
    "expected_image",
    "direct_probe",
    "route_observers",
    "blocked_observers",
}
_ROUTE_FIELDS = {
    "logical_name",
    "namespace",
    "namespace_uid",
    "deployment",
    "deployment_uid",
    "pod",
    "pod_uid",
    "replicaset_uid",
    "revision",
    "container",
    "expected_image",
    "url",
    "ca_file",
}


@dataclass(frozen=True)
class _TargetContract:
    url: str
    tls_secret_name: str
    required_observers: tuple[str, ...]


_TARGETS = {
    "api": _TargetContract(
        "https://api.email-platform.svc:8443/readyz",
        "platform-api-internal-tls",
        ("edge", "prometheus"),
    ),
    "web": _TargetContract(
        "https://web.email-platform.svc:8443/",
        "platform-web-internal-tls",
        ("edge",),
    ),
    "worker-mail": _TargetContract(
        "https://worker-mail.email-platform.svc:9101/metrics",
        "platform-worker-mail-internal-tls",
        ("prometheus",),
    ),
    "worker-sub2": _TargetContract(
        "https://worker-sub2.email-platform.svc:9102/metrics",
        "platform-worker-sub2-internal-tls",
        ("prometheus",),
    ),
}


class KubernetesRotationBackendError(RotationRuntimeError):
    """The reviewed Kubernetes runtime profile cannot be executed safely."""


@dataclass(frozen=True)
class KubernetesRouteObserver:
    logical_name: str
    namespace: str
    namespace_uid: str
    deployment: str
    deployment_uid: str
    pod: str
    pod_uid: str
    replicaset_uid: str
    revision: int
    container: str
    expected_image: str
    url: str
    ca_file: str


@dataclass(frozen=True)
class KubernetesRotationProfile:
    live_capture_sha256: str
    target_environment: str
    service: str
    expected_instance_count: int
    required_observers: tuple[str, ...]
    kubeconfig_path: Path
    kubeconfig_sha256: str
    context: str
    namespace: str
    namespace_uid: str
    deployment_uid: str
    expected_image: str
    direct_observer: KubernetesRouteObserver
    route_observers: tuple[KubernetesRouteObserver, ...]
    blocked_observers: tuple[str, ...]
    profile_sha256: str


def _canonical_digest(value: Mapping[str, object]) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _closed_mapping(value: object, fields: set[str], context: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise KubernetesRotationBackendError(f"invalid {context}")
    return value


def _external_path(path: Path) -> Path:
    if not path.is_absolute():
        raise KubernetesRotationBackendError("runtime path is invalid")
    try:
        path.resolve(strict=False).relative_to(REPOSITORY_ROOT.resolve())
    except ValueError:
        return path
    raise KubernetesRotationBackendError("runtime path is invalid")


def _valid_name(value: object) -> bool:
    return isinstance(value, str) and _NAME.fullmatch(value) is not None


def _valid_uid(value: object) -> bool:
    return isinstance(value, str) and _UID.fullmatch(value) is not None


def _valid_image(value: object) -> bool:
    return isinstance(value, str) and _OCI_IMAGE.fullmatch(value) is not None


def _valid_runtime_image(value: object) -> bool:
    return isinstance(value, str) and _RUNTIME_IMAGE.fullmatch(value) is not None


def load_kubernetes_rotation_profile(path: Path) -> KubernetesRotationProfile:
    try:
        raw = read_stable_bytes(_external_path(path), max_bytes=MAX_PROFILE_BYTES)
        value = parse_unique_json_bytes(raw)
    except (StableFileError, UnicodeError, json.JSONDecodeError, ValueError):
        raise KubernetesRotationBackendError("runtime profile cannot be read") from None
    return validate_kubernetes_rotation_profile(value)


def validate_kubernetes_rotation_profile(value: object) -> KubernetesRotationProfile:
    profile = _closed_mapping(value, _PROFILE_FIELDS, "Kubernetes rotation profile")
    service = profile["service"]
    contract = _TARGETS.get(service) if isinstance(service, str) else None
    required = profile["required_observers"]
    blocked = profile["blocked_observers"]
    routes = profile["route_observers"]
    direct = _closed_mapping(profile["direct_probe"], _ROUTE_FIELDS, "Kubernetes direct observer profile")
    try:
        kubeconfig_path = _external_path(Path(profile["kubeconfig_path"]))
    except (TypeError, ValueError):
        raise KubernetesRotationBackendError("Kubernetes rotation profile identity is invalid") from None
    if (
        profile["schema_version"] != PROFILE_SCHEMA_VERSION
        or profile["profile_kind"] != PROFILE_KIND
        or not isinstance(profile["live_capture_sha256"], str)
        or _SHA256.fullmatch(profile["live_capture_sha256"]) is None
        or contract is None
        or profile["expected_instance_count"] != 2
        or required != list(contract.required_observers)
        or not isinstance(blocked, list)
        or blocked != sorted(set(blocked))
        or not isinstance(routes, list)
        or not isinstance(profile["target_environment"], str)
        or not profile["target_environment"]
        or not _valid_name(profile["namespace"])
        or not _valid_uid(profile["namespace_uid"])
        or not _valid_uid(profile["deployment_uid"])
        or not _valid_image(profile["expected_image"])
        or not isinstance(profile["kubeconfig_sha256"], str)
        or _SHA256.fullmatch(profile["kubeconfig_sha256"]) is None
        or not isinstance(profile["context"], str)
        or _CONTEXT.fullmatch(profile["context"]) is None
    ):
        raise KubernetesRotationBackendError("Kubernetes rotation profile identity is invalid")
    if (
        direct["logical_name"] != "direct-instance"
        or not all(_valid_name(direct[field]) for field in ("namespace", "deployment", "pod", "container"))
        or not all(_valid_uid(direct[field]) for field in ("namespace_uid", "deployment_uid", "pod_uid", "replicaset_uid"))
        or type(direct["revision"]) is not int
        or direct["revision"] < 1
        or not _valid_runtime_image(direct["expected_image"])
        or direct["url"] != contract.url
        or direct["ca_file"] != _CA_FILE
    ):
        raise KubernetesRotationBackendError("Kubernetes direct observer profile is invalid")
    parsed_routes: list[KubernetesRouteObserver] = []
    for item in routes:
        route = _closed_mapping(item, _ROUTE_FIELDS, "Kubernetes route observer profile")
        if (
            route["logical_name"] not in required
            or route["deployment"] != route["logical_name"]
            or route["container"] != route["deployment"]
            or not all(_valid_name(route[field]) for field in ("namespace", "deployment", "pod", "container"))
            or not all(_valid_uid(route[field]) for field in ("namespace_uid", "deployment_uid", "pod_uid", "replicaset_uid"))
            or type(route["revision"]) is not int
            or route["revision"] < 1
            or not _valid_runtime_image(route["expected_image"])
            or route["url"] != contract.url
            or route["ca_file"] != _CA_FILE
        ):
            raise KubernetesRotationBackendError("Kubernetes route observer profile is invalid")
        parsed_routes.append(KubernetesRouteObserver(**route))
    route_names = [item.logical_name for item in parsed_routes]
    if (
        route_names != sorted(set(route_names))
        or sorted(route_names + list(blocked)) != list(required)
    ):
        raise KubernetesRotationBackendError("Kubernetes observer inventory is incomplete")
    return KubernetesRotationProfile(
        live_capture_sha256=str(profile["live_capture_sha256"]),
        target_environment=str(profile["target_environment"]),
        service=service,
        expected_instance_count=2,
        required_observers=tuple(required),
        kubeconfig_path=kubeconfig_path,
        kubeconfig_sha256=str(profile["kubeconfig_sha256"]),
        context=str(profile["context"]),
        namespace=str(profile["namespace"]),
        namespace_uid=str(profile["namespace_uid"]),
        deployment_uid=str(profile["deployment_uid"]),
        expected_image=str(profile["expected_image"]),
        direct_observer=KubernetesRouteObserver(**direct),
        route_observers=tuple(parsed_routes),
        blocked_observers=tuple(blocked),
        profile_sha256=_canonical_digest(profile),
    )


def kubectl_prefix(
    kubeconfig_path: Path,
    *,
    context: str,
    namespace: str | None = None,
) -> tuple[str, ...]:
    prefix = (
        "kubectl",
        "--kubeconfig",
        str(kubeconfig_path),
        "--context",
        context,
        "--request-timeout=30s",
    )
    return prefix if namespace is None else (*prefix, "--namespace", namespace)


def _certificate_identity(encoded: str) -> tuple[str, str]:
    try:
        raw = base64.b64decode(encoded.strip(), validate=True)
        try:
            certificate = x509.load_pem_x509_certificate(raw)
        except ValueError:
            certificate = x509.load_der_x509_certificate(raw)
    except (ValueError, binascii.Error):
        raise KubernetesRotationBackendError("Kubernetes TLS certificate is invalid") from None
    public_key = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return certificate.fingerprint(hashes.SHA256()).hex(), hashlib.sha256(public_key).hexdigest()


class KubernetesRotationBackend:
    runtime_kind = "kubernetes"

    def __init__(self, profile: KubernetesRotationProfile, runner: Runner) -> None:
        self.profile = profile
        self.runner = runner
        self._materialized: MaterializedPrivateSecret | None = None
        self._closed = False
        self._routes = {item.logical_name: item for item in profile.route_observers}
        self._deployment: KubernetesDeploymentSnapshot | None = None
        self._old_uids: tuple[str, ...] = ()
        self._before_replicaset_uid: str | None = None
        self._target_replicaset_uid: str | None = None
        self._acted = False

    def _kubectl_prefix(self, namespace: str | None = None) -> tuple[str, ...]:
        if self._closed or self._materialized is None:
            raise KubernetesRotationBackendError(
                "Kubernetes kubeconfig materialization is unavailable"
            )
        try:
            self._materialized.verify()
        except PrivateSecretMaterializationError:
            raise KubernetesRotationBackendError(
                "Kubernetes kubeconfig materialization is invalid"
            ) from None
        return kubectl_prefix(
            self._materialized.path,
            context=self.profile.context,
            namespace=namespace,
        )

    @property
    def _base_prefix(self) -> tuple[str, ...]:
        return self._kubectl_prefix()

    @property
    def _prefix(self) -> tuple[str, ...]:
        return self._kubectl_prefix(self.profile.namespace)

    def _assert_namespace(self, namespace: str, expected_uid: str) -> None:
        if get_kubernetes_namespace_uid(self.runner, self._base_prefix, namespace=namespace) != expected_uid:
            raise KubernetesRotationBackendError("Kubernetes Namespace identity has drifted")

    def _assert_deployment_binding(self, value: KubernetesDeploymentSnapshot) -> None:
        contract = _TARGETS[self.profile.service]
        if (
            value.uid != self.profile.deployment_uid
            or value.image_identity != self.profile.expected_image
            or value.tls_secret_name != contract.tls_secret_name
            or value.paused
        ):
            raise KubernetesRotationBackendError("Kubernetes Deployment identity has drifted")

    def _route_snapshot(self, route: KubernetesRouteObserver) -> RuntimeInstanceSnapshot:
        self._assert_namespace(route.namespace, route.namespace_uid)
        snapshot = get_kubernetes_named_pod_snapshot(
            self.runner,
            self._kubectl_prefix(route.namespace),
            pod=route.pod,
            deployment=route.deployment,
            deployment_uid=route.deployment_uid,
            target_revision=route.revision,
            target_replicaset_uid=route.replicaset_uid,
        )
        if (
            snapshot.evidence["instance_id"] != route.pod_uid
            or snapshot.image_identity != route.expected_image
        ):
            raise KubernetesRotationBackendError("Kubernetes observer Pod identity has drifted")
        return snapshot

    def _preflight_observer_probe(
        self, observer: KubernetesRouteObserver, *, expected_sha256: str
    ) -> None:
        before = self._route_snapshot(observer)
        command = kubernetes_probe_command(
            self._kubectl_prefix(observer.namespace),
            observer=observer.pod,
            container=observer.container,
            url=observer.url,
            ca_file=observer.ca_file,
        )
        try:
            parse_tls_probe_observation(
                self.runner.run(
                    command.command,
                    capture_output=True,
                    input_text=command.input_text,
                ),
                expected_sha256=expected_sha256,
            )
        except (TypeError, ValueError):
            raise KubernetesRotationBackendError("reviewed observer probe runtime is unavailable") from None
        if self._route_snapshot(observer) != before:
            raise KubernetesRotationBackendError("Kubernetes observer Pod identity has drifted")

    def preflight(self, projection: Mapping[str, object]) -> None:
        expected = {
            "target_environment": self.profile.target_environment,
            "runtime_kind": "kubernetes",
            "service": self.profile.service,
            "expected_instance_count": self.profile.expected_instance_count,
            "required_observers": list(self.profile.required_observers),
            "runtime_profile_sha256": self.profile.profile_sha256,
            "old_leaf_sha256": projection["old_leaf_sha256"],
            "new_leaf_sha256": projection["new_leaf_sha256"],
            "old_spki_sha256": projection["old_spki_sha256"],
            "new_spki_sha256": projection["new_spki_sha256"],
        }
        if rotation_plan_digest(expected) != rotation_plan_digest(projection):
            raise KubernetesRotationBackendError("runtime profile does not match rotation plan")
        if self.profile.blocked_observers:
            raise KubernetesRotationBackendError("required real observer probe runtime is unavailable")
        try:
            kubeconfig = read_private_secret_bytes(
                self.profile.kubeconfig_path,
                max_bytes=1024 * 1024,
                require_read_only=True,
            )
        except OSError:
            raise KubernetesRotationBackendError("Kubernetes kubeconfig cannot be read") from None
        try:
            kubeconfig_sha256 = validate_self_contained_kubeconfig(
                kubeconfig,
                expected_context=self.profile.context,
                expected_namespace=self.profile.namespace,
            )
        except KubernetesKubeconfigIntakeError:
            raise KubernetesRotationBackendError(
                "Kubernetes kubeconfig intake is invalid"
            ) from None
        if not hmac.compare_digest(kubeconfig_sha256, self.profile.kubeconfig_sha256):
            raise KubernetesRotationBackendError("Kubernetes kubeconfig identity has drifted")
        if self._closed or self._materialized is not None:
            raise KubernetesRotationBackendError(
                "Kubernetes kubeconfig materialization is unavailable"
            )
        try:
            self._materialized = materialize_private_secret_bytes(
                kubeconfig,
                kubeconfig_sha256,
            )
        except PrivateSecretMaterializationError:
            raise KubernetesRotationBackendError(
                "Kubernetes kubeconfig materialization failed"
            ) from None
        self._assert_namespace(self.profile.namespace, self.profile.namespace_uid)
        deployment = get_kubernetes_deployment_snapshot(
            self.runner,
            self._prefix,
            deployment=self.profile.service,
            expected_count=self.profile.expected_instance_count,
        )
        self._assert_deployment_binding(deployment)
        contract = _TARGETS[self.profile.service]
        certificate = self.runner.run(
            [
                *self._prefix,
                "get",
                "secret",
                contract.tls_secret_name,
                "-o",
                "jsonpath={.data.tls\\.crt}",
            ],
            capture_output=True,
        )
        leaf, spki = _certificate_identity(certificate)
        if not hmac.compare_digest(leaf, str(projection["new_leaf_sha256"])) or not hmac.compare_digest(
            spki, str(projection["new_spki_sha256"])
        ):
            raise KubernetesRotationBackendError("reviewed replacement certificate identity has drifted")
        self._preflight_observer_probe(
            self.profile.direct_observer,
            expected_sha256=str(projection["old_leaf_sha256"]),
        )
        for route in self.profile.route_observers:
            self._preflight_observer_probe(
                route,
                expected_sha256=str(projection["old_leaf_sha256"]),
            )
        self._deployment = deployment

    def snapshot(self) -> list[RuntimeInstanceSnapshot]:
        if self._deployment is None:
            raise KubernetesRotationBackendError("Kubernetes preflight is incomplete")
        self._assert_namespace(self.profile.namespace, self.profile.namespace_uid)
        deployment = get_kubernetes_deployment_snapshot(
            self.runner,
            self._prefix,
            deployment=self.profile.service,
            expected_count=self.profile.expected_instance_count,
        )
        self._assert_deployment_binding(deployment)
        if self._acted:
            if deployment != self._deployment:
                raise KubernetesRotationBackendError("Kubernetes Deployment generation has drifted")
            revision = deployment.revision
            target_replicaset_uid = self._target_replicaset_uid
        else:
            if deployment != self._deployment:
                raise KubernetesRotationBackendError("Kubernetes Deployment generation has drifted")
            revision = deployment.revision
            target_replicaset_uid = self._before_replicaset_uid
        snapshots = collect_kubernetes_generation(
            self.runner,
            self._prefix,
            deployment=self.profile.service,
            expected_count=self.profile.expected_instance_count,
            deployment_uid=self.profile.deployment_uid,
            target_revision=revision,
            target_replicaset_uid=target_replicaset_uid,
        )
        controllers = {item.controller_id for item in snapshots}
        if len(controllers) != 1 or None in controllers:
            raise KubernetesRotationBackendError("Kubernetes ReplicaSet identity is ambiguous")
        controller = next(iter(controllers))
        if self._acted:
            if self._target_replicaset_uid is None:
                self._target_replicaset_uid = controller
            elif controller != self._target_replicaset_uid:
                raise KubernetesRotationBackendError("Kubernetes ReplicaSet identity has drifted")
            assert_kubernetes_uids_absent(
                self.runner,
                self._prefix,
                old_uids=self._old_uids,
            )
        else:
            if self._before_replicaset_uid is None:
                self._before_replicaset_uid = controller
            elif controller != self._before_replicaset_uid:
                raise KubernetesRotationBackendError("Kubernetes ReplicaSet identity has drifted")
            self._old_uids = tuple(item.evidence["instance_id"] for item in snapshots)
        return snapshots

    def _exact_target_snapshot(
        self,
        instance: RuntimeInstanceSnapshot,
        deployment: KubernetesDeploymentSnapshot | None = None,
    ) -> RuntimeInstanceSnapshot:
        deployment = self._deployment if deployment is None else deployment
        if deployment is None or not instance.runtime_name or not instance.controller_id:
            raise KubernetesRotationBackendError("Kubernetes target Pod identity is incomplete")
        current = get_kubernetes_named_pod_snapshot(
            self.runner,
            self._prefix,
            pod=instance.runtime_name,
            deployment=self.profile.service,
            deployment_uid=self.profile.deployment_uid,
            target_revision=deployment.revision,
            target_replicaset_uid=instance.controller_id,
        )
        if current != instance:
            raise KubernetesRotationBackendError("Kubernetes target Pod identity has drifted")
        return current

    def _probe_instance_for_deployment(
        self, instance, deployment, *, expected_sha256, phase, observed_at
    ):
        self._exact_target_snapshot(instance, deployment)
        direct_before = self._route_snapshot(self.profile.direct_observer)
        command = kubernetes_probe_command(
            self._kubectl_prefix(self.profile.direct_observer.namespace),
            observer=self.profile.direct_observer.pod,
            container=self.profile.direct_observer.container,
            url=_TARGETS[self.profile.service].url,
            ca_file=self.profile.direct_observer.ca_file,
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
        if self._route_snapshot(self.profile.direct_observer) != direct_before:
            raise KubernetesRotationBackendError("Kubernetes direct observer Pod identity has drifted")
        self._exact_target_snapshot(instance, deployment)
        return observation

    def probe_instance(self, instance, *, expected_sha256, phase, observed_at):
        if self._deployment is None:
            raise KubernetesRotationBackendError("Kubernetes preflight is incomplete")
        return self._probe_instance_for_deployment(
            instance,
            self._deployment,
            expected_sha256=expected_sha256,
            phase=phase,
            observed_at=observed_at,
        )

    def act(self) -> None:
        if self._deployment is None:
            raise KubernetesRotationBackendError("Kubernetes preflight is incomplete")
        before = self._deployment
        restart_kubernetes_deployment(self.runner, self._prefix, deployment=self.profile.service)
        discovered = get_kubernetes_deployment_snapshot(
            self.runner,
            self._prefix,
            deployment=self.profile.service,
            expected_count=self.profile.expected_instance_count,
            require_ready=False,
        )
        self._assert_deployment_binding(discovered)
        if (
            discovered.generation <= before.generation
            or discovered.revision <= before.revision
            or discovered.restarted_at is None
            or discovered.restarted_at == before.restarted_at
        ):
            raise KubernetesRotationBackendError("Kubernetes rollout revision was not discovered")
        wait_kubernetes_rollout_revision(
            self.runner,
            self._prefix,
            deployment=self.profile.service,
            revision=discovered.revision,
        )
        ready = get_kubernetes_deployment_snapshot(
            self.runner,
            self._prefix,
            deployment=self.profile.service,
            expected_count=self.profile.expected_instance_count,
        )
        self._assert_deployment_binding(ready)
        if (
            ready.uid != discovered.uid
            or ready.generation != discovered.generation
            or ready.revision != discovered.revision
            or ready.restarted_at != discovered.restarted_at
            or ready.paused != discovered.paused
            or ready.image_identity != discovered.image_identity
            or ready.tls_secret_name != discovered.tls_secret_name
        ):
            raise KubernetesRotationBackendError("Kubernetes rollout generation is unconfirmed")
        self._deployment = ready
        self._target_replicaset_uid = None
        self._acted = True

    def _reconciliation_generation(
        self,
        deployment: KubernetesDeploymentSnapshot,
        *,
        replicaset_uid: str | None,
    ) -> tuple[list[RuntimeInstanceSnapshot], str]:
        snapshots = collect_kubernetes_generation(
            self.runner,
            self._prefix,
            deployment=self.profile.service,
            expected_count=self.profile.expected_instance_count,
            deployment_uid=self.profile.deployment_uid,
            target_revision=deployment.revision,
            target_replicaset_uid=replicaset_uid,
        )
        controllers = {item.controller_id for item in snapshots}
        if len(controllers) != 1 or None in controllers:
            raise KubernetesRotationBackendError("Kubernetes ReplicaSet identity is ambiguous")
        return snapshots, str(next(iter(controllers)))

    def reconcile_action(
        self,
        before,
        *,
        old_sha256,
        new_sha256,
        observed_at,
    ) -> ActionReconciliation:
        """Read-only classification after an indeterminate kubectl return."""

        try:
            if self._deployment is None or self._before_replicaset_uid is None:
                raise KubernetesRotationBackendError("Kubernetes preflight is incomplete")
            original = self._deployment
            self._assert_namespace(self.profile.namespace, self.profile.namespace_uid)
            current = get_kubernetes_deployment_snapshot(
                self.runner,
                self._prefix,
                deployment=self.profile.service,
                expected_count=self.profile.expected_instance_count,
                require_ready=False,
            )
            self._assert_deployment_binding(current)
        except Exception:
            return ActionReconciliation("unknown", reason_code="runtime_read_failed")
        if current.observed_generation != current.generation:
            return ActionReconciliation("unknown", reason_code="deployment_unobserved")
        try:
            inventory_reason = classify_kubernetes_reconcile_inventory(
                self.runner,
                self._prefix,
                deployment=self.profile.service,
                expected_count=self.profile.expected_instance_count,
            )
        except Exception:
            return ActionReconciliation("unknown", reason_code="runtime_read_failed")
        if inventory_reason is not None:
            return ActionReconciliation("unknown", reason_code=inventory_reason)
        try:
            if current == original:
                result = "verified_old"
                expected = old_sha256
                phase = "action_reconcile_old"
                first, controller = self._reconciliation_generation(
                    current, replicaset_uid=self._before_replicaset_uid
                )
                if controller != self._before_replicaset_uid or first != list(before):
                    raise KubernetesRotationBackendError("Kubernetes old generation has drifted")
            else:
                if (
                    current.uid != original.uid
                    or current.generation != original.generation + 1
                    or current.revision != original.revision + 1
                    or current.restarted_at is None
                    or current.restarted_at == original.restarted_at
                ):
                    raise KubernetesRotationBackendError("Kubernetes rollout generation is ambiguous")
                result = "verified_new"
                expected = new_sha256
                phase = "action_reconcile_new"
                first, controller = self._reconciliation_generation(
                    current, replicaset_uid=None
                )
                assert_generation_replaced(
                    before,
                    first,
                    expected_count=self.profile.expected_instance_count,
                )
                assert_kubernetes_uids_absent(
                    self.runner,
                    self._prefix,
                    old_uids=self._old_uids,
                )
        except Exception:
            return ActionReconciliation("unknown", reason_code="rollout_markers_ambiguous")
        try:
            observations = tuple(
                self._probe_instance_for_deployment(
                    instance,
                    current,
                    expected_sha256=expected,
                    phase=phase,
                    observed_at=observed_at,
                )
                for instance in first
            )
        except Exception:
            return ActionReconciliation("unknown", reason_code="peer_unconfirmed")
        try:
            final, final_controller = self._reconciliation_generation(
                current, replicaset_uid=controller
            )
            if final != first or final_controller != controller:
                raise KubernetesRotationBackendError("Kubernetes generation drifted during reconciliation")
            if result == "verified_new":
                assert_kubernetes_uids_absent(
                    self.runner,
                    self._prefix,
                    old_uids=self._old_uids,
                )
            return ActionReconciliation(result, tuple(first), observations)
        except Exception:
            return ActionReconciliation("unknown", reason_code="inventory_unstable")

    def probe_route(self, observer, *, attempt, expected_sha256, observed_at):
        route = self._routes.get(observer)
        if route is None:
            raise KubernetesRotationBackendError("route observer is not reviewed")
        before = self._route_snapshot(route)
        command = kubernetes_probe_command(
            self._kubectl_prefix(route.namespace),
            observer=route.pod,
            container=route.container,
            url=route.url,
            ca_file=route.ca_file,
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
        if self._route_snapshot(route) != before:
            raise KubernetesRotationBackendError("Kubernetes observer Pod identity has drifted")
        return observation

    def contain(self) -> None:
        before = get_kubernetes_deployment_snapshot(
            self.runner,
            self._prefix,
            deployment=self.profile.service,
            expected_count=self.profile.expected_instance_count,
            require_ready=False,
        )
        if before.uid != self.profile.deployment_uid:
            raise KubernetesRotationBackendError("Kubernetes containment target has drifted")
        pause_kubernetes_deployment(self.runner, self._prefix, deployment=self.profile.service)
        after = get_kubernetes_deployment_snapshot(
            self.runner,
            self._prefix,
            deployment=self.profile.service,
            expected_count=self.profile.expected_instance_count,
            require_ready=False,
        )
        if after.uid != before.uid or not after.paused:
            raise KubernetesRotationBackendError("Kubernetes rollout pause is unconfirmed")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        materialized, self._materialized = self._materialized, None
        if materialized is None:
            return
        try:
            materialized.close()
        except PrivateSecretMaterializationError:
            raise KubernetesRotationBackendError(
                "Kubernetes kubeconfig cleanup failed"
            ) from None


def build_kubernetes_rotation_backend(
    profile_path: Path,
    projection: Mapping[str, object],
    *,
    shell_environment: Mapping[str, str],
    runner_factory=SanitizedSubprocessRunner,
) -> KubernetesRotationBackend:
    profile = load_kubernetes_rotation_profile(profile_path)
    if (
        projection.get("runtime_kind") != "kubernetes"
        or projection.get("target_environment") != profile.target_environment
        or projection.get("service") != profile.service
        or projection.get("expected_instance_count") != profile.expected_instance_count
        or projection.get("required_observers") != list(profile.required_observers)
        or projection.get("runtime_profile_sha256") != profile.profile_sha256
    ):
        raise KubernetesRotationBackendError("runtime profile does not match rotation plan")
    if profile.blocked_observers:
        raise KubernetesRotationBackendError("required real observer probe runtime is unavailable")
    return KubernetesRotationBackend(profile, runner_factory(shell_environment))
