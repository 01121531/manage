from __future__ import annotations

from collections import deque
from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest import mock

from scripts.kubernetes_kubeconfig_intake import KubernetesKubeconfigIntakeError
from scripts.private_secret_materialization import PrivateSecretMaterializationError
from scripts.tls_rotation_profile_capture import TlsRotationProfileCaptureError
from scripts.tls_rotation_profile_live import ReadOnlyCaptureRunner, _kubernetes_capture


KUBECONFIG = Path("C:/protected/kubeconfig")
MATERIALIZED_KUBECONFIG = Path("C:/protected-materialized/secret")
CONTEXT = "production-cluster"
TARGET_NAMESPACE_UID = "11111111-1111-4111-8111-111111111111"
WEB_DEPLOYMENT_UID = "22222222-2222-4222-8222-222222222222"
WEB_REPLICASET_UID = "33333333-3333-4333-8333-333333333333"
WEB_IMAGE = "registry.invalid/email/web@sha256:" + "a" * 64


def _request() -> dict[str, object]:
    return {
        "schema_version": 1,
        "request_kind": "tls_rotation_profile_capture_request",
        "runtime_kind": "kubernetes",
        "target_environment": "production-cn",
        "service": "web",
        "kubeconfig_path": str(KUBECONFIG),
        "context": CONTEXT,
        "namespace": "email-platform",
        "direct_observer": {
            "logical_name": "direct-instance",
            "namespace": "diagnostics",
            "deployment": "tls-probe",
            "container": "tls-probe",
        },
        "route_observers": [{
            "logical_name": "edge",
            "namespace": "ingress-system",
            "deployment": "edge",
            "container": "edge",
        }],
    }


def _prefix(namespace: str | None = None) -> tuple[str, ...]:
    value = (
        "kubectl", "--kubeconfig", str(MATERIALIZED_KUBECONFIG), "--context", CONTEXT,
        "--request-timeout=30s",
    )
    return value if namespace is None else (*value, "--namespace", namespace)


def _deployment(
    name: str,
    uid: str,
    image: str,
    *,
    replicas: int,
    revision: int,
) -> dict[str, object]:
    container: dict[str, object] = {"name": name, "image": image}
    volumes: list[dict[str, object]] = []
    template_metadata: dict[str, object] = {}
    if name == "web":
        container["volumeMounts"] = [
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
        volumes = [{
            "name": "internal-tls",
            "secret": {"secretName": "platform-web-internal-tls"},
        }]
        template_metadata = {
            "annotations": {
                "kubectl.kubernetes.io/restartedAt": "2026-08-27T08:00:00Z"
            }
        }
    return {
        "metadata": {
            "uid": uid,
            "generation": revision,
            "annotations": {"deployment.kubernetes.io/revision": str(revision)},
        },
        "spec": {
            "replicas": replicas,
            "paused": False,
            "template": {
                "metadata": template_metadata,
                "spec": {"containers": [container], "volumes": volumes},
            },
        },
        "status": {
            "observedGeneration": revision,
            "replicas": replicas,
            "updatedReplicas": replicas,
            "readyReplicas": replicas,
            "availableReplicas": replicas,
            "unavailableReplicas": 0,
        },
    }


def _pod(
    deployment: str,
    name: str,
    uid: str,
    replicaset: str,
    replicaset_uid: str,
    image: str,
    digit: str,
    address: str,
) -> dict[str, object]:
    return {
        "metadata": {
            "name": name,
            "uid": uid,
            "ownerReferences": [{
                "apiVersion": "apps/v1",
                "kind": "ReplicaSet",
                "name": replicaset,
                "uid": replicaset_uid,
                "controller": True,
            }],
        },
        "status": {
            "phase": "Running",
            "conditions": [{"type": "Ready", "status": "True"}],
            "podIP": address,
            "containerStatuses": [{
                "name": deployment,
                "ready": True,
                "restartCount": 0,
                "state": {"running": {"startedAt": "2026-08-27T08:01:00Z"}},
                "containerID": "containerd://" + digit * 64,
                "imageID": "containerd://" + image,
            }],
        },
    }


def _replicaset(
    name: str,
    uid: str,
    deployment: str,
    deployment_uid: str,
    revision: int,
) -> dict[str, object]:
    return {
        "metadata": {
            "name": name,
            "uid": uid,
            "annotations": {"deployment.kubernetes.io/revision": str(revision)},
            "ownerReferences": [{
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "name": deployment,
                "uid": deployment_uid,
                "controller": True,
            }],
        }
    }


def _generation(*, web_runtime_image: str = WEB_IMAGE, mixed_rs: bool = False):
    direct_image = "registry.invalid/ops/tls-probe@sha256:" + "b" * 64
    edge_image = "registry.invalid/ops/edge@sha256:" + "c" * 64
    web_pods = [
        _pod(
            "web", "web-a", "44444444-4444-4444-8444-444444444444",
            "web-rs", WEB_REPLICASET_UID, web_runtime_image, "1", "10.20.0.11",
        ),
        _pod(
            "web", "web-b", "55555555-5555-4555-8555-555555555555",
            "web-rs-2" if mixed_rs else "web-rs",
            "66666666-6666-4666-8666-666666666666" if mixed_rs else WEB_REPLICASET_UID,
            web_runtime_image, "2", "10.20.0.12",
        ),
    ]
    direct_pod = _pod(
        "tls-probe", "tls-probe-a", "99999999-9999-4999-8999-999999999999",
        "tls-probe-rs", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        direct_image, "3", "10.21.0.11",
    )
    edge_pod = _pod(
        "edge", "edge-a", "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        "edge-rs", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        edge_image, "4", "10.22.0.11",
    )
    deployments = {
        "web": _deployment("web", WEB_DEPLOYMENT_UID, WEB_IMAGE, replicas=2, revision=7),
        "tls-probe": _deployment(
            "tls-probe", "88888888-8888-4888-8888-888888888888",
            direct_image, replicas=1, revision=4,
        ),
        "edge": _deployment(
            "edge", "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            edge_image, replicas=1, revision=3,
        ),
    }
    namespaces = {
        "email-platform": TARGET_NAMESPACE_UID,
        "diagnostics": "77777777-7777-4777-8777-777777777777",
        "ingress-system": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    }
    pods = {"web": web_pods, "tls-probe": [direct_pod], "edge": [edge_pod]}
    replica_sets = {
        "web-rs": _replicaset("web-rs", WEB_REPLICASET_UID, "web", WEB_DEPLOYMENT_UID, 7),
        "web-rs-2": _replicaset(
            "web-rs-2", "66666666-6666-4666-8666-666666666666",
            "web", WEB_DEPLOYMENT_UID, 7,
        ),
        "tls-probe-rs": _replicaset(
            "tls-probe-rs", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "tls-probe", "88888888-8888-4888-8888-888888888888", 4,
        ),
        "edge-rs": _replicaset(
            "edge-rs", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            "edge", "cccccccc-cccc-4ccc-8ccc-cccccccccccc", 3,
        ),
    }
    return namespaces, deployments, pods, replica_sets


def _steps(generation):
    namespaces, deployments, pods, replica_sets = generation
    result: list[tuple[tuple[str, ...], object]] = []
    for namespace, deployment in (
        ("email-platform", "web"),
        ("diagnostics", "tls-probe"),
        ("ingress-system", "edge"),
    ):
        base = _prefix()
        scoped = _prefix(namespace)
        result.append(((*base, "get", "namespace", namespace, "-o", "json"), {
            "metadata": {"uid": namespaces[namespace]}
        }))
        result.append(((*scoped, "get", "deployment", deployment, "-o", "json"), deployments[deployment]))
        selector = f"app.kubernetes.io/name=email-platform,app.kubernetes.io/component={deployment}"
        result.append(((*scoped, "get", "pods", "-l", selector, "-o", "json"), {
            "items": pods[deployment]
        }))
        for pod in pods[deployment]:
            pod_name = pod["metadata"]["name"]
            rs_name = pod["metadata"]["ownerReferences"][0]["name"]
            result.append(((*scoped, "get", "pod", pod_name, "-o", "json"), pod))
            result.append(((*scoped, "get", "replicaset", rs_name, "-o", "json"), replica_sets[rs_name]))
    return result


class OrderedJsonRunner:
    def __init__(self, case: unittest.TestCase, steps) -> None:
        self.case = case
        self.steps = deque(deepcopy(steps))
        self.calls: list[tuple[str, ...]] = []

    def run(self, command, *, capture_output=False, input_text=None):
        self.case.assertTrue(self.steps, f"unexpected command: {command!r}")
        expected, response = self.steps.popleft()
        self.case.assertEqual(tuple(command), expected)
        self.case.assertIs(capture_output, True)
        self.case.assertIsNone(input_text)
        self.calls.append(tuple(command))
        return json.dumps(response, separators=(",", ":"))


class MaterializedKubeconfig:
    def __init__(self) -> None:
        self.path = MATERIALIZED_KUBECONFIG
        self.verify_calls = 0
        self.close_calls = 0

    def verify(self) -> None:
        self.verify_calls += 1

    def close(self) -> None:
        self.close_calls += 1

    def __enter__(self):
        self.verify()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False


class KubernetesTlsRotationLiveCaptureTests(unittest.TestCase):
    def test_two_stable_snapshots_are_34_closed_gets(self) -> None:
        steps = _steps(_generation())
        delegate = OrderedJsonRunner(self, [*steps, *steps])
        runner = ReadOnlyCaptureRunner(delegate)
        materialized = MaterializedKubeconfig()
        with mock.patch(
            "scripts.tls_rotation_profile_live.read_private_secret_bytes",
            side_effect=[b"KUBECONFIG-CANARY", b"KUBECONFIG-CANARY"],
        ) as read_kubeconfig, mock.patch(
            "scripts.tls_rotation_profile_live.validate_self_contained_kubeconfig",
            side_effect=["a" * 64, "a" * 64],
        ) as validate_kubeconfig, mock.patch(
            "scripts.tls_rotation_profile_live.materialize_private_secret_bytes",
            return_value=materialized,
        ) as create_materialized:
            candidate, summary = _kubernetes_capture(_request(), runner)
        self.assertFalse(delegate.steps)
        self.assertEqual(len(delegate.calls), 34)
        self.assertTrue(all("get" in command and "exec" not in command for command in delegate.calls))
        self.assertEqual(
            read_kubeconfig.call_args_list,
            [
                mock.call(KUBECONFIG, max_bytes=1024 * 1024, require_read_only=True),
                mock.call(KUBECONFIG, max_bytes=1024 * 1024, require_read_only=True),
            ],
        )
        self.assertEqual(candidate["deployment_uid"], WEB_DEPLOYMENT_UID)
        self.assertEqual(candidate["kubeconfig_sha256"], "a" * 64)
        self.assertEqual(
            validate_kubeconfig.call_args_list,
            [
                mock.call(
                    b"KUBECONFIG-CANARY",
                    expected_context="production-cluster",
                    expected_namespace="email-platform",
                ),
                mock.call(
                    b"KUBECONFIG-CANARY",
                    expected_context="production-cluster",
                    expected_namespace="email-platform",
                ),
            ],
        )
        self.assertEqual(candidate["expected_image"], WEB_IMAGE)
        create_materialized.assert_called_once_with(b"KUBECONFIG-CANARY", "a" * 64)
        self.assertEqual(materialized.verify_calls, 4)
        self.assertEqual(materialized.close_calls, 1)
        self.assertTrue(all(str(MATERIALIZED_KUBECONFIG) in call for call in delegate.calls))
        self.assertTrue(all(str(KUBECONFIG) not in call for call in delegate.calls))
        self.assertEqual(len(summary["instances"]), 2)
        serialized = json.dumps({"candidate": candidate, "summary": summary}, sort_keys=True)
        for secret in (
            "KUBECONFIG-CANARY", "10.20.0.11", "10.20.0.12",
            "platform-web-internal-tls", "web-rs", "tls.key", "tls.crt",
        ):
            self.assertNotIn(secret, serialized)

    def test_private_kubeconfig_failure_precedes_runtime_commands(self) -> None:
        delegate = OrderedJsonRunner(self, [])
        with mock.patch(
            "scripts.tls_rotation_profile_live.read_private_secret_bytes",
            side_effect=OSError("denied"),
        ), self.assertRaises(OSError):
            _kubernetes_capture(_request(), ReadOnlyCaptureRunner(delegate))
        self.assertEqual(delegate.calls, [])

    def test_invalid_kubeconfig_intake_precedes_runtime_commands(self) -> None:
        delegate = OrderedJsonRunner(self, [])
        with mock.patch(
            "scripts.tls_rotation_profile_live.read_private_secret_bytes",
            return_value=b"SECRET-CANARY",
        ), mock.patch(
            "scripts.tls_rotation_profile_live.validate_self_contained_kubeconfig",
            side_effect=KubernetesKubeconfigIntakeError(
                "Kubernetes kubeconfig intake is invalid"
            ),
        ), self.assertRaisesRegex(
            TlsRotationProfileCaptureError,
            "^Kubernetes kubeconfig intake is invalid$",
        ) as raised:
            _kubernetes_capture(_request(), ReadOnlyCaptureRunner(delegate))
        self.assertNotIn("SECRET-CANARY", str(raised.exception))
        self.assertEqual(delegate.calls, [])

    def test_source_drift_does_not_change_consumed_materialized_path(self) -> None:
        steps = _steps(_generation())
        delegate = OrderedJsonRunner(self, [*steps, *steps])
        materialized = MaterializedKubeconfig()
        with mock.patch(
            "scripts.tls_rotation_profile_live.read_private_secret_bytes",
            side_effect=[b"SOURCE-A", b"SOURCE-B"],
        ), mock.patch(
            "scripts.tls_rotation_profile_live.validate_self_contained_kubeconfig",
            side_effect=["a" * 64, "b" * 64],
        ), mock.patch(
            "scripts.tls_rotation_profile_live.materialize_private_secret_bytes",
            return_value=materialized,
        ), self.assertRaisesRegex(
            TlsRotationProfileCaptureError, "capture identity is unstable"
        ):
            _kubernetes_capture(_request(), ReadOnlyCaptureRunner(delegate))
        self.assertEqual(len(delegate.calls), 34)
        self.assertTrue(all(str(MATERIALIZED_KUBECONFIG) in call for call in delegate.calls))
        self.assertTrue(all(str(KUBECONFIG) not in call for call in delegate.calls))
        self.assertEqual(materialized.close_calls, 1)

    def test_materialized_identity_failure_stops_between_snapshots(self) -> None:
        steps = _steps(_generation())
        delegate = OrderedJsonRunner(self, steps)
        materialized = MaterializedKubeconfig()
        original_verify = materialized.verify

        def verify() -> None:
            original_verify()
            if materialized.verify_calls == 3:
                raise PrivateSecretMaterializationError(
                    "private secret materialization failed"
                )

        materialized.verify = verify
        with mock.patch(
            "scripts.tls_rotation_profile_live.read_private_secret_bytes",
            return_value=b"SOURCE-A",
        ), mock.patch(
            "scripts.tls_rotation_profile_live.validate_self_contained_kubeconfig",
            return_value="a" * 64,
        ), mock.patch(
            "scripts.tls_rotation_profile_live.materialize_private_secret_bytes",
            return_value=materialized,
        ), self.assertRaisesRegex(
            TlsRotationProfileCaptureError, "kubeconfig materialization failed"
        ):
            _kubernetes_capture(_request(), ReadOnlyCaptureRunner(delegate))
        self.assertEqual(len(delegate.calls), 17)
        self.assertEqual(materialized.close_calls, 1)

    def test_runtime_image_drift_and_mixed_replicasets_are_rejected(self) -> None:
        cases = (
            (_generation(web_runtime_image="registry.invalid/email/web@sha256:" + "f" * 64), "image"),
            (_generation(mixed_rs=True), "ReplicaSet"),
        )
        for generation, message in cases:
            with self.subTest(message=message):
                delegate = OrderedJsonRunner(self, _steps(generation))
                materialized = MaterializedKubeconfig()
                with mock.patch(
                    "scripts.tls_rotation_profile_live.read_private_secret_bytes",
                    return_value=b"KUBECONFIG-CANARY",
                ), mock.patch(
                    "scripts.tls_rotation_profile_live.validate_self_contained_kubeconfig",
                    return_value="a" * 64,
                ), mock.patch(
                    "scripts.tls_rotation_profile_live.materialize_private_secret_bytes",
                    return_value=materialized,
                ), self.assertRaisesRegex(TlsRotationProfileCaptureError, message):
                    _kubernetes_capture(_request(), ReadOnlyCaptureRunner(delegate))
                self.assertEqual(materialized.close_calls, 1)


if __name__ == "__main__":
    unittest.main()
