from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.kubernetes_kubeconfig_intake import KubernetesKubeconfigIntakeError
from scripts.kubernetes_tls_rotation_backend import (
    KubernetesRotationBackend,
    KubernetesRotationBackendError,
    KubernetesRotationProfile,
    KubernetesRouteObserver,
    build_kubernetes_rotation_backend,
    kubectl_prefix,
    load_kubernetes_rotation_profile,
)
from scripts.tls_rotation_runtime import KubernetesDeploymentSnapshot, RuntimeInstanceSnapshot


NAMESPACE_UID = "11111111-1111-4111-8111-111111111111"
DEPLOYMENT_UID = "22222222-2222-4222-8222-222222222222"
IMAGE = "registry.example.invalid/email-platform/web@sha256:" + "a" * 64
MATERIALIZED_KUBECONFIG = Path("C:/materialized/secret")


class Runner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(self, command, *, capture_output=False, input_text=None):
        self.calls.append(list(command))
        return ""


class MaterializedKubeconfig:
    def __init__(self) -> None:
        self.path = MATERIALIZED_KUBECONFIG
        self.verify_calls = 0
        self.close_calls = 0

    def verify(self) -> None:
        self.verify_calls += 1

    def close(self) -> None:
        self.close_calls += 1


def _activate(backend: KubernetesRotationBackend) -> MaterializedKubeconfig:
    value = MaterializedKubeconfig()
    backend._materialized = value
    return value


def _profile_value(kubeconfig: Path) -> dict[str, object]:
    return {
        "schema_version": 2,
        "profile_kind": "kubernetes_tls_rotation_backend",
        "live_capture_sha256": "f" * 64,
        "target_environment": "production",
        "service": "web",
        "expected_instance_count": 2,
        "required_observers": ["edge"],
        "kubeconfig_path": str(kubeconfig),
        "kubeconfig_sha256": hashlib.sha256(kubeconfig.read_bytes()).hexdigest(),
        "context": "production-cluster",
        "namespace": "email-platform",
        "namespace_uid": NAMESPACE_UID,
        "deployment_uid": DEPLOYMENT_UID,
        "expected_image": IMAGE,
        "direct_probe": {
            "logical_name": "direct-instance",
            "namespace": "diagnostics",
            "namespace_uid": "77777777-7777-4777-8777-777777777777",
            "deployment": "tls-probe",
            "deployment_uid": "88888888-8888-4888-8888-888888888888",
            "pod": "tls-probe-abc",
            "pod_uid": "99999999-9999-4999-8999-999999999999",
            "replicaset_uid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "revision": 4,
            "container": "tls-probe",
            "expected_image": "registry.example.invalid/ops/tls-probe@sha256:" + "c" * 64,
            "url": "https://web.email-platform.svc:8443/",
            "ca_file": "/run/secrets/internal-tls/ca.crt",
        },
        "route_observers": [],
        "blocked_observers": ["edge"],
    }


def _snapshot(*, generation: int, revision: int, observed: int, restarted_at: str) -> KubernetesDeploymentSnapshot:
    return KubernetesDeploymentSnapshot(
        uid=DEPLOYMENT_UID,
        generation=generation,
        observed_generation=observed,
        revision=revision,
        restarted_at=restarted_at,
        paused=False,
        image_identity=IMAGE,
        tls_secret_name="platform-web-internal-tls",
    )


def _direct() -> KubernetesRouteObserver:
    return KubernetesRouteObserver(
        logical_name="direct-instance",
        namespace="diagnostics",
        namespace_uid="77777777-7777-4777-8777-777777777777",
        deployment="tls-probe",
        deployment_uid="88888888-8888-4888-8888-888888888888",
        pod="tls-probe-abc",
        pod_uid="99999999-9999-4999-8999-999999999999",
        replicaset_uid="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        revision=4,
        container="tls-probe",
        expected_image="registry.example.invalid/ops/tls-probe@sha256:" + "c" * 64,
        url="https://web.email-platform.svc:8443/",
        ca_file="/run/secrets/internal-tls/ca.crt",
    )


class KubernetesTlsRotationBackendTests(unittest.TestCase):
    def test_preflight_private_read_only_kubeconfig_failure_precedes_runner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            kubeconfig = Path(directory) / "kubeconfig"
            kubeconfig.write_text("clusters: []\n", encoding="utf-8")
            profile = KubernetesRotationProfile(
                "f" * 64, "production", "web", 2, ("edge",), kubeconfig,
                hashlib.sha256(kubeconfig.read_bytes()).hexdigest(),
                "production-cluster", "email-platform", NAMESPACE_UID,
                DEPLOYMENT_UID, IMAGE, _direct(), (), (), "f" * 64,
            )
            runner = Runner()
            projection = {
                "target_environment": "production",
                "runtime_kind": "kubernetes",
                "service": "web",
                "expected_instance_count": 2,
                "required_observers": ["edge"],
                "runtime_profile_sha256": profile.profile_sha256,
                "old_leaf_sha256": "1" * 64,
                "new_leaf_sha256": "2" * 64,
                "old_spki_sha256": "3" * 64,
                "new_spki_sha256": "4" * 64,
            }
            with mock.patch(
                "scripts.kubernetes_tls_rotation_backend.read_private_secret_bytes",
                side_effect=OSError("denied"),
            ) as read_kubeconfig, self.assertRaisesRegex(
                KubernetesRotationBackendError, "kubeconfig cannot be read"
            ):
                KubernetesRotationBackend(profile, runner).preflight(projection)
            read_kubeconfig.assert_called_once_with(
                kubeconfig, max_bytes=1024 * 1024, require_read_only=True
            )
            self.assertEqual(runner.calls, [])

    def test_invalid_kubeconfig_intake_precedes_runner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            kubeconfig = Path(directory) / "kubeconfig"
            kubeconfig.write_text("clusters: []\n", encoding="utf-8")
            profile = KubernetesRotationProfile(
                "f" * 64, "production", "web", 2, ("edge",), kubeconfig,
                hashlib.sha256(kubeconfig.read_bytes()).hexdigest(),
                "production-cluster", "email-platform", NAMESPACE_UID,
                DEPLOYMENT_UID, IMAGE, _direct(), (), (), "f" * 64,
            )
            projection = {
                "target_environment": "production",
                "runtime_kind": "kubernetes",
                "service": "web",
                "expected_instance_count": 2,
                "required_observers": ["edge"],
                "runtime_profile_sha256": profile.profile_sha256,
                "old_leaf_sha256": "1" * 64,
                "new_leaf_sha256": "2" * 64,
                "old_spki_sha256": "3" * 64,
                "new_spki_sha256": "4" * 64,
            }
            runner = Runner()
            with mock.patch(
                "scripts.kubernetes_tls_rotation_backend.read_private_secret_bytes",
                return_value=b"SECRET-CANARY",
            ), mock.patch(
                "scripts.kubernetes_tls_rotation_backend.validate_self_contained_kubeconfig",
                side_effect=KubernetesKubeconfigIntakeError(
                    "Kubernetes kubeconfig intake is invalid"
                ),
            ), self.assertRaisesRegex(
                KubernetesRotationBackendError,
                "^Kubernetes kubeconfig intake is invalid$",
            ) as raised:
                KubernetesRotationBackend(profile, runner).preflight(projection)
            self.assertNotIn("SECRET-CANARY", str(raised.exception))
            self.assertEqual(runner.calls, [])

    def test_preflight_materializes_once_and_prefix_never_uses_source_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            kubeconfig = Path(directory) / "kubeconfig"
            kubeconfig.write_bytes(b"SOURCE-CANARY")
            profile = KubernetesRotationProfile(
                "f" * 64, "production", "web", 2, ("edge",), kubeconfig,
                "a" * 64, "production-cluster", "email-platform", NAMESPACE_UID,
                DEPLOYMENT_UID, IMAGE, _direct(), (), (), "f" * 64,
            )
            projection = {
                "target_environment": "production",
                "runtime_kind": "kubernetes",
                "service": "web",
                "expected_instance_count": 2,
                "required_observers": ["edge"],
                "runtime_profile_sha256": profile.profile_sha256,
                "old_leaf_sha256": "1" * 64,
                "new_leaf_sha256": "2" * 64,
                "old_spki_sha256": "3" * 64,
                "new_spki_sha256": "4" * 64,
            }
            materialized = MaterializedKubeconfig()
            backend = KubernetesRotationBackend(profile, Runner())
            deployment = _snapshot(
                generation=8,
                revision=9,
                observed=8,
                restarted_at="2026-08-27T00:00:00.000000Z",
            )
            with mock.patch(
                "scripts.kubernetes_tls_rotation_backend.read_private_secret_bytes",
                return_value=b"SOURCE-CANARY",
            ), mock.patch(
                "scripts.kubernetes_tls_rotation_backend.validate_self_contained_kubeconfig",
                return_value="a" * 64,
            ), mock.patch(
                "scripts.kubernetes_tls_rotation_backend.materialize_private_secret_bytes",
                return_value=materialized,
            ) as create, mock.patch.object(
                backend, "_assert_namespace"
            ), mock.patch(
                "scripts.kubernetes_tls_rotation_backend.get_kubernetes_deployment_snapshot",
                return_value=deployment,
            ), mock.patch(
                "scripts.kubernetes_tls_rotation_backend._certificate_identity",
                return_value=("2" * 64, "4" * 64),
            ), mock.patch.object(
                backend, "_preflight_observer_probe"
            ):
                backend.preflight(projection)
            create.assert_called_once_with(b"SOURCE-CANARY", "a" * 64)
            prefix = backend._prefix
            self.assertIn(str(MATERIALIZED_KUBECONFIG), prefix)
            self.assertNotIn(str(kubeconfig), prefix)
            backend.close()
            backend.close()
            self.assertEqual(materialized.close_calls, 1)
            with self.assertRaisesRegex(
                KubernetesRotationBackendError, "materialization is unavailable"
            ):
                backend._kubectl_prefix()

    def test_real_materialization_survives_source_replacement_until_close(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            kubeconfig = Path(directory) / "kubeconfig"
            kubeconfig.write_bytes(b"SOURCE-A")
            digest = hashlib.sha256(b"SOURCE-A").hexdigest()
            profile = KubernetesRotationProfile(
                "f" * 64, "production", "web", 2, ("edge",), kubeconfig,
                digest, "production-cluster", "email-platform", NAMESPACE_UID,
                DEPLOYMENT_UID, IMAGE, _direct(), (), (), "f" * 64,
            )
            projection = {
                "target_environment": "production",
                "runtime_kind": "kubernetes",
                "service": "web",
                "expected_instance_count": 2,
                "required_observers": ["edge"],
                "runtime_profile_sha256": profile.profile_sha256,
                "old_leaf_sha256": "1" * 64,
                "new_leaf_sha256": "2" * 64,
                "old_spki_sha256": "3" * 64,
                "new_spki_sha256": "4" * 64,
            }
            backend = KubernetesRotationBackend(profile, Runner())
            deployment = _snapshot(
                generation=8,
                revision=9,
                observed=8,
                restarted_at="2026-08-27T00:00:00.000000Z",
            )
            with mock.patch(
                "scripts.kubernetes_tls_rotation_backend.read_private_secret_bytes",
                return_value=b"SOURCE-A",
            ), mock.patch(
                "scripts.kubernetes_tls_rotation_backend.validate_self_contained_kubeconfig",
                return_value=digest,
            ), mock.patch.object(
                backend, "_assert_namespace"
            ), mock.patch(
                "scripts.kubernetes_tls_rotation_backend.get_kubernetes_deployment_snapshot",
                return_value=deployment,
            ), mock.patch(
                "scripts.kubernetes_tls_rotation_backend._certificate_identity",
                return_value=("2" * 64, "4" * 64),
            ), mock.patch.object(
                backend, "_preflight_observer_probe"
            ):
                backend.preflight(projection)
            assert backend._materialized is not None
            materialized_path = backend._materialized.path
            try:
                self.assertNotEqual(materialized_path, kubeconfig)
                self.assertEqual(materialized_path.read_bytes(), b"SOURCE-A")
                kubeconfig.write_bytes(b"SOURCE-B")
                self.assertIn(str(materialized_path), backend._prefix)
                self.assertNotIn(str(kubeconfig), backend._prefix)
            finally:
                backend.close()
            self.assertFalse(materialized_path.exists())
            self.assertFalse(materialized_path.parent.exists())

    def test_action_reconciliation_never_restarts_or_pauses(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            kubeconfig = Path(directory) / "kubeconfig"
            kubeconfig.write_text("clusters: []\n", encoding="utf-8")
            profile = KubernetesRotationProfile(
                "f" * 64, "production", "web", 2, ("edge",), kubeconfig,
                hashlib.sha256(kubeconfig.read_bytes()).hexdigest(),
                "production-cluster", "email-platform", NAMESPACE_UID,
                DEPLOYMENT_UID, IMAGE, _direct(), (), (), "f" * 64,
            )
            backend = KubernetesRotationBackend(profile, Runner())
            _activate(backend)
            original = _snapshot(
                generation=8, revision=9, observed=8,
                restarted_at="2026-08-27T00:00:00.000000Z",
            )
            current = _snapshot(
                generation=9, revision=10, observed=9,
                restarted_at="2026-08-27T00:01:00.000000Z",
            )
            old = [
                RuntimeInstanceSnapshot({
                    "instance_id": f"{index}" * 8 + f"-{index}" * 4 + f"-4{index}" * 4 + f"-8{index}" * 4 + f"-{index}" * 12,
                    "container_id": "containerd://" + f"{index}" * 64,
                    "started_at": "2026-08-26T00:00:00Z",
                }) for index in (1, 2)
            ]
            new = [
                RuntimeInstanceSnapshot({
                    "instance_id": value,
                    "container_id": "containerd://" + digit * 64,
                    "started_at": "2026-08-27T00:00:03Z",
                }, runtime_name=f"web-{digit}", controller_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                for value, digit in (
                    ("33333333-3333-4333-8333-333333333333", "3"),
                    ("44444444-4444-4444-8444-444444444444", "4"),
                )
            ]
            backend._deployment = original
            backend._before_replicaset_uid = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
            backend._old_uids = tuple(item.evidence["instance_id"] for item in old)
            observations = iter([
                {"phase": "action_reconcile_new", "observer": "direct-instance",
                 "instance_id": item.evidence["instance_id"], "attempt": 1,
                 "expected_sha256": "2" * 64, "peer_sha256": "2" * 64,
                 "tls_version": "TLSv1.3", "observed_at": "2026-08-27T00:00:04Z"}
                for item in new
            ])
            with mock.patch.object(backend, "_assert_namespace"), mock.patch(
                "scripts.kubernetes_tls_rotation_backend.get_kubernetes_deployment_snapshot",
                return_value=current,
            ), mock.patch(
                "scripts.kubernetes_tls_rotation_backend.classify_kubernetes_reconcile_inventory",
                return_value=None,
            ), mock.patch.object(
                backend, "_reconciliation_generation",
                side_effect=[(new, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
                             (new, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")],
            ), mock.patch.object(
                backend, "_probe_instance_for_deployment", side_effect=lambda *args, **kwargs: next(observations)
            ), mock.patch(
                "scripts.kubernetes_tls_rotation_backend.assert_kubernetes_uids_absent"
            ) as absent, mock.patch(
                "scripts.kubernetes_tls_rotation_backend.restart_kubernetes_deployment"
            ) as restart, mock.patch(
                "scripts.kubernetes_tls_rotation_backend.pause_kubernetes_deployment"
            ) as pause:
                result = backend.reconcile_action(
                    old, old_sha256="1" * 64, new_sha256="2" * 64,
                    observed_at="2026-08-27T00:00:04Z",
                )
            self.assertEqual(result.result, "verified_new")
            self.assertIsNone(result.reason_code)
            self.assertEqual(absent.call_count, 2)
            restart.assert_not_called()
            pause.assert_not_called()

    def test_reconciliation_returns_closed_mixed_and_unready_reasons(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            kubeconfig = Path(directory) / "kubeconfig"
            kubeconfig.write_text("clusters: []\n", encoding="utf-8")
            profile = KubernetesRotationProfile(
                "f" * 64, "production", "web", 2, ("edge",), kubeconfig,
                hashlib.sha256(kubeconfig.read_bytes()).hexdigest(),
                "production-cluster", "email-platform", NAMESPACE_UID,
                DEPLOYMENT_UID, IMAGE, _direct(), (), (), "f" * 64,
            )
            backend = KubernetesRotationBackend(profile, Runner())
            _activate(backend)
            original = _snapshot(
                generation=8, revision=9, observed=8,
                restarted_at="2026-08-27T00:00:00.000000Z",
            )
            backend._deployment = original
            backend._before_replicaset_uid = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
            for reason in ("mixed_replicasets", "pod_unready"):
                with self.subTest(reason=reason), mock.patch.object(
                    backend, "_assert_namespace"
                ), mock.patch(
                    "scripts.kubernetes_tls_rotation_backend.get_kubernetes_deployment_snapshot",
                    return_value=original,
                ), mock.patch(
                    "scripts.kubernetes_tls_rotation_backend.classify_kubernetes_reconcile_inventory",
                    return_value=reason,
                ):
                    result = backend.reconcile_action(
                        [], old_sha256="1" * 64, new_sha256="2" * 64,
                        observed_at="2026-08-27T00:00:04Z",
                    )
                self.assertEqual((result.result, result.reason_code), ("unknown", reason))
                self.assertEqual((result.instances, result.peer_observations), ((), ()))

    def test_profile_is_external_closed_and_blocked_inventory_prevents_runner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            kubeconfig = root / "kubeconfig"
            kubeconfig.write_text("clusters: []\n", encoding="utf-8")
            value = _profile_value(kubeconfig)
            profile_path = root / "profile.json"
            profile_path.write_text(json.dumps(value), encoding="utf-8")
            profile = load_kubernetes_rotation_profile(profile_path)
            projection = {
                "runtime_kind": "kubernetes",
                "target_environment": "production",
                "service": "web",
                "expected_instance_count": 2,
                "required_observers": ["edge"],
                "runtime_profile_sha256": profile.profile_sha256,
            }
            factory = mock.Mock()
            with self.assertRaisesRegex(KubernetesRotationBackendError, "observer"):
                build_kubernetes_rotation_backend(
                    profile_path,
                    projection,
                    shell_environment={},
                    runner_factory=factory,
                )
            factory.assert_not_called()

            value["unexpected"] = "canary"
            profile_path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(KubernetesRotationBackendError, "profile"):
                load_kubernetes_rotation_profile(profile_path)

    def test_prefix_is_fully_explicit_and_never_inherits_context_or_namespace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            kubeconfig = Path(directory) / "kubeconfig"
            kubeconfig.write_text("clusters: []\n", encoding="utf-8")
            value = _profile_value(kubeconfig)
            value["blocked_observers"] = []
            value["route_observers"] = [{
                "logical_name": "edge",
                "namespace": "ingress-system",
                "namespace_uid": "33333333-3333-4333-8333-333333333333",
                "deployment": "edge",
                "deployment_uid": "44444444-4444-4444-8444-444444444444",
                "pod": "edge-abc",
                "pod_uid": "55555555-5555-4555-8555-555555555555",
                "replicaset_uid": "66666666-6666-4666-8666-666666666666",
                "revision": 7,
                "container": "edge",
                "expected_image": "registry.example.invalid/edge/proxy@sha256:" + "b" * 64,
                "url": "https://web.email-platform.svc:8443/",
                "ca_file": "/run/secrets/internal-tls/ca.crt",
            }]
            profile_path = Path(directory) / "profile.json"
            profile_path.write_text(json.dumps(value), encoding="utf-8")
            profile = load_kubernetes_rotation_profile(profile_path)
        self.assertEqual(
            kubectl_prefix(
                MATERIALIZED_KUBECONFIG,
                context="production-cluster",
                namespace="email-platform",
            ),
            (
                "kubectl", "--kubeconfig", str(MATERIALIZED_KUBECONFIG), "--context",
                "production-cluster", "--request-timeout=30s", "--namespace",
                "email-platform",
            ),
        )

    def test_action_discovers_new_revision_before_waiting_and_binds_ready_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            kubeconfig = Path(directory) / "kubeconfig"
            kubeconfig.write_text("clusters: []\n", encoding="utf-8")
            value = _profile_value(kubeconfig)
            profile = KubernetesRotationProfile(
                live_capture_sha256="f" * 64,
                target_environment="production",
                service="web",
                expected_instance_count=2,
                required_observers=("edge",),
                kubeconfig_path=kubeconfig,
                kubeconfig_sha256=value["kubeconfig_sha256"],
                context="production-cluster",
                namespace="email-platform",
                namespace_uid=NAMESPACE_UID,
                deployment_uid=DEPLOYMENT_UID,
                expected_image=IMAGE,
                direct_observer=_direct(),
                route_observers=(),
                blocked_observers=(),
                profile_sha256="f" * 64,
            )
            runner = Runner()
            backend = KubernetesRotationBackend(profile, runner)
            _activate(backend)
            before = _snapshot(generation=8, revision=9, observed=8, restarted_at="2026-08-27T00:00:00.000000Z")
            discovered = _snapshot(generation=9, revision=10, observed=8, restarted_at="2026-08-27T00:01:00.000000Z")
            ready = _snapshot(generation=9, revision=10, observed=9, restarted_at="2026-08-27T00:01:00.000000Z")
            backend._deployment = before
            with mock.patch(
                "scripts.kubernetes_tls_rotation_backend.restart_kubernetes_deployment"
            ) as restart, mock.patch(
                "scripts.kubernetes_tls_rotation_backend.get_kubernetes_deployment_snapshot",
                side_effect=[discovered, ready],
            ) as get_deployment, mock.patch(
                "scripts.kubernetes_tls_rotation_backend.wait_kubernetes_rollout_revision"
            ) as wait:
                backend.act()
            restart.assert_called_once()
            self.assertFalse(get_deployment.call_args_list[0].kwargs["require_ready"])
            self.assertNotIn("require_ready", get_deployment.call_args_list[1].kwargs)
            self.assertEqual(wait.call_args.kwargs["revision"], 10)
            self.assertTrue(backend._acted)
            self.assertEqual(backend._deployment, ready)

    def test_containment_confirms_same_deployment_uid_and_paused_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            kubeconfig = Path(directory) / "kubeconfig"
            kubeconfig.write_text("clusters: []\n", encoding="utf-8")
            profile = KubernetesRotationProfile(
                "f" * 64, "production", "web", 2, ("edge",), kubeconfig,
                hashlib.sha256(kubeconfig.read_bytes()).hexdigest(),
                "production-cluster", "email-platform", NAMESPACE_UID,
                DEPLOYMENT_UID, IMAGE, _direct(), (), (), "f" * 64,
            )
            backend = KubernetesRotationBackend(profile, Runner())
            _activate(backend)
            before = _snapshot(generation=9, revision=10, observed=8, restarted_at="2026-08-27T00:01:00.000000Z")
            after = KubernetesDeploymentSnapshot(**{**before.__dict__, "paused": True, "generation": 10})
            with mock.patch(
                "scripts.kubernetes_tls_rotation_backend.get_kubernetes_deployment_snapshot",
                side_effect=[before, after],
            ), mock.patch(
                "scripts.kubernetes_tls_rotation_backend.pause_kubernetes_deployment"
            ) as pause:
                backend.contain()
            pause.assert_called_once()


if __name__ == "__main__":
    unittest.main()
