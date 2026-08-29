from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from scripts.tls_rotation_runtime import (
    RotationRuntimeError,
    assert_generation_replaced,
    assert_kubernetes_deployment_ready,
    assert_kubernetes_uids_absent,
    classify_kubernetes_reconcile_inventory,
    collect_compose_generation,
    collect_kubernetes_generation,
    collect_peer_observation,
    compose_probe_command,
    force_recreate_compose_service,
    get_kubernetes_deployment_snapshot,
    get_kubernetes_namespace_uid,
    kubernetes_probe_command,
    pause_kubernetes_deployment,
    restart_kubernetes_deployment,
    wait_kubernetes_rollout_revision,
)


DEPLOYMENT_UID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
REPLICASET_UID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


class Runner:
    def __init__(self, outputs: list[str]) -> None:
        self.outputs = list(outputs)
        self.calls: list[list[str]] = []

    def run(self, command, *, capture_output=False, input_text=None):
        self.calls.append(list(command))
        self.input_text = input_text
        return self.outputs.pop(0) if self.outputs else ""


def _pod(uid: str, container: str, address: str) -> dict[str, object]:
    return {
        "metadata": {
            "uid": uid,
            "name": "api-7654abcd-pod",
            "ownerReferences": [{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "api-7654abcd", "uid": REPLICASET_UID, "controller": True}],
        },
        "status": {
            "phase": "Running",
            "podIP": address,
            "conditions": [{"type": "Ready", "status": "True"}],
            "containerStatuses": [{
                "name": "api",
                "ready": True,
                "restartCount": 0,
                "containerID": "containerd://" + container * 64,
                "imageID": "registry.example.invalid/email-platform/api@sha256:" + "d" * 64,
                "state": {"running": {"startedAt": "2026-08-27T00:00:02.123456789Z"}},
            }],
        },
    }


def _replicaset() -> dict[str, object]:
    return {
        "metadata": {
            "uid": REPLICASET_UID,
            "annotations": {"deployment.kubernetes.io/revision": "9"},
            "ownerReferences": [{
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "name": "api",
                "uid": DEPLOYMENT_UID,
                "controller": True,
            }],
        }
    }


def _deployment(*, generation: int = 8, revision: int = 9, paused: bool = False) -> dict[str, object]:
    return {
        "metadata": {
            "uid": DEPLOYMENT_UID,
            "generation": generation,
            "annotations": {"deployment.kubernetes.io/revision": str(revision)},
        },
        "spec": {
            "replicas": 2,
            "paused": paused,
            "template": {
                "metadata": {"annotations": {
                    "kubectl.kubernetes.io/restartedAt": "2026-08-27T00:00:01Z"
                }},
                "spec": {
                    "containers": [{
                        "name": "api",
                        "image": "registry.example.invalid/email-platform/api@sha256:" + "d" * 64,
                        "volumeMounts": [
                            {"name": "internal-tls", "mountPath": "/run/secrets/internal-tls/tls.crt", "subPath": "tls.crt", "readOnly": True},
                            {"name": "internal-tls", "mountPath": "/run/secrets/internal-tls/tls.key", "subPath": "tls.key", "readOnly": True},
                        ],
                    }],
                    "volumes": [{"name": "internal-tls", "secret": {"secretName": "platform-api-internal-tls"}}],
                },
            },
        },
        "status": {
            "observedGeneration": generation,
            "replicas": 2,
            "updatedReplicas": 2,
            "readyReplicas": 2,
            "availableReplicas": 2,
            "unavailableReplicas": 0,
        },
    }


class TlsRotationRuntimeTests(unittest.TestCase):
    def test_compose_collection_pins_id_started_at_and_reviewed_read_only_mounts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert = root / "tls.crt"
            key = root / "tls.key"
            cert.write_text("certificate", encoding="utf-8")
            key.write_text("key", encoding="utf-8")
            identifier = "1" * 64
            mounts = [
                    {"Type": "bind", "Source": str(cert), "Destination": "/run/tls/tls.crt", "RW": False},
                    {"Type": "bind", "Source": str(key), "Destination": "/run/tls/tls.key", "RW": False},
            ]
            image = "registry.example.invalid/api@sha256:" + "a" * 64
            network_id = "9" * 64
            networks = {"email-platform-metrics": {
                "IPAddress": "172.30.0.12", "NetworkID": network_id,
            }}
            runner = Runner([
                identifier + "\n", identifier, "true", "2026-08-27T00:00:02.123456789Z",
                json.dumps(mounts), image, json.dumps(networks),
            ])
            snapshots = collect_compose_generation(
                runner,
                ["docker", "compose", "-f", "compose.yml"],
                service="api",
                expected_tls_mounts={"/run/tls/tls.crt": cert, "/run/tls/tls.key": key},
                expected_image=image,
                expected_network="email-platform-metrics",
            )
        self.assertEqual(snapshots[0].evidence["instance_id"], identifier)
        self.assertEqual(snapshots[0].evidence["started_at"], "2026-08-27T00:00:02.123456Z")
        self.assertNotIn("Source", snapshots[0].evidence)
        self.assertEqual(snapshots[0].image_identity, image)
        self.assertEqual(snapshots[0].connect_host, "172.30.0.12")
        self.assertEqual(snapshots[0].network_identity, network_id)
        self.assertTrue(all(call[:3] != ["docker", "inspect", identifier] for call in runner.calls))

        mounts[1]["RW"] = True
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert = root / "tls.crt"
            key = root / "tls.key"
            cert.write_text("certificate", encoding="utf-8")
            key.write_text("key", encoding="utf-8")
            mounts = [
                {"Type": "bind", "Source": str(cert), "Destination": "/run/tls/tls.crt", "RW": False},
                {"Type": "bind", "Source": str(key), "Destination": "/run/tls/tls.key", "RW": True},
            ]
            runner = Runner([
                identifier, identifier, "true", "2026-08-27T00:00:02Z",
                json.dumps(mounts), image, json.dumps(networks),
            ])
            with self.assertRaisesRegex(RotationRuntimeError, "mount contract"):
                collect_compose_generation(
                    runner,
                    ["docker", "compose"],
                    service="api",
                    expected_tls_mounts={
                        "/run/tls/tls.crt": Path(mounts[0]["Source"]),
                        "/run/tls/tls.key": Path(mounts[1]["Source"]),
                    },
                    expected_image=image,
                    expected_network="email-platform-metrics",
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert = root / "tls.crt"
            key = root / "tls.key"
            cert.write_text("certificate", encoding="utf-8")
            key.write_text("key", encoding="utf-8")
            mounts = [
                {"Type": "bind", "Source": str(cert), "Destination": "/run/tls/tls.crt", "RW": False},
                {"Type": "bind", "Source": str(key), "Destination": "/run/tls/tls.key", "RW": False},
            ]
            runner = Runner([
                identifier, identifier, "true", "2026-08-27T00:00:02Z",
                json.dumps(mounts),
                "registry.example.invalid/api@sha256:" + "b" * 64,
                json.dumps(networks),
            ])
            with self.assertRaisesRegex(RotationRuntimeError, "image identity"):
                collect_compose_generation(
                    runner, ["docker", "compose"], service="api",
                    expected_tls_mounts={
                        "/run/tls/tls.crt": cert,
                        "/run/tls/tls.key": key,
                    },
                    expected_image=image,
                    expected_network="email-platform-metrics",
                )

        with self.assertRaisesRegex(RotationRuntimeError, "direct network"):
            collect_compose_generation(
                Runner([
                    identifier, identifier, "true", "2026-08-27T00:00:02Z",
                    json.dumps(mounts), image,
                    json.dumps({"email-platform-frontend": {
                        "IPAddress": "172.31.0.12", "NetworkID": network_id,
                    }}),
                ]),
                ["docker", "compose"],
                service="api",
                expected_tls_mounts={
                    "/run/tls/tls.crt": cert,
                    "/run/tls/tls.key": key,
                },
                expected_image=image,
                expected_network="email-platform-metrics",
            )

    def test_compose_recreate_is_explicit_and_cannot_degrade_to_start(self) -> None:
        runner = Runner([])
        force_recreate_compose_service(runner, ["docker", "compose"], service="api")
        self.assertEqual(
            runner.calls[0][-8:],
            ["up", "-d", "--no-deps", "--no-build", "--pull", "never", "--force-recreate", "api"],
        )

    def test_kubernetes_collection_uses_uid_container_id_and_every_ready_pod(self) -> None:
        inventory = {
            "items": [
                _pod("11111111-1111-4111-8111-111111111111", "1", "10.0.0.11"),
                _pod("22222222-2222-4222-8222-222222222222", "2", "10.0.0.12"),
            ]
        }
        runner = Runner([
            json.dumps(inventory),
            json.dumps(inventory["items"][0]), json.dumps(_replicaset()),
            json.dumps(inventory["items"][1]), json.dumps(_replicaset()),
        ])
        snapshots = collect_kubernetes_generation(
            runner, ["kubectl", "--context", "staging"], deployment="api", expected_count=2,
            deployment_uid=DEPLOYMENT_UID, target_revision=9,
        )
        self.assertEqual({item.connect_host for item in snapshots}, {"10.0.0.11", "10.0.0.12"})
        serialized = json.dumps([item.evidence for item in snapshots])
        self.assertNotIn("10.0.0.", serialized)
        self.assertNotIn("pod_name", serialized)

        one_pod = copy.deepcopy(inventory)
        one_pod["items"].pop()
        with self.assertRaisesRegex(RotationRuntimeError, "count"):
            collect_kubernetes_generation(
                Runner([json.dumps(one_pod)]), ["kubectl"], deployment="api", expected_count=2,
                deployment_uid=DEPLOYMENT_UID,
            )

    def test_kubernetes_reconcile_inventory_classifies_mixed_before_unready(self) -> None:
        first = _pod("11111111-1111-4111-8111-111111111111", "1", "10.0.0.11")
        second = _pod("22222222-2222-4222-8222-222222222222", "2", "10.0.0.12")
        second["metadata"]["ownerReferences"][0]["uid"] = (
            "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        )
        second["status"]["conditions"][0]["status"] = "False"
        self.assertEqual(
            classify_kubernetes_reconcile_inventory(
                Runner([json.dumps({"items": [first, second]})]),
                ["kubectl"], deployment="api", expected_count=2,
            ),
            "mixed_replicasets",
        )
        second["metadata"]["ownerReferences"][0]["uid"] = REPLICASET_UID
        self.assertEqual(
            classify_kubernetes_reconcile_inventory(
                Runner([json.dumps({"items": [first, second]})]),
                ["kubectl"], deployment="api", expected_count=2,
            ),
            "pod_unready",
        )

        inventory = {"items": [first]}
        forged = _replicaset()
        forged["metadata"]["ownerReferences"][0]["uid"] = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        with self.assertRaisesRegex(RotationRuntimeError, "ownership"):
            collect_kubernetes_generation(
                Runner([
                    json.dumps({"items": [inventory["items"][0]]}),
                    json.dumps(inventory["items"][0]), json.dumps(forged),
                ]),
                ["kubectl"], deployment="api", expected_count=1,
                deployment_uid=DEPLOYMENT_UID,
            )

    def test_kubernetes_rollout_and_observed_generation_are_both_required(self) -> None:
        ready = _deployment()
        runner = Runner([json.dumps(ready)])
        assert_kubernetes_deployment_ready(runner, ["kubectl"], deployment="api", expected_count=2)
        snapshot = get_kubernetes_deployment_snapshot(
            Runner([json.dumps(ready)]), ["kubectl"], deployment="api", expected_count=2
        )
        self.assertEqual((snapshot.uid, snapshot.generation, snapshot.revision), (DEPLOYMENT_UID, 8, 9))
        stale = copy.deepcopy(ready)
        stale["status"]["observedGeneration"] = 7
        with self.assertRaisesRegex(RotationRuntimeError, "unconfirmed"):
            assert_kubernetes_deployment_ready(
                Runner([json.dumps(stale)]), ["kubectl"], deployment="api", expected_count=2
            )

        mutation = Runner([])
        restart_kubernetes_deployment(
            mutation, ["kubectl", "--context", "staging"], deployment="api"
        )
        wait_kubernetes_rollout_revision(
            mutation, ["kubectl", "--context", "staging"], deployment="api", revision=9
        )
        self.assertEqual(mutation.calls[0][-3:], ["rollout", "restart", "deployment/api"])
        self.assertEqual(mutation.calls[1][-5:], ["rollout", "status", "deployment/api", "--revision=9", "--timeout=10m"])
        pause_kubernetes_deployment(mutation, ["kubectl"], deployment="api")
        self.assertEqual(mutation.calls[2][-3:], ["rollout", "pause", "deployment/api"])

        namespace_uid = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        self.assertEqual(
            get_kubernetes_namespace_uid(
                Runner([json.dumps({"metadata": {"uid": namespace_uid}})]),
                ["kubectl"], namespace="email-platform",
            ),
            namespace_uid,
        )
        assert_kubernetes_uids_absent(
            Runner([json.dumps({"items": [{"metadata": {"uid": "dddddddd-dddd-4ddd-8ddd-dddddddddddd"}}]})]),
            ["kubectl"], old_uids=["11111111-1111-4111-8111-111111111111"],
        )
        with self.assertRaisesRegex(RotationRuntimeError, "still present"):
            assert_kubernetes_uids_absent(
                Runner([json.dumps({"items": [{"metadata": {"uid": "11111111-1111-4111-8111-111111111111"}}]})]),
                ["kubectl"], old_uids=["11111111-1111-4111-8111-111111111111"],
            )

    def test_old_uid_or_container_survival_cannot_masquerade_as_rotation(self) -> None:
        old = collect_kubernetes_generation(
            Runner([
                json.dumps({"items": [_pod("11111111-1111-4111-8111-111111111111", "1", "10.0.0.11")]}),
                json.dumps(_pod("11111111-1111-4111-8111-111111111111", "1", "10.0.0.11")),
                json.dumps(_replicaset()),
            ]),
            ["kubectl"], deployment="api", expected_count=1, deployment_uid=DEPLOYMENT_UID,
        )
        changed_name_only = collect_kubernetes_generation(
            Runner([
                json.dumps({"items": [_pod("11111111-1111-4111-8111-111111111111", "1", "10.0.0.12")]}),
                json.dumps(_pod("11111111-1111-4111-8111-111111111111", "1", "10.0.0.12")),
                json.dumps(_replicaset()),
            ]),
            ["kubectl"], deployment="api", expected_count=1, deployment_uid=DEPLOYMENT_UID,
        )
        with self.assertRaisesRegex(RotationRuntimeError, "fully replaced"):
            assert_generation_replaced(old, changed_name_only, expected_count=1)

    def test_direct_pod_probe_separates_connect_address_without_publishing_it(self) -> None:
        command = kubernetes_probe_command(
            ["kubectl", "--context", "staging"],
            observer="api",
            container="api",
            url="https://api.email-platform.svc:8443/readyz",
            ca_file="/run/secrets/internal-tls/ca.crt",
            connect_host="10.0.0.42",
        )
        self.assertIn("api", command.command)
        self.assertNotIn("deployment/api", command.command)
        self.assertNotIn("10.0.0.42", command.command)
        self.assertNotIn("https://api.email-platform.svc:8443/readyz", command.command)
        self.assertIn("10.0.0.42", command.input_text)
        fingerprint = "a" * 64
        observation = collect_peer_observation(
            Runner([json.dumps({"peer_sha256": fingerprint, "tls_version": "TLSv1.3"})]),
            command,
            phase="after_instance",
            observer="direct-instance",
            instance_id="11111111-1111-4111-8111-111111111111",
            attempt=1,
            expected_sha256=fingerprint,
            observed_at="2026-08-27T00:00:03.123456789Z",
        )
        serialized = json.dumps(observation)
        self.assertNotIn("10.0.0.42", serialized)
        self.assertNotIn("url", serialized.casefold())
        self.assertEqual(observation["observed_at"], "2026-08-27T00:00:03.123456Z")

        compose = compose_probe_command(
            ["docker", "compose"],
            observer="api",
            url="https://worker-mail:9101/metrics",
            ca_file="/run/secrets/internal-tls/ca.crt",
        )
        self.assertEqual(compose.command[2:5], ("exec", "-T", "api"))
        self.assertNotIn("https://worker-mail:9101/metrics", compose.command)


if __name__ == "__main__":
    unittest.main()
