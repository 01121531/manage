from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest
from unittest import mock

import yaml

from scripts.verify_kubernetes_portability import (
    KUBERNETES_ROOT,
    deployment_alignment_errors,
    load_documents,
    main,
    verification_errors,
)


class KubernetesPortabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.documents = load_documents(KUBERNETES_ROOT)

    def test_repository_baseline_is_complete_and_fail_closed(self) -> None:
        self.assertEqual(verification_errors(), [])
        self.assertEqual(deployment_alignment_errors(self.documents), [])
        gate = Path("scripts/quality_gate.ps1").read_text(encoding="utf-8")
        self.assertIn("python scripts/verify_kubernetes_portability.py", gate)

    def test_overlay_handoff_requires_matching_phase0_manifest_and_environment(self) -> None:
        manifest = Path("D:/external/target-intake.json")
        with mock.patch(
            "scripts.verify_kubernetes_portability.phase_checkpoint_errors",
            return_value=[],
        ) as validator:
            self.assertEqual(
                main(
                    [
                        "--target-intake-manifest",
                        str(manifest),
                        "--target-environment",
                        "staging",
                    ]
                ),
                0,
            )
        validator.assert_called_once_with(
            manifest,
            environment="staging",
            through_phase=0,
        )
        self.assertEqual(main(["--target-environment", "staging"]), 2)

    def test_compose_commands_and_portable_environment_defaults_cannot_drift(self) -> None:
        mutated = copy.deepcopy(self.documents)
        mail = next(
            item
            for item in mutated
            if item.get("kind") == "Deployment"
            and item["metadata"]["name"] == "worker-mail"
        )
        mail["spec"]["template"]["spec"]["containers"][0]["command"] = [
            "python",
            "-m",
            "infra.worker",
        ]
        errors = deployment_alignment_errors(mutated)
        self.assertTrue(any("command has drifted" in error for error in errors), errors)

        baseline_mail = next(
            item
            for item in self.documents
            if item.get("kind") == "Deployment"
            and item["metadata"]["name"] == "worker-mail"
        )
        self.assertEqual(baseline_mail["spec"]["strategy"], {"type": "Recreate"})

        overlapping_mail_workers = copy.deepcopy(self.documents)
        mail = next(
            item
            for item in overlapping_mail_workers
            if item.get("kind") == "Deployment"
            and item["metadata"]["name"] == "worker-mail"
        )
        mail["spec"]["strategy"] = {
            "type": "RollingUpdate",
            "rollingUpdate": {"maxUnavailable": 1, "maxSurge": 1},
        }
        errors = verification_errors(overlapping_mail_workers)
        self.assertTrue(any("RollingUpdate" in error for error in errors), errors)

        baseline_sub2 = next(
            item
            for item in self.documents
            if item.get("kind") == "Deployment"
            and item["metadata"]["name"] == "worker-sub2"
        )
        self.assertEqual(baseline_sub2["spec"]["strategy"], {"type": "Recreate"})

        overlapping_sub2_workers = copy.deepcopy(self.documents)
        sub2 = next(
            item
            for item in overlapping_sub2_workers
            if item.get("kind") == "Deployment"
            and item["metadata"]["name"] == "worker-sub2"
        )
        sub2["spec"]["strategy"] = {
            "type": "RollingUpdate",
            "rollingUpdate": {"maxUnavailable": 1, "maxSurge": 1},
        }
        errors = verification_errors(overlapping_sub2_workers)
        self.assertTrue(any("worker-sub2" in error for error in errors), errors)

        mutated = copy.deepcopy(self.documents)
        sub2_config = next(
            item
            for item in mutated
            if item.get("kind") == "ConfigMap"
            and item["metadata"]["name"] == "platform-sub2-config"
        )
        sub2_config["data"]["PLATFORM_SUB2_CONCURRENCY"] = "40"
        errors = deployment_alignment_errors(mutated)
        self.assertTrue(any("portable defaults" in error for error in errors), errors)

    def test_release_and_target_intake_dependencies_cannot_be_detached(self) -> None:
        compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
        release = json.loads(
            Path("deploy/release-manifest.json").read_text(encoding="utf-8")
        )
        intake = json.loads(
            Path("deploy/target-intake-requirements.json").read_text(encoding="utf-8")
        )

        drifted_release = copy.deepcopy(release)
        drifted_release["compose_images"].pop("web")
        errors = deployment_alignment_errors(
            self.documents,
            compose=compose,
            release_manifest=drifted_release,
            target_requirements=intake,
        )
        self.assertTrue(any("release image inventory" in error for error in errors), errors)

        drifted_intake = copy.deepcopy(intake)
        drifted_intake["requirements"] = [
            item
            for item in drifted_intake["requirements"]
            if item["id"] != "target_platform_inventory"
        ]
        errors = deployment_alignment_errors(
            self.documents,
            compose=compose,
            release_manifest=release,
            target_requirements=drifted_intake,
        )
        self.assertTrue(any("target intake dependencies" in error for error in errors), errors)

    def test_platform_workloads_are_independently_scalable_and_hardened(self) -> None:
        deployments = {
            document["metadata"]["name"]: document
            for document in self.documents
            if document.get("kind") == "Deployment"
        }
        self.assertEqual(
            set(deployments), {"api", "web", "worker-mail", "worker-sub2"}
        )
        for name, deployment in deployments.items():
            with self.subTest(name=name):
                self.assertGreaterEqual(deployment["spec"]["replicas"], 2)
                pod_spec = deployment["spec"]["template"]["spec"]
                self.assertFalse(pod_spec["automountServiceAccountToken"])
                self.assertEqual(
                    pod_spec["securityContext"]["seccompProfile"]["type"],
                    "RuntimeDefault",
                )
                container = pod_spec["containers"][0]
                self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
                self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])
                self.assertEqual(
                    container["securityContext"]["capabilities"]["drop"], ["ALL"]
                )

    def test_plaintext_secret_objects_and_secret_environment_values_are_rejected(self) -> None:
        secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "forbidden"},
            "stringData": {"database-url": "postgresql://user:password@db/app"},
        }
        errors = verification_errors([*copy.deepcopy(self.documents), secret])
        self.assertTrue(any("must not contain Secret objects" in error for error in errors), errors)

        mutated = copy.deepcopy(self.documents)
        api = next(
            item
            for item in mutated
            if item.get("kind") == "Deployment"
            and item["metadata"]["name"] == "api"
        )
        api["spec"]["template"]["spec"]["containers"][0]["env"].append(
            {"name": "PLATFORM_DATABASE_URL", "value": "postgresql://inline"}
        )
        errors = verification_errors(mutated)
        self.assertTrue(any("forbidden inline secret setting" in error for error in errors), errors)

    def test_secret_key_whitelists_and_internal_service_boundary_cannot_drift(self) -> None:
        mutated = copy.deepcopy(self.documents)
        api = next(
            item
            for item in mutated
            if item.get("kind") == "Deployment"
            and item["metadata"]["name"] == "api"
        )
        runtime = next(
            volume
            for volume in api["spec"]["template"]["spec"]["volumes"]
            if volume["name"] == "runtime"
        )
        runtime["secret"]["secretName"] = "platform-mail-runtime"
        errors = verification_errors(mutated)
        self.assertTrue(any("external secret references" in error for error in errors), errors)

        mutated = copy.deepcopy(self.documents)
        service = next(
            item
            for item in mutated
            if item.get("kind") == "Service" and item["metadata"]["name"] == "api"
        )
        service["spec"]["type"] = "LoadBalancer"
        errors = verification_errors(mutated)
        self.assertTrue(any("internal ClusterIP" in error for error in errors), errors)

    def test_tls_secret_mount_and_rollout_contract_cannot_drift(self) -> None:
        mutations = []

        missing_mount = copy.deepcopy(self.documents)
        api = next(item for item in missing_mount if item.get("kind") == "Deployment" and item["metadata"]["name"] == "api")
        api["spec"]["template"]["spec"]["containers"][0]["volumeMounts"] = [
            mount for mount in api["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
            if mount.get("subPath") != "tls.key"
        ]
        mutations.append((missing_mount, "TLS mount"))

        wrong_subpath = copy.deepcopy(self.documents)
        api = next(item for item in wrong_subpath if item.get("kind") == "Deployment" and item["metadata"]["name"] == "api")
        next(mount for mount in api["spec"]["template"]["spec"]["containers"][0]["volumeMounts"] if mount.get("subPath") == "tls.crt")["subPath"] = "replacement.crt"
        mutations.append((wrong_subpath, "TLS mount"))

        writable_mount = copy.deepcopy(self.documents)
        api = next(item for item in writable_mount if item.get("kind") == "Deployment" and item["metadata"]["name"] == "api")
        next(mount for mount in api["spec"]["template"]["spec"]["containers"][0]["volumeMounts"] if mount.get("subPath") == "ca.crt")["readOnly"] = False
        mutations.append((writable_mount, "TLS mount"))

        wrong_item_path = copy.deepcopy(self.documents)
        api = next(item for item in wrong_item_path if item.get("kind") == "Deployment" and item["metadata"]["name"] == "api")
        volume = next(item for item in api["spec"]["template"]["spec"]["volumes"] if item["name"] == "internal-tls")
        volume["secret"]["items"][0]["path"] = "replacement.crt"
        mutations.append((wrong_item_path, "key/path"))

        wrong_mode = copy.deepcopy(self.documents)
        api = next(item for item in wrong_mode if item.get("kind") == "Deployment" and item["metadata"]["name"] == "api")
        volume = next(item for item in api["spec"]["template"]["spec"]["volumes"] if item["name"] == "internal-ca")
        volume["secret"]["defaultMode"] = 420
        mutations.append((wrong_mode, "secret volume schema"))

        optional_secret = copy.deepcopy(self.documents)
        api = next(item for item in optional_secret if item.get("kind") == "Deployment" and item["metadata"]["name"] == "api")
        volume = next(item for item in api["spec"]["template"]["spec"]["volumes"] if item["name"] == "internal-ca")
        volume["secret"]["optional"] = True
        mutations.append((optional_secret, "secret volume schema"))

        unsafe_rollout = copy.deepcopy(self.documents)
        api = next(item for item in unsafe_rollout if item.get("kind") == "Deployment" and item["metadata"]["name"] == "api")
        api["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"] = 1
        mutations.append((unsafe_rollout, "RollingUpdate"))

        for documents, message in mutations:
            with self.subTest(message=message):
                errors = verification_errors(documents)
                self.assertTrue(any(message in error for error in errors), errors)

    def test_schema_gate_and_release_bound_migration_cannot_be_removed(self) -> None:
        mutated = copy.deepcopy(self.documents)
        api = next(
            item
            for item in mutated
            if item.get("kind") == "Deployment"
            and item["metadata"]["name"] == "api"
        )
        api["spec"]["template"]["spec"]["initContainers"] = []
        errors = verification_errors(mutated)
        self.assertTrue(any("schema-current init container" in error for error in errors), errors)

        mutated = copy.deepcopy(self.documents)
        job = next(item for item in mutated if item.get("kind") == "Job")
        job["metadata"]["annotations"].pop("email-platform.io/release-bound")
        errors = verification_errors(mutated)
        self.assertTrue(any("release-bound migration" in error for error in errors), errors)

    def test_network_policy_cannot_be_broadened_to_all_destinations(self) -> None:
        mutated = copy.deepcopy(self.documents)
        policy = next(
            item
            for item in mutated
            if item.get("kind") == "NetworkPolicy"
            and item["metadata"]["name"] == "api-egress"
        )
        policy["spec"]["egress"].append(
            {"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}
        )
        errors = verification_errors(mutated)
        self.assertTrue(any("broad egress CIDR" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
