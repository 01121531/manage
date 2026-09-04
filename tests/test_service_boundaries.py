import copy
import unittest
from pathlib import Path

import yaml

from scripts.verify_service_boundaries import validate_service_boundaries


class ServiceBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compose = yaml.safe_load(
            Path("docker-compose.yml").read_text(encoding="utf-8")
        )

    def validate(self, compose: dict | None = None) -> list[str]:
        return validate_service_boundaries(self.compose if compose is None else compose)

    @staticmethod
    def networks(compose: dict, service: str) -> set[str]:
        value = compose["services"][service]["networks"]
        return set(value if isinstance(value, list) else value)

    def test_repository_network_paths_are_available_and_data_is_isolated(self) -> None:
        self.assertEqual(self.validate(), [])
        required_pairs = {
            ("edge", target) for target in ("web", "api", "keycloak")
        }
        required_pairs.update(
            (client, "postgres")
            for client in ("api", "keycloak", "worker-mail", "worker-sub2")
        )
        required_pairs.update((client, "redis") for client in ("api", "worker-sub2"))
        required_pairs.update(
            (client, "vault") for client in ("api", "worker-mail", "worker-sub2")
        )
        required_pairs.update(
            ("prometheus", target)
            for target in ("api", "keycloak", "worker-mail", "worker-sub2")
        )
        required_pairs.add(("prometheus", "alertmanager"))
        for source, target in required_pairs:
            with self.subTest(source=source, target=target):
                self.assertTrue(
                    self.networks(self.compose, source)
                    & self.networks(self.compose, target)
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
            for data_service in data_plane:
                with self.subTest(
                    public_service=public_service,
                    data_service=data_service,
                ):
                    self.assertFalse(
                    self.networks(self.compose, public_service)
                    & self.networks(self.compose, data_service)
                )

    def test_user_facing_nonproduction_email_examples_use_invalid_domain(self) -> None:
        examples = {
            "frontend/src/App.tsx": (
                'placeholder="name@example.invalid"',
                'placeholder="name@example.com"',
            ),
            "frontend/src/views/MailboxesView.tsx": (
                'm***@example.invalid',
                'm***@example.com',
            ),
            "platform/README.md": (
                '--email user@example.invalid',
                '--email user@example.com',
            ),
        }
        for path, (required, forbidden) in examples.items():
            with self.subTest(path=path):
                source = Path(path).read_text(encoding="utf-8")
                self.assertIn(required, source)
                self.assertNotIn(forbidden, source)

    def test_data_stores_have_separate_internal_networks(self) -> None:
        expected = {
            "postgres": {"postgres-backend"},
            "redis": {"redis-backend"},
            "vault": {"vault-backend"},
            "migrate": {"postgres-backend"},
        }
        for network in ("postgres-backend", "redis-backend", "vault-backend"):
            with self.subTest(network=network):
                self.assertIs(self.compose["networks"][network].get("internal"), True)
        for service, networks in expected.items():
            with self.subTest(service=service):
                self.assertEqual(self.networks(self.compose, service), networks)

    def test_sub2_worker_waits_for_healthy_shared_concurrency_store(self) -> None:
        compose = copy.deepcopy(self.compose)
        compose["services"]["worker-sub2"]["depends_on"].pop("redis")
        errors = self.validate(compose)
        self.assertTrue(
            any("healthy Redis concurrency storage" in error for error in errors),
            errors,
        )

    def test_data_network_external_gateway_mutations_are_rejected(self) -> None:
        for network in ("postgres-backend", "redis-backend", "vault-backend"):
            for value in (False, None):
                compose = copy.deepcopy(self.compose)
                if value is None:
                    compose["networks"][network].pop("internal")
                else:
                    compose["networks"][network]["internal"] = value
                with self.subTest(network=network, value=value):
                    errors = self.validate(compose)
                    self.assertTrue(
                        any(
                            f"{network} network must be internal" in error
                            for error in errors
                        ),
                        errors,
                    )

    def test_workers_cannot_publish_metrics_or_other_host_ports(self) -> None:
        for service, port in (("worker-mail", "9101:9101"), ("worker-sub2", "9102:9102")):
            compose = copy.deepcopy(self.compose)
            compose["services"][service]["ports"] = [port]
            with self.subTest(service=service):
                errors = self.validate(compose)
                self.assertTrue(
                    any(f"{service} must not publish a host port" in error for error in errors),
                    errors,
                )

    def test_monitoring_control_plane_is_isolated_from_data_services(self) -> None:
        data_only_services = {"postgres", "redis", "vault", "migrate"}
        for monitoring_service in ("prometheus", "alertmanager"):
            for data_service in data_only_services:
                with self.subTest(
                    monitoring_service=monitoring_service,
                    data_service=data_service,
                ):
                    self.assertFalse(
                        self.networks(self.compose, monitoring_service)
                        & self.networks(self.compose, data_service)
                    )

    def test_alertmanager_network_is_reachable_only_from_prometheus(self) -> None:
        alerting_networks = self.networks(self.compose, "alertmanager")
        self.assertEqual(alerting_networks, {"alerting"})
        for service in self.compose["services"]:
            if service in {"alertmanager", "prometheus"}:
                continue
            with self.subTest(service=service):
                self.assertFalse(
                    alerting_networks & self.networks(self.compose, service)
                )

    def test_frontend_services_cannot_rejoin_the_data_network(self) -> None:
        mutations = {
            "edge": "postgres-backend",
            "web": "redis-backend",
            "postgres": "frontend",
            "redis": "frontend",
            "worker-mail": "frontend",
            "worker-sub2": "frontend",
        }
        for service, added_network in mutations.items():
            compose = copy.deepcopy(self.compose)
            compose["services"][service]["networks"].append(added_network)
            with self.subTest(service=service, network=added_network):
                errors = self.validate(compose)
                self.assertTrue(
                    any(f"{service} networks must be exactly" in error for error in errors),
                    errors,
                )

    def test_required_multi_network_service_paths_cannot_be_removed(self) -> None:
        mutations = (
            ("api", "frontend"),
            ("api", "postgres-backend"),
            ("api", "redis-backend"),
            ("api", "vault-backend"),
            ("api", "metrics"),
            ("keycloak", "frontend"),
            ("keycloak", "postgres-backend"),
            ("keycloak", "metrics"),
            ("worker-mail", "postgres-backend"),
            ("worker-mail", "vault-backend"),
            ("worker-mail", "metrics"),
            ("worker-sub2", "postgres-backend"),
            ("worker-sub2", "redis-backend"),
            ("worker-sub2", "vault-backend"),
            ("worker-sub2", "metrics"),
            ("prometheus", "metrics"),
            ("prometheus", "alerting"),
        )
        for service, removed_network in mutations:
            compose = copy.deepcopy(self.compose)
            compose["services"][service]["networks"].remove(removed_network)
            with self.subTest(service=service, network=removed_network):
                errors = self.validate(compose)
                self.assertTrue(
                    any(f"{service} networks must be exactly" in error for error in errors),
                    errors,
                )

    def test_missing_network_is_rejected_for_every_service(self) -> None:
        for service in self.compose["services"]:
            compose = copy.deepcopy(self.compose)
            compose["services"][service].pop("networks")
            with self.subTest(service=service):
                errors = self.validate(compose)
                self.assertTrue(
                    any(f"{service} networks must be exactly" in error for error in errors),
                    errors,
                )

    def test_host_network_mode_is_rejected_for_every_service(self) -> None:
        for service in self.compose["services"]:
            compose = copy.deepcopy(self.compose)
            compose["services"][service]["network_mode"] = "host"
            with self.subTest(service=service):
                errors = self.validate(compose)
                self.assertTrue(
                    any(f"{service} must not set network_mode" in error for error in errors),
                    errors,
                )

    def test_missing_or_extra_declared_network_is_rejected(self) -> None:
        missing = copy.deepcopy(self.compose)
        missing["networks"].pop("frontend")
        missing_errors = self.validate(missing)
        self.assertTrue(
            any("network declarations do not match" in error for error in missing_errors),
            missing_errors,
        )

        extra = copy.deepcopy(self.compose)
        extra["networks"]["shared"] = {"driver": "bridge"}
        extra["services"]["edge"]["networks"].append("shared")
        extra["services"]["postgres"]["networks"].append("shared")
        extra_errors = self.validate(extra)
        self.assertTrue(
            any("network declarations do not match" in error for error in extra_errors),
            extra_errors,
        )
        self.assertTrue(
            any("edge must be isolated from postgres" in error for error in extra_errors),
            extra_errors,
        )

    def test_monitoring_lateral_paths_are_structurally_rejected(self) -> None:
        mutations = (
            ("prometheus", "postgres-backend"),
            ("alertmanager", "redis-backend"),
            ("api", "alerting"),
            ("keycloak", "alerting"),
            ("worker-mail", "alerting"),
            ("worker-sub2", "alerting"),
        )
        for service, network in mutations:
            compose = copy.deepcopy(self.compose)
            compose["services"][service]["networks"].append(network)
            with self.subTest(service=service, network=network):
                errors = self.validate(compose)
                self.assertTrue(
                    any("Forbidden network path exists" in error for error in errors),
                    errors,
                )

    def test_existing_secret_environment_boundaries_remain_enforced(self) -> None:
        api_leak = copy.deepcopy(self.compose)
        api_leak["services"]["api"]["environment"]["PLATFORM_MAIL_API_URL"] = (
            "https://mail.example.invalid"
        )
        api_errors = self.validate(api_leak)
        self.assertTrue(
            any("API service must not carry" in error for error in api_errors),
            api_errors,
        )

        missing_worker_secret = copy.deepcopy(self.compose)
        missing_worker_secret["services"]["worker-sub2"]["environment"].pop(
            "PLATFORM_SUB2_CREDENTIAL_REF"
        )
        worker_errors = self.validate(missing_worker_secret)
        self.assertTrue(
            any("must carry PLATFORM_SUB2_CREDENTIAL_REF" in error for error in worker_errors),
            worker_errors,
        )

    def test_sub2_admin_inputs_belong_only_to_sub2_worker(self) -> None:
        admin_keys = {
            "PLATFORM_SUB2_ADMIN_BASE_URL",
            "PLATFORM_SUB2_ADMIN_API_KEY_REF",
            "PLATFORM_SUB2_ADMIN_PROXY_ID",
            "PLATFORM_SUB2_ADMIN_MODEL_MAPPING_FILE",
        }
        api_env = self.compose["services"]["api"]["environment"]
        worker_env = self.compose["services"]["worker-sub2"]["environment"]
        self.assertFalse(admin_keys & set(api_env))
        self.assertTrue(admin_keys.issubset(worker_env))

        for key in admin_keys:
            missing = copy.deepcopy(self.compose)
            missing["services"]["worker-sub2"]["environment"].pop(key)
            with self.subTest(missing=key):
                errors = self.validate(missing)
                self.assertTrue(
                    any("Sub2 admin" in error for error in errors),
                    errors,
                )

            leaked = copy.deepcopy(self.compose)
            leaked["services"]["api"]["environment"][key] = worker_env[key]
            with self.subTest(leaked=key):
                errors = self.validate(leaked)
                self.assertTrue(
                    any("API service must not carry" in error for error in errors),
                    errors,
                )

    def test_sub2_admin_model_mapping_is_external_read_only_input(self) -> None:
        worker = self.compose["services"]["worker-sub2"]
        expected_target = "/run/config/sub2/admin-model-mapping.json"
        mappings = [
            volume
            for volume in worker["volumes"]
            if volume.get("target") == expected_target
        ]
        self.assertEqual(len(mappings), 1)
        self.assertTrue(mappings[0]["read_only"])
        self.assertFalse(mappings[0]["bind"]["create_host_path"])

        writable = copy.deepcopy(self.compose)
        mapping = next(
            volume
            for volume in writable["services"]["worker-sub2"]["volumes"]
            if volume.get("target") == expected_target
        )
        mapping["read_only"] = False
        self.assertTrue(
            any("model mapping volume" in error for error in self.validate(writable))
        )

    def test_api_and_sub2_worker_share_only_the_server_owned_policy_inputs(self) -> None:
        policy_keys = {
            "PLATFORM_SUB2_POLICY_VERSION",
            "PLATFORM_SUB2_GROUP_ID",
            "PLATFORM_SUB2_CONCURRENCY",
            "PLATFORM_SUB2_PROXY_REF",
            "PLATFORM_SUB2_CREDENTIAL_REF",
            "PLATFORM_SUB2_UPLOAD_URL",
        }
        api_env = self.compose["services"]["api"]["environment"]
        worker_env = self.compose["services"]["worker-sub2"]["environment"]
        self.assertEqual(
            {key: api_env.get(key) for key in policy_keys},
            {key: worker_env.get(key) for key in policy_keys},
        )

        mutated = copy.deepcopy(self.compose)
        mutated["services"]["api"]["environment"][
            "PLATFORM_SUB2_CONCURRENCY"
        ] = "${PLATFORM_SUB2_CONCURRENCY:-99}"
        errors = self.validate(mutated)
        self.assertTrue(any("Sub2 policy inputs" in error for error in errors), errors)

    def test_sub2_allowlist_file_identity_is_fixed_and_read_only(self) -> None:
        worker = self.compose["services"]["worker-sub2"]
        self.assertEqual(
            worker["environment"]["PLATFORM_SUB2_ALLOWED_ORIGINS_FILE"],
            "/run/config/sub2/allowed-origins",
        )
        expected = {
            "type": "bind",
            "source": "${PLATFORM_SUB2_ALLOWED_ORIGINS_FILE:?set PLATFORM_SUB2_ALLOWED_ORIGINS_FILE in .env}",
            "target": "/run/config/sub2/allowed-origins",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
        self.assertEqual(
            [volume for volume in worker["volumes"] if volume.get("target") == expected["target"]],
            [expected],
        )

        mutations: list[dict] = []
        missing_env = copy.deepcopy(self.compose)
        missing_env["services"]["worker-sub2"]["environment"].pop(
            "PLATFORM_SUB2_ALLOWED_ORIGINS_FILE"
        )
        mutations.append(missing_env)

        wrong_env = copy.deepcopy(self.compose)
        wrong_env["services"]["worker-sub2"]["environment"][
            "PLATFORM_SUB2_ALLOWED_ORIGINS_FILE"
        ] = "/tmp/allowed-origins"
        mutations.append(wrong_env)

        for field, value in (
            ("source", "./allowed-origins"),
            ("target", "/tmp/allowed-origins"),
            ("read_only", False),
            ("bind", {"create_host_path": True}),
        ):
            compose = copy.deepcopy(self.compose)
            volume = next(
                item
                for item in compose["services"]["worker-sub2"]["volumes"]
                if item.get("target") == "/run/config/sub2/allowed-origins"
            )
            volume[field] = value
            mutations.append(compose)

        missing_volume = copy.deepcopy(self.compose)
        missing_volume["services"]["worker-sub2"]["volumes"] = [
            item
            for item in missing_volume["services"]["worker-sub2"]["volumes"]
            if item.get("target") != "/run/config/sub2/allowed-origins"
        ]
        mutations.append(missing_volume)

        for compose in mutations:
            with self.subTest():
                self.assertTrue(
                    any("allowed origins" in error.lower() for error in self.validate(compose)),
                    self.validate(compose),
                )

    def test_mail_allowlist_file_identity_is_fixed_and_read_only(self) -> None:
        worker = self.compose["services"]["worker-mail"]
        self.assertEqual(
            worker["environment"]["PLATFORM_MAIL_ALLOWED_ORIGINS_FILE"],
            "/run/config/mail/allowed-origins",
        )
        expected = {
            "type": "bind",
            "source": "${PLATFORM_MAIL_ALLOWED_ORIGINS_FILE:?set PLATFORM_MAIL_ALLOWED_ORIGINS_FILE in .env}",
            "target": "/run/config/mail/allowed-origins",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
        self.assertEqual(
            [volume for volume in worker["volumes"] if volume.get("target") == expected["target"]],
            [expected],
        )

        mutations: list[dict] = []
        missing_env = copy.deepcopy(self.compose)
        missing_env["services"]["worker-mail"]["environment"].pop(
            "PLATFORM_MAIL_ALLOWED_ORIGINS_FILE"
        )
        mutations.append(missing_env)

        wrong_env = copy.deepcopy(self.compose)
        wrong_env["services"]["worker-mail"]["environment"][
            "PLATFORM_MAIL_ALLOWED_ORIGINS_FILE"
        ] = "/tmp/allowed-origins"
        mutations.append(wrong_env)

        for field, value in (
            ("source", "./allowed-origins"),
            ("target", "/tmp/allowed-origins"),
            ("read_only", False),
            ("bind", {"create_host_path": True}),
        ):
            compose = copy.deepcopy(self.compose)
            volume = next(
                item
                for item in compose["services"]["worker-mail"]["volumes"]
                if item.get("target") == "/run/config/mail/allowed-origins"
            )
            volume[field] = value
            mutations.append(compose)

        missing_volume = copy.deepcopy(self.compose)
        missing_volume["services"]["worker-mail"]["volumes"] = [
            item
            for item in missing_volume["services"]["worker-mail"]["volumes"]
            if item.get("target") != "/run/config/mail/allowed-origins"
        ]
        mutations.append(missing_volume)

        for compose in mutations:
            with self.subTest():
                errors = self.validate(compose)
                self.assertTrue(
                    any("mail allowed origins" in error.lower() for error in errors),
                    errors,
                )


if __name__ == "__main__":
    unittest.main()
