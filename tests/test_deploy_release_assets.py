from __future__ import annotations

import unittest
from pathlib import Path

from scripts.verify_deploy_release import THIRD_PARTY_IMAGES, deployment_asset_errors


ROOT = Path(__file__).resolve().parents[1]


class DeployReleaseAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.dev_compose = (ROOT / "docker-compose.dev.yml").read_text(encoding="utf-8")
        self.env = (ROOT / ".env.example").read_text(encoding="utf-8")
        self.dev_env = (ROOT / ".env.development.example").read_text(encoding="utf-8")
        self.deploy = (ROOT / "scripts/deploy_release.py").read_text(encoding="utf-8")
        self.upstream_scan = (ROOT / "scripts/scan_third_party_images.py").read_text(
            encoding="utf-8"
        )

    def errors(self, **changes: str) -> list[str]:
        return deployment_asset_errors(
            changes.get("compose", self.compose),
            changes.get("dev_compose", self.dev_compose),
            changes.get("env", self.env),
            changes.get("dev_env", self.dev_env),
            changes.get("deploy", self.deploy),
            changes.get("upstream_scan", self.upstream_scan),
        )

    def test_repository_assets_are_valid(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_phase0_intake_gate_cannot_move_after_evidence_or_lock(self) -> None:
        changed = self.deploy.replace(
            "checkpoint = load_phase_checkpoint(",
            "checkpoint = removed_phase_checkpoint(",
            1,
        )
        self.assertTrue(
            any("Phase 0 target intake" in error for error in self.errors(deploy=changed))
        )

    def test_production_build_and_local_fallback_are_rejected(self) -> None:
        build = self.compose.replace(
            "  api:\n    image:",
            "  api:\n    build: .\n    image:",
            1,
        )
        fallback = self.compose.replace(
            "${PLATFORM_API_IMAGE:?set immutable PLATFORM_API_IMAGE in .env}",
            "${PLATFORM_API_IMAGE:-email-platform-api:local}",
            1,
        )
        self.assertTrue(any("must not contain build" in error for error in self.errors(compose=build)))
        self.assertTrue(any("immutable production image" in error for error in self.errors(compose=fallback)))

    def test_production_env_cannot_supply_mutable_image(self) -> None:
        changed = self.env.replace("PLATFORM_API_IMAGE=\n", "PLATFORM_API_IMAGE=email-platform-api:local\n")
        self.assertTrue(any("must leave PLATFORM_API_IMAGE empty" in error for error in self.errors(env=changed)))

    def test_third_party_production_images_require_digest_fragments(self) -> None:
        mutable_tags = {
            "postgres": "postgres:16-alpine",
            "redis": "redis:7-alpine",
            "keycloak": "quay.io/keycloak/keycloak:26.3",
            "alertmanager": "prom/alertmanager:v0.28.1",
            "prometheus": "prom/prometheus:v2.55.1",
        }
        for service, expected in THIRD_PARTY_IMAGES.items():
            with self.subTest(service=service):
                changed = self.compose.replace(expected, mutable_tags[service], 1)
                errors = self.errors(compose=changed)
                self.assertTrue(
                    any(service in error and "digest" in error for error in errors),
                    errors,
                )
                fallback = self.compose.replace(expected, expected.replace(":?", ":-", 1), 1)
                errors = self.errors(compose=fallback)
                self.assertTrue(
                    any(service in error and "digest" in error for error in errors),
                    errors,
                )

    def test_third_party_digest_examples_must_exist_and_remain_unset(self) -> None:
        for expected in THIRD_PARTY_IMAGES.values():
            variable = expected.split("${", 1)[1].split(":?", 1)[0]
            with self.subTest(variable=variable):
                self.assertIn(f"{variable}=\n", self.env)
                changed = self.env.replace(
                    f"{variable}=\n",
                    f"{variable}={'a' * 64}\n",
                    1,
                )
                errors = self.errors(env=changed)
                self.assertTrue(
                    any(f"must leave {variable} empty" in error for error in errors),
                    errors,
                )
                missing = self.env.replace(f"{variable}=\n", "", 1)
                errors = self.errors(env=missing)
                self.assertTrue(
                    any(f"must leave {variable} empty" in error for error in errors),
                    errors,
                )

    def test_vault_mutable_tag_exception_remains_development_only(self) -> None:
        changed = self.compose.replace('profiles: ["vault-dev"]', 'profiles: ["production"]', 1)
        errors = self.errors(compose=changed)
        self.assertTrue(any("vault-dev profile" in error for error in errors), errors)

    def test_deployment_runtime_digest_validation_cannot_be_bypassed(self) -> None:
        changed = self.deploy.replace(
            "_validated_third_party_image_environment(os.environ)",
            "dict(os.environ)",
            1,
        )
        errors = self.errors(deploy=changed)
        self.assertTrue(any("validate third-party digests" in error for error in errors), errors)

    def test_deployment_must_reuse_process_compose_input_rejection(self) -> None:
        changed = self.deploy.replace(
            "_validated_third_party_image_environment(os.environ)",
            "_validated_third_party_image_environment({})",
            1,
        )
        errors = self.errors(deploy=changed)
        self.assertTrue(any("process environment" in error for error in errors), errors)

    def test_docker_target_preflight_must_precede_every_runner_access(self) -> None:
        changed = self.deploy.replace(
            "            environment = plan.compose_environment()",
            "            _assert_running_services(command_runner, {})\n"
            "            environment = plan.compose_environment()",
            1,
        )
        errors = self.errors(deploy=changed)
        self.assertTrue(
            any("Docker target environment preflight" in error for error in errors),
            errors,
        )

    def test_development_build_is_explicit_and_complete(self) -> None:
        changed = self.dev_compose.replace("  edge:\n", "  removed-edge:\n", 1)
        self.assertTrue(any("exactly the six" in error for error in self.errors(dev_compose=changed)))

    def test_unsafe_compose_up_is_rejected(self) -> None:
        changed = self.deploy.replace('"--no-build",\n                "--pull",\n                "never",', '"--pull",\n                "always",', 1)
        if changed == self.deploy:
            changed = self.deploy.replace(
                '"--no-build",\n                    "--pull",\n                    "never",',
                '"--pull",\n                    "always",',
                1,
            )
        self.assertTrue(any("--no-build --pull never" in error for error in self.errors(deploy=changed)))

    def test_missing_supply_chain_or_runtime_digest_check_is_rejected(self) -> None:
        no_verify = self.deploy.replace(
            "_verify_supply_chain(plan, command_runner, environment)", "pass", 1
        )
        no_runtime = self.deploy.replace(
            "plan.rollback.images[image_name]",
            "plan.images[image_name]",
            1,
        )
        self.assertTrue(any("required release stage" in error for error in self.errors(deploy=no_verify)))
        self.assertTrue(any("required release stage" in error for error in self.errors(deploy=no_runtime)))

    def test_upstream_scan_contract_and_deploy_stage_cannot_drift(self) -> None:
        no_stage = self.deploy.replace(
            "scan_third_party_images(environment, command_runner)",
            "pass",
            1,
        )
        wrong_inventory = self.upstream_scan.replace(
            '"quay.io/keycloak/keycloak"',
            '"unreviewed/keycloak"',
            1,
        )
        open_gate = self.upstream_scan.replace(
            '"--exit-code",\n    "1",',
            '"--exit-code",\n    "0",',
            1,
        )
        no_binding = self.upstream_scan.replace(
            "_validate_sarif(report, reference)",
            "pass",
            1,
        )
        no_scan_environment = self.upstream_scan.replace(
            "                env=environment,\n", "", 1
        )
        self.assertTrue(
            any("required release stage" in error for error in self.errors(deploy=no_stage))
        )
        self.assertTrue(
            any(
                "fixed five-image inventory" in error
                for error in self.errors(upstream_scan=wrong_inventory)
            )
        )
        self.assertTrue(
            any(
                "Trivy command" in error
                for error in self.errors(upstream_scan=open_gate)
            )
        )
        self.assertTrue(
            any(
                "report binding" in error
                for error in self.errors(upstream_scan=no_binding)
            )
        )
        self.assertTrue(
            any(
                "validated environment" in error
                for error in self.errors(upstream_scan=no_scan_environment)
            )
        )

    def test_deployment_subprocess_environment_cannot_expand_or_disappear(self) -> None:
        wrong_supply_environment = self.deploy.replace(
            "_verify_supply_chain(plan.rollback, command_runner, rollback_environment)",
            "_verify_supply_chain(plan.rollback, command_runner, environment)",
            1,
        )
        missing_pull_environment = self.deploy.replace(
            "_pull_images(plan, command_runner, environment)",
            "_pull_images(plan, command_runner)",
            1,
        )
        missing_direct_environment = self.deploy.replace(
            "        command_runner.run(_compose(\"stop\", \"edge\"), env=environment)",
            "        command_runner.run(_compose(\"stop\", \"edge\"))",
            1,
        )
        expectations = (
            (wrong_supply_environment, "supply-chain checks"),
            (missing_pull_environment, "pull and external smoke"),
            (missing_direct_environment, "every deployment runner"),
        )
        for changed, fragment in expectations:
            with self.subTest(fragment=fragment):
                self.assertTrue(
                    any(fragment in error for error in self.errors(deploy=changed)),
                    self.errors(deploy=changed),
                )

    def test_public_edge_tls_preflight_cannot_be_removed_or_redirected(self) -> None:
        missing = self.deploy.replace(
            "edge_fingerprint = validate_edge_tls(PRODUCTION_ENV_FILE, domain)",
            "edge_fingerprint = None",
            1,
        )
        wrong_inventory = self.deploy.replace(
            "edge_fingerprint = validate_edge_tls(PRODUCTION_ENV_FILE, domain)",
            "edge_fingerprint = validate_edge_tls(Path('unreviewed.env'), domain)",
            1,
        )
        wrong_domain = self.deploy.replace(
            "edge_fingerprint = validate_edge_tls(PRODUCTION_ENV_FILE, domain)",
            "edge_fingerprint = validate_edge_tls(PRODUCTION_ENV_FILE, 'other.example.com')",
            1,
        )
        for changed in (missing, wrong_inventory, wrong_domain):
            with self.subTest():
                self.assertTrue(
                    any(
                        "public edge TLS preflight" in error
                        for error in self.errors(deploy=changed)
                    )
                )

    def test_vault_token_sink_preflights_cannot_drift_or_move(self) -> None:
        call = "validate_vault_token_sinks(PRODUCTION_ENV_FILE, PRODUCTION_COMPOSE)"
        first_removed = self.deploy.replace(call, "pass", 1)
        wrong_inventory = self.deploy.replace(
            call,
            "validate_vault_token_sinks(Path('unreviewed.env'), PRODUCTION_COMPOSE)",
            1,
        )
        local_replacement = self.deploy.replace(
            "def execute_deployment(",
            "def validate_vault_token_sinks(*_args):\n    return None\n\n\ndef execute_deployment(",
            1,
        )
        without_second = (
            self.deploy[: self.deploy.rfind(call)]
            + self.deploy[self.deploy.rfind(call) :].replace(call, "pass", 1)
        )
        early_recheck = without_second.replace(
            "            _internal_smoke(\n                command_runner,\n                environment,\n                internal_fingerprints,\n                evidence,\n            )",
            f"            {call}\n"
            "            _internal_smoke(\n                command_runner,\n                environment,\n                internal_fingerprints,\n                evidence,\n            )",
            1,
        )
        late_initial = self.deploy.replace(call, "pass", 1).replace(
            "        command_runner = runner or SubprocessRunner()",
            "        command_runner = runner or SubprocessRunner()\n"
            f"        {call}",
            1,
        )
        for changed in (first_removed, wrong_inventory, local_replacement):
            with self.subTest():
                self.assertTrue(
                    any("Vault token sink" in error for error in self.errors(deploy=changed))
                )
        self.assertTrue(
            any("fail-closed order" in error for error in self.errors(deploy=early_recheck))
        )
        self.assertTrue(
            any("fail-closed order" in error for error in self.errors(deploy=late_initial))
        )

    def test_rollback_plan_loader_and_cli_inputs_are_required(self) -> None:
        no_loader = self.deploy.replace(
            "rollback = load_rollback_plan(",
            "rollback = unreviewed_loader(",
            1,
        )
        no_key = self.deploy.replace(
            'command.add_argument("--rollback-key-file", type=Path, required=True)',
            'command.add_argument("--removed-key-file", type=Path, required=True)',
            1,
        )
        self.assertTrue(any("authenticated rollback point" in error for error in self.errors(deploy=no_loader)))
        self.assertTrue(any("--rollback-key-file" in error for error in self.errors(deploy=no_key)))

    def test_rollback_readiness_cannot_move_after_target_pull(self) -> None:
        changed = self.deploy.replace(
            "_verify_supply_chain(plan.rollback, command_runner, rollback_environment)",
            "pass",
            1,
        ).replace(
            "_pull_images(plan, command_runner, environment)",
            "_pull_images(plan, command_runner, environment)\n"
            "            _verify_supply_chain(plan.rollback, command_runner, rollback_environment)",
            1,
        )
        self.assertTrue(any("fail-closed order" in error for error in self.errors(deploy=changed)))

    def test_operational_gates_are_required_before_mutation_and_final_success(self) -> None:
        preflight_removed = self.deploy.replace(
            "_assert_operational_services(command_runner, rollback_environment)",
            "pass",
            1,
        )
        final_removed = self.deploy.replace(
            "_assert_operational_services(command_runner, environment)",
            "pass",
            1,
        )
        for changed in (preflight_removed, final_removed):
            with self.subTest():
                self.assertTrue(
                    any("operational service contract" in error for error in self.errors(deploy=changed))
                )

    def test_deployment_cannot_stop_monitoring_services(self) -> None:
        changed = self.deploy.replace(
            'command_runner.run(_compose("stop", "edge"), env=environment)',
            'command_runner.run(\n'
            '                _compose("stop", "edge", "prometheus", "alertmanager"),\n'
            '                env=environment,\n'
            '            )',
            1,
        )
        self.assertTrue(
            any("keep Prometheus and Alertmanager running" in error for error in self.errors(deploy=changed))
        )

    def test_release_checkout_preflight_cannot_be_removed_or_moved(self) -> None:
        call = """_assert_release_checkout(
                plan.commit,
                runner=command_runner,
                environment=environment,
                shell_environment=os.environ,
            )"""
        missing = self.deploy.replace(call, "pass", 1)
        moved = self.deploy.replace(call, "pass", 1).replace(
            "_pull_images(plan, command_runner, environment)",
            "_pull_images(plan, command_runner, environment)\n            " + call,
            1,
        )
        self.assertTrue(any("_assert_release_checkout" in error for error in self.errors(deploy=missing)))
        self.assertTrue(any("fail-closed order" in error for error in self.errors(deploy=moved)))

    def test_checkout_must_use_manifest_commit_and_compose_helper(self) -> None:
        wrong_commit = self.deploy.replace(
            "_assert_release_checkout(\n                plan.commit,",
            "_assert_release_checkout(\n                plan.rollback.commit,",
            1,
        )
        direct_compose = self.deploy.replace(
            "        command_runner = runner or SubprocessRunner()",
            '        command_runner = runner or SubprocessRunner()\n'
            '        command_runner.run(["docker", "compose", "ps"])',
            1,
        )
        self.assertTrue(any("plan.commit" in error for error in self.errors(deploy=wrong_commit)))
        self.assertTrue(any("pinned Compose helper" in error for error in self.errors(deploy=direct_compose)))

    def test_edge_cannot_start_before_internal_smoke_or_omit_final_close(self) -> None:
        early_edge = self.deploy.replace(
            "            _internal_smoke(\n                command_runner,\n                environment,\n                internal_fingerprints,\n                evidence,\n            )",
            "            pass",
            1,
        ).replace(
            "            observed_edge = _assert_runtime_image(\n                \"edge\",",
            "            _internal_smoke(\n"
            "                command_runner,\n"
            "                environment,\n"
            "                internal_fingerprints,\n"
            "                evidence,\n"
            "            )\n"
            "            observed_edge = _assert_runtime_image(\n                \"edge\",",
            1,
        )
        no_finally = self.deploy.replace(
            "                closure_unconfirmed = not _stop_edge_for_failure(\n",
            "                closure_unconfirmed = not _removed_stop_edge(\n",
            1,
        )
        self.assertTrue(any("fail-closed order" in error for error in self.errors(deploy=early_edge)))
        self.assertTrue(any("finally" in error for error in self.errors(deploy=no_finally)))

    def test_terminal_evidence_contract_cannot_be_removed_or_moved(self) -> None:
        no_preflight = self.deploy.replace(
            "    try:\n        prepare_evidence_output(evidence_output)",
            "    try:\n        pass",
            1,
        )
        success_publish = "        _publish_evidence(evidence, evidence_output)"
        success_publish_at = self.deploy.rfind(success_publish)
        self.assertGreater(success_publish_at, 0)
        no_success_publish = (
            self.deploy[:success_publish_at]
            + "        pass"
            + self.deploy[success_publish_at + len(success_publish):]
        )
        no_unconfirmed = self.deploy.replace(
            "            TERMINAL_EDGE_UNCONFIRMED",
            "            TERMINAL_EDGE_CLOSED_FAILURE",
            1,
        )
        for changed in (no_preflight, no_success_publish, no_unconfirmed):
            with self.subTest():
                self.assertTrue(
                    any("evidence" in error or "terminal" in error for error in self.errors(deploy=changed)),
                    self.errors(deploy=changed),
                )


if __name__ == "__main__":
    unittest.main()
