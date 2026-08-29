import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "verify_rollback_assets.py"
SPEC = importlib.util.spec_from_file_location("verify_rollback_assets", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
verify_rollback_assets = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify_rollback_assets
SPEC.loader.exec_module(verify_rollback_assets)


class RollbackAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compose_text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.env_text = (ROOT / ".env.example").read_text(encoding="utf-8")
        self.rollback_text = (ROOT / "scripts/rollback_release.py").read_text(
            encoding="utf-8"
        )

    def errors(self, rollback_text: str | None = None) -> list[str]:
        return verify_rollback_assets.rollback_asset_errors(
            self.compose_text,
            self.env_text,
            self.rollback_text if rollback_text is None else rollback_text,
        )

    def test_repository_image_mapping_is_valid(self) -> None:
        self.assertEqual(
            verify_rollback_assets.rollback_asset_errors(
                self.compose_text, self.env_text
            ),
            [],
        )

    def test_independent_worker_image_variable_is_rejected(self) -> None:
        changed_compose = self.compose_text.replace(
            "  worker-mail:\n"
            "    image: ${PLATFORM_API_IMAGE:?set immutable PLATFORM_API_IMAGE in .env}",
            "  worker-mail:\n"
            "    image: ${PLATFORM_WORKER_MAIL_IMAGE:?set immutable PLATFORM_WORKER_MAIL_IMAGE in .env}",
            1,
        )
        changed_env = self.env_text + "\nPLATFORM_WORKER_MAIL_IMAGE=worker:local\n"

        errors = verify_rollback_assets.rollback_asset_errors(
            changed_compose, changed_env
        )

        self.assertTrue(any("worker-mail image must be" in error for error in errors))
        self.assertTrue(
            any("independent worker image variables" in error for error in errors)
        )

    def test_migrate_cannot_use_a_different_api_image(self) -> None:
        changed_compose = self.compose_text.replace(
            "image: ${PLATFORM_API_IMAGE:?set immutable PLATFORM_API_IMAGE in .env}",
            "image: email-platform-migrate:local",
            1,
        )

        errors = verify_rollback_assets.rollback_asset_errors(
            changed_compose, self.env_text
        )

        self.assertTrue(any("migrate image must be" in error for error in errors))

    def test_required_image_variable_must_be_documented(self) -> None:
        changed_env = self.env_text.replace(
            "PLATFORM_EDGE_IMAGE=\n", ""
        )

        errors = verify_rollback_assets.rollback_asset_errors(
            self.compose_text, changed_env
        )

        self.assertIn(
            ".env.example is missing image variables: PLATFORM_EDGE_IMAGE", errors
        )

    def test_runtime_third_party_digest_validation_cannot_be_bypassed(self) -> None:
        changed = self.rollback_text.replace(
            "_validated_third_party_image_environment(os.environ)",
            "dict(os.environ)",
            1,
        )
        errors = self.errors(changed)
        self.assertTrue(
            any("fail closed on third-party digest injection" in error for error in errors),
            errors,
        )

    def test_process_compose_input_rejection_cannot_be_removed(self) -> None:
        mutations = (
            self.rollback_text.replace(
                "    inherited_compose_inputs =",
                "    inherited_compose_inputs_removed =",
                1,
            ),
            self.rollback_text.replace(
                "    if inherited_compose_inputs:",
                "    if False:",
                1,
            ),
        )
        for changed in mutations:
            with self.subTest(changed=changed):
                self.assertTrue(
                    any("process environment" in error for error in self.errors(changed)),
                    self.errors(changed),
                )

    def test_docker_target_override_contract_is_exact_and_presence_based(self) -> None:
        wrong_inventory = self.rollback_text.replace(
            '    "DOCKER_CONFIG",',
            '    "DOCKER_TLS_VERIFY",',
            1,
        )
        truthiness = self.rollback_text.replace(
            "if any(name in environment for name in FORBIDDEN_DOCKER_TARGET_VARIABLES):",
            "if any(environment.get(name) for name in FORBIDDEN_DOCKER_TARGET_VARIABLES):",
            1,
        )
        removed = self.rollback_text.replace(
            "    if any(name in environment for name in FORBIDDEN_DOCKER_TARGET_VARIABLES):\n"
            '        raise ComposeEnvironmentError("production Compose environment preflight failed")\n',
            "",
            1,
        )
        for changed in (wrong_inventory, truthiness, removed):
            with self.subTest():
                self.assertTrue(
                    any("Docker target" in error for error in self.errors(changed)),
                    self.errors(changed),
                )

    def test_docker_tls_override_contract_is_exact_and_presence_based(self) -> None:
        wrong_inventory = self.rollback_text.replace(
            '    "DOCKER_CERT_PATH",',
            '    "DOCKER_API_VERSION",',
            1,
        )
        truthiness = self.rollback_text.replace(
            "if any(name in environment for name in FORBIDDEN_DOCKER_TLS_VARIABLES):",
            "if any(environment.get(name) for name in FORBIDDEN_DOCKER_TLS_VARIABLES):",
            1,
        )
        removed = self.rollback_text.replace(
            "    if any(name in environment for name in FORBIDDEN_DOCKER_TLS_VARIABLES):\n"
            '        raise ComposeEnvironmentError("production Compose environment preflight failed")\n',
            "",
            1,
        )
        for changed in (wrong_inventory, truthiness, removed):
            with self.subTest():
                self.assertTrue(
                    any("Docker TLS" in error for error in self.errors(changed)),
                    self.errors(changed),
                )

    def test_plaintext_credential_contract_is_exact_and_presence_based(self) -> None:
        wrong_inventory = self.rollback_text.replace(
            '    "PLATFORM_VAULT_SUB2_SECRET_ID",',
            '    "UNREVIEWED_SECRET",',
            1,
        )
        truthiness = self.rollback_text.replace(
            "name in environment for name in FORBIDDEN_PRODUCTION_CREDENTIAL_VARIABLES",
            "environment.get(name) for name in FORBIDDEN_PRODUCTION_CREDENTIAL_VARIABLES",
            1,
        )
        secret_injection = self.rollback_text.replace(
            "    return validated",
            '    validated["VAULT_TOKEN"] = environment["VAULT_TOKEN"]\n    return validated',
            1,
        )
        for changed in (wrong_inventory, truthiness, secret_injection):
            with self.subTest():
                self.assertTrue(
                    any("plaintext credential" in error for error in self.errors(changed)),
                    self.errors(changed),
                )

    def test_subprocess_environment_allowlist_and_explicit_runner_cannot_drift(self) -> None:
        wrong_base = self.rollback_text.replace(
            '    "PROGRAMDATA",', '    "PYTHONPATH",', 1
        )
        full_inheritance = self.rollback_text.replace(
            """    validated = {
        name: environment[name]
        for name in (
            *SUBPROCESS_BASE_ENVIRONMENT_VARIABLES,
            *THIRD_PARTY_IMAGE_DIGEST_VARIABLES,
        )
        if name in environment
    }""",
            "    validated = dict(environment)",
            1,
        )
        missing_runner_guard = self.rollback_text.replace(
            "        if env is None:", "        if False:", 1
        )
        implicit_git_environment = self.rollback_text.replace(
            "            env=environment,\n            capture_output=True,",
            "            capture_output=True,",
            1,
        )
        expanded_pull_environment = self.rollback_text.replace(
            "_pull_images(plan, command_runner, environment)",
            "_pull_images(plan, command_runner, os.environ)",
            1,
        )
        expectations = (
            (wrong_base, "base environment"),
            (full_inheritance, "reviewed allowlist"),
            (missing_runner_guard, "subprocess runner"),
            (implicit_git_environment, "explicit environment"),
            (expanded_pull_environment, "pull, and external smoke"),
        )
        for changed, fragment in expectations:
            with self.subTest(fragment=fragment):
                self.assertTrue(
                    any(fragment in error for error in self.errors(changed)),
                    self.errors(changed),
                )

    def test_github_credential_scope_cannot_expand(self) -> None:
        github_token_to_cosign = self.rollback_text.replace(
            'runner.run(["cosign", "verify", *common, image], env=environment)',
            'runner.run(["cosign", "verify", *common, image], env=gh_environment)',
            1,
        )
        github_token_removed = self.rollback_text.replace(
            "            env=gh_environment,", "            env=environment,", 1
        )
        for changed in (github_token_to_cosign, github_token_removed):
            with self.subTest():
                self.assertTrue(
                    any("GitHub attestation" in error for error in self.errors(changed)),
                    self.errors(changed),
                )

    def test_compose_inputs_must_come_from_authoritative_production_file(self) -> None:
        changed = self.rollback_text.replace(
            "load_unique_yaml_with_text(path)",
            "({}, '')",
            1,
        )
        self.assertTrue(
            any("authoritative production Compose" in error for error in self.errors(changed)),
            self.errors(changed),
        )

    def test_internal_smoke_rejects_shared_contract_import_drift(self) -> None:
        mutations = (
            self.rollback_text.replace("    PROBES,", "    PROBES as OLD_PROBES,", 1),
            self.rollback_text.replace(
                "    TLS_HTTP_PROBE_PROGRAM,", "    TLS_HTTP_PROBE_PROGRAM as OLD_PROGRAM,", 1
            ),
            self.rollback_text.replace(
                "    restore_contract_errors,", "    restore_contract_errors as skip_contract,", 1
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertTrue(self.errors(mutation))

    def test_internal_smoke_rejects_bypassed_contract_or_probe_set(self) -> None:
        skipped_contract = self.rollback_text.replace(
            "contract_errors = restore_contract_errors() + tls_probe_contract_errors()",
            "contract_errors = []",
            1,
        )
        missing_probes = self.rollback_text.replace(
            "for endpoint, url in zip(endpoints, PROBES, strict=True):",
            "for endpoint, url in ():",
            1,
        )
        self.assertTrue(self.errors(skipped_contract))
        self.assertTrue(self.errors(missing_probes))

    def test_internal_smoke_rejects_nonshared_program_or_container(self) -> None:
        unsafe_program = self.rollback_text.replace(
            "                TLS_HTTP_PROBE_PROGRAM,", '                "unsafe",', 1
        )
        wrong_container = self.rollback_text.replace(
            "                PROBE_CONTAINER,", '                "web",', 1
        )
        for mutation in (unsafe_program, wrong_container):
            with self.subTest(mutation=mutation):
                self.assertTrue(self.errors(mutation))

    def test_compose_file_and_project_directory_are_structurally_pinned(self) -> None:
        missing_file = self.rollback_text.replace(
            '        "-f",\n        str(PRODUCTION_COMPOSE),\n',
            "",
            1,
        )
        missing_project = self.rollback_text.replace(
            '        "--project-directory",\n        str(ROOT),\n',
            "",
            1,
        )
        self.assertTrue(any("pin the production" in error for error in self.errors(missing_file)))
        self.assertTrue(any("pin the production" in error for error in self.errors(missing_project)))

        missing_env_file = self.rollback_text.replace(
            '        "--env-file",\n        str(PRODUCTION_ENV_FILE),\n',
            "",
            1,
        )
        missing_project_name = self.rollback_text.replace(
            '        "--project-name",\n        PRODUCTION_PROJECT_NAME,\n',
            "",
            1,
        )
        self.assertTrue(any("pin the production" in error for error in self.errors(missing_env_file)))
        self.assertTrue(any("pin the production" in error for error in self.errors(missing_project_name)))

    def test_checkout_preflight_rejects_override_and_cannot_move_late(self) -> None:
        missing_override = self.rollback_text.replace(
            '        "compose.override.yaml",\n',
            "",
            1,
        )
        missing_compose_file = self.rollback_text.replace('"COMPOSE_FILE"', '"REMOVED_FILE"', 1)
        missing_project_name = self.rollback_text.replace(
            '"COMPOSE_PROJECT_NAME"', '"REMOVED_PROJECT_NAME"', 1
        )
        sanitized_control_check = self.rollback_text.replace(
            "name in shell_environment for name in FORBIDDEN_COMPOSE_CONTROL_VARIABLES",
            "name in environment for name in FORBIDDEN_COMPOSE_CONTROL_VARIABLES",
            1,
        )
        call = """_assert_release_checkout(
            plan.commit,
            runner=command_runner,
            environment=environment,
            shell_environment=os.environ,
        )"""
        moved = self.rollback_text.replace(call, "pass", 1).replace(
            "_pull_images(plan, command_runner, environment)",
            "_pull_images(plan, command_runner, environment)\n        " + call,
            1,
        )
        self.assertTrue(any("every default Compose override" in error for error in self.errors(missing_override)))
        self.assertTrue(any("COMPOSE_FILE" in error for error in self.errors(missing_compose_file)))
        self.assertTrue(
            any("COMPOSE_PROJECT_NAME" in error for error in self.errors(missing_project_name))
        )
        self.assertTrue(
            any(
                "Compose control variables" in error
                for error in self.errors(sanitized_control_check)
            )
        )
        self.assertTrue(any("before supply chain" in error for error in self.errors(moved)))

    def test_operational_service_contract_is_exact(self) -> None:
        for old, new in (("prometheus", "migrate"), ("alertmanager", "vault-dev")):
            with self.subTest(service=old):
                changed = self.rollback_text.replace(f'    "{old}",', f'    "{new}",', 1)
                self.assertTrue(
                    any("exactly the reviewed ten services" in error for error in self.errors(changed))
                )

    def test_rollback_cannot_stop_monitoring_services(self) -> None:
        changed = self.rollback_text.replace(
            '    "edge",\n',
            '    "edge",\n    "prometheus",\n    "alertmanager",\n',
            1,
        )
        self.assertTrue(
            any("keep Prometheus and Alertmanager running" in error for error in self.errors(changed))
        )

    def test_operational_gates_cannot_move_after_restore_or_final_success(self) -> None:
        call = "_assert_operational_services(command_runner, environment)"
        preflight_removed = self.rollback_text.replace(call, "pass", 1)
        final_removed = self.rollback_text[: self.rollback_text.rfind(call)] + self.rollback_text[
            self.rollback_text.rfind(call) :
        ].replace(call, "pass", 1)
        for changed in (preflight_removed, final_removed):
            with self.subTest():
                self.assertTrue(
                    any("operational" in error for error in self.errors(changed))
                )

    def test_public_edge_tls_preflight_cannot_be_removed_or_redirected(self) -> None:
        call = "edge_fingerprint = validate_edge_tls(PRODUCTION_ENV_FILE, domain)"
        mutations = (
            self.rollback_text.replace(call, "pass", 1),
            self.rollback_text.replace(
                call,
                "edge_fingerprint = validate_edge_tls(Path('unreviewed.env'), domain)",
                1,
            ),
            self.rollback_text.replace(
                call,
                "edge_fingerprint = validate_edge_tls(PRODUCTION_ENV_FILE, 'other.example.com')",
                1,
            ),
        )
        for changed in mutations:
            with self.subTest():
                self.assertTrue(
                    any(
                        "public edge TLS preflight" in error
                        for error in self.errors(changed)
                    )
                )

    def test_vault_token_sink_preflights_cannot_drift_or_move(self) -> None:
        call = "validate_vault_token_sinks(PRODUCTION_ENV_FILE, PRODUCTION_COMPOSE)"
        first_removed = self.rollback_text.replace(call, "pass", 1)
        wrong_inventory = self.rollback_text.replace(
            call,
            "validate_vault_token_sinks(Path('unreviewed.env'), PRODUCTION_COMPOSE)",
            1,
        )
        local_replacement = self.rollback_text.replace(
            "def execute_rollback(",
            "def validate_vault_token_sinks(*_args):\n    return None\n\n\ndef execute_rollback(",
            1,
        )
        without_second = (
            self.rollback_text[: self.rollback_text.rfind(call)]
            + self.rollback_text[self.rollback_text.rfind(call) :].replace(call, "pass", 1)
        )
        early_recheck = without_second.replace(
            "    _internal_smoke(command_runner, environment)",
            f"    {call}\n    _internal_smoke(command_runner, environment)",
            1,
        )
        late_initial = self.rollback_text.replace(
            f"    try:\n        {call}\n",
            "    try:\n        pass\n",
            1,
        ).replace(
            "    command_runner = runner or SubprocessRunner()",
            "    command_runner = runner or SubprocessRunner()\n"
            f"    {call}",
            1,
        )
        for changed in (first_removed, wrong_inventory, local_replacement, early_recheck):
            with self.subTest():
                self.assertTrue(
                    any("Vault token sink" in error for error in self.errors(changed))
                )
        self.assertTrue(self.errors(late_initial))

    def test_checkout_uses_manifest_commit_and_direct_compose_is_rejected(self) -> None:
        wrong_commit = self.rollback_text.replace(
            "_assert_release_checkout(\n            plan.commit,",
            "_assert_release_checkout(\n            plan.tag,",
            1,
        )
        direct_compose = self.rollback_text.replace(
            "command_runner = runner or SubprocessRunner()",
            'command_runner = runner or SubprocessRunner()\n        command_runner.run(["docker", "compose", "ps"])',
            1,
        )
        self.assertTrue(any("plan.commit" in error for error in self.errors(wrong_commit)))
        self.assertTrue(any("pinned Compose helper" in error for error in self.errors(direct_compose)))

    def test_write_once_rollback_evidence_controls_cannot_be_removed(self) -> None:
        mutations = (
            self.rollback_text.replace(
                "prepare_evidence_output(evidence_output)", "pass"
            ),
            self.rollback_text.replace(
                "evidence.observed_image(", "evidence.removed_observation("
            ),
            self.rollback_text.replace(
                "TERMINAL_EDGE_UNCONFIRMED", "REMOVED_EDGE_TERMINAL"
            ),
            self.rollback_text.replace('"--evidence-output"', '"--removed-output"', 1),
        )
        for changed in mutations:
            with self.subTest():
                self.assertTrue(
                    any("rollback evidence control" in error for error in self.errors(changed))
                )

    def test_rollback_evidence_ast_control_flow_cannot_be_removed(self) -> None:
        execute_offset = self.rollback_text.index("def execute_rollback(")
        failure_publish = self.rollback_text.index(
            "_publish_evidence(evidence, evidence_output)", execute_offset
        )
        success_publish = self.rollback_text.rindex(
            "_publish_evidence(evidence, evidence_output)"
        )
        success_stop = self.rollback_text.rindex("_stop_edge_for_failure(")

        def rename_call(source: str, offset: int, old: str, new: str) -> str:
            self.assertEqual(source[offset : offset + len(old)], old)
            return source[:offset] + new + source[offset + len(old) :]

        mutations = (
            self.rollback_text.replace("@_serialized_release_control\n", "", 1),
            rename_call(
                self.rollback_text,
                failure_publish,
                "_publish_evidence",
                "_removed_publish",
            ),
            rename_call(
                self.rollback_text,
                success_publish,
                "_publish_evidence",
                "_removed_publish",
            ),
            rename_call(
                self.rollback_text,
                success_stop,
                "_stop_edge_for_failure",
                "_removed_stop_edge",
            ),
        )
        for changed in mutations:
            with self.subTest():
                self.assertTrue(
                    any("rollback evidence AST" in error for error in self.errors(changed))
                )


if __name__ == "__main__":
    unittest.main()
