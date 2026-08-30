import copy
import unittest
from pathlib import Path

import yaml

from scripts.verify_ci_workflow import (
    APPROVED_EXTERNAL_ACTIONS,
    CI_READ_ONLY_PERMISSIONS,
    POSIX_TLS_BOUNDARY_COMMAND,
    POSIX_TLS_BOUNDARY_STEP,
    verification_errors,
)


class CiWorkflowTests(unittest.TestCase):
    def test_repository_forces_lf_for_exact_byte_ci_contracts(self) -> None:
        attributes = Path(".gitattributes").read_bytes()
        self.assertTrue(attributes.startswith(b"* text=auto eol=lf\n"))
        self.assertNotIn(b"\r\n", attributes)

    @staticmethod
    def workflow() -> dict:
        loaded = yaml.safe_load(
            Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        )
        assert isinstance(loaded, dict)
        return loaded

    @staticmethod
    def workflow_text(workflow: dict) -> str:
        return yaml.safe_dump(workflow, sort_keys=False)

    def test_ci_builds_and_uploads_verified_windows_release(self) -> None:
        self.assertEqual(verification_errors(), [])

    def test_every_checkout_disables_persisted_credentials(self) -> None:
        original = self.workflow()
        for job_name, job in original["jobs"].items():
            checkout_indexes = [
                index
                for index, step in enumerate(job.get("steps", []))
                if isinstance(step, dict)
                and str(step.get("uses", "")).startswith("actions/checkout@")
            ]
            for index in checkout_indexes:
                for unsafe in (None, True, "false"):
                    mutated = copy.deepcopy(original)
                    checkout = mutated["jobs"][job_name]["steps"][index]
                    if unsafe is None:
                        checkout.pop("with", None)
                    else:
                        checkout.setdefault("with", {})["persist-credentials"] = unsafe
                    with self.subTest(job=job_name, unsafe=unsafe):
                        errors = verification_errors(self.workflow_text(mutated))
                        self.assertTrue(
                            any("persist-credentials" in error for error in errors),
                            errors,
                        )

        with_extra_input = copy.deepcopy(original)
        with_extra_input["jobs"]["quality-gate"]["steps"][0]["with"][
            "fetch-depth"
        ] = 0
        self.assertEqual(
            verification_errors(self.workflow_text(with_extra_input)), []
        )

    def test_windows_release_installs_platform_test_dependencies(self) -> None:
        workflow_path = ".github/workflows/ci.yml"
        with open(workflow_path, encoding="utf-8") as workflow_file:
            workflow = workflow_file.read()
        self.assertIn("-r platform/requirements-test.txt", workflow)

    def test_ci_uploads_verified_phase6_rehearsal_evidence(self) -> None:
        with open(".github/workflows/ci.yml", encoding="utf-8") as workflow_file:
            workflow = workflow_file.read()
        with open("scripts/quality_gate.ps1", encoding="utf-8") as gate_file:
            quality_gate = gate_file.read()
        self.assertIn("phase6-ci-rehearsal-${{ github.sha }}", workflow)
        self.assertIn("phase6_rehearsal.py run", quality_gate)
        self.assertIn("phase6_rehearsal.py verify", quality_gate)

        missing_external_output = workflow.replace(
            "          PHASE6_EVIDENCE_OUTPUT: ${{ runner.temp }}/phase6-ci-rehearsal-${{ github.sha }}.json\n",
            "",
            1,
        )
        repository_output = workflow.replace(
            "${{ runner.temp }}/phase6-ci-rehearsal-${{ github.sha }}.json",
            "release/evidence/phase6-ci-rehearsal.json",
        )
        self.assertTrue(verification_errors(missing_external_output))
        self.assertTrue(verification_errors(repository_output))

        job_level_runner_context = workflow.replace(
            "        env:\n"
            "          PHASE6_EVIDENCE_OUTPUT: ${{ runner.temp }}/phase6-ci-rehearsal-${{ github.sha }}.json\n",
            "    env:\n"
            "      PHASE6_EVIDENCE_OUTPUT: ${{ runner.temp }}/phase6-ci-rehearsal-${{ github.sha }}.json\n",
            1,
        )
        self.assertTrue(verification_errors(job_level_runner_context))

    def test_ci_quality_gate_cannot_omit_migration_compatibility(self) -> None:
        quality_gate = Path("scripts/quality_gate.ps1").read_text(encoding="utf-8")
        self.assertIn("verify_migration_compatibility.py", quality_gate)
        without_gate = quality_gate.replace(
            "python scripts/verify_migration_compatibility.py",
            "python scripts/removed_migration_compatibility.py",
            1,
        )
        errors = verification_errors(quality_gate_text=without_gate)
        self.assertTrue(any("verify_migration_compatibility.py" in error for error in errors), errors)

        without_phase6_output_gate = quality_gate.replace(
            "python scripts/verify_phase6_evidence_outputs.py",
            "python scripts/removed_phase6_evidence_outputs.py",
            1,
        )
        errors = verification_errors(quality_gate_text=without_phase6_output_gate)
        self.assertTrue(
            any("verify_phase6_evidence_outputs.py" in error for error in errors),
            errors,
        )

    def test_windows_artifact_cannot_bypass_browser_e2e(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        without_dependency = workflow.replace(
            "    needs:\n      - quality-gate\n      - browser-e2e",
            "    needs: quality-gate",
            1,
        )
        self.assertTrue(verification_errors(without_dependency))

    def test_browser_e2e_command_and_fail_closed_behavior_are_required(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        wrong_command = workflow.replace("npm run test:e2e", "npm run build", 1)
        self.assertTrue(verification_errors(wrong_command))

        allowed_failure = workflow.replace(
            "  browser-e2e:\n    runs-on: ubuntu-24.04",
            "  browser-e2e:\n    continue-on-error: true\n    runs-on: ubuntu-24.04",
            1,
        )
        self.assertTrue(verification_errors(allowed_failure))

    def test_every_job_and_step_rejects_non_boolean_continue_on_error(self) -> None:
        original = self.workflow()
        unsafe_values = ("true", "${{ always() }}", None, 0, [True], {"value": True})
        for job_name, job in original["jobs"].items():
            for unsafe in unsafe_values:
                mutated = copy.deepcopy(original)
                mutated["jobs"][job_name]["continue-on-error"] = unsafe
                with self.subTest(job=job_name, unsafe=unsafe):
                    self.assertTrue(
                        any(
                            "continue-on-error" in error
                            for error in verification_errors(self.workflow_text(mutated))
                        )
                    )
            for index, step in enumerate(job.get("steps", [])):
                if not isinstance(step, dict):
                    continue
                mutated = copy.deepcopy(original)
                mutated["jobs"][job_name]["steps"][index][
                    "continue-on-error"
                ] = "${{ always() }}"
                with self.subTest(job=job_name, step=index):
                    self.assertTrue(
                        any(
                            "continue-on-error" in error
                            for error in verification_errors(self.workflow_text(mutated))
                        )
                    )

        explicit_false = copy.deepcopy(original)
        for job in explicit_false["jobs"].values():
            job["continue-on-error"] = False
            for step in job.get("steps", []):
                if isinstance(step, dict):
                    step["continue-on-error"] = False
        self.assertEqual(verification_errors(self.workflow_text(explicit_false)), [])

    def test_browser_e2e_is_serialized_for_the_shared_dev_server(self) -> None:
        config = Path("frontend/playwright.config.ts").read_text(encoding="utf-8")
        self.assertIn("fullyParallel: false", config)
        self.assertIn("workers: 1", config)

    def test_postgres_migration_gate_is_online_fail_closed_and_required(self) -> None:
        workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        mutations = {
            "missing_job": workflow.replace(
                "  postgres-migration-gate:", "  removed-postgres-migration-gate:", 1
            ),
            "missing_service": workflow.replace(
                "      postgres:\n        image: postgres:16-alpine",
                "      removed-postgres:\n        image: postgres:16-alpine",
                1,
            ),
            "missing_health_check": workflow.replace("--health-cmd", "--removed-health-cmd", 1),
            "offline_sql": workflow.replace(
                "alembic -c alembic.ini upgrade head",
                "alembic -c alembic.ini upgrade head --sql",
                1,
            ),
            "sqlite_substitution": workflow.replace(
                "postgresql+psycopg://migration_gate:migration_gate@localhost:5432/"
                "email_platform_migration_gate",
                '"sqlite+pysqlite:///:memory:"',
                1,
            ),
            "job_allows_failure": workflow.replace(
                "  postgres-migration-gate:\n    runs-on: ubuntu-24.04",
                "  postgres-migration-gate:\n    continue-on-error: true\n    runs-on: ubuntu-24.04",
                1,
            ),
            "step_allows_failure": workflow.replace(
                "      - name: Apply PostgreSQL migrations online\n        run:",
                "      - name: Apply PostgreSQL migrations online\n"
                "        continue-on-error: true\n        run:",
                1,
            ),
            "missing_unique_head_check": workflow.replace(
                "if len(heads) != 1:", "if False:", 1
            ),
            "missing_database_head_check": workflow.replace(
                "database_head != heads[0]", "database_head == heads[0]", 1
            ),
            "artifact_bypasses_migrations": workflow.replace(
                "    needs: postgres-migration-gate\n",
                "",
                1,
            ),
        }
        gate_start = workflow.index("  postgres-migration-gate:")
        gate_end = workflow.index("\n  browser-e2e:", gate_start)
        gate = workflow[gate_start:gate_end]
        mutations["unpinned_action"] = (
            workflow[:gate_start]
            + gate.replace(
                "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
                "actions/checkout@v4",
                1,
            )
            + workflow[gate_end:]
        )
        for mutation, changed_workflow in mutations.items():
            with self.subTest(mutation=mutation):
                self.assertNotEqual(changed_workflow, workflow)
                self.assertTrue(verification_errors(changed_workflow))

    def test_posix_vault_token_file_checks_run_in_linux_gate(self) -> None:
        workflow = self.workflow()
        steps = workflow["jobs"]["postgres-migration-gate"]["steps"]
        self.assertIn(
            "python -m unittest platform.tests.test_secret_resolvers "
            "tests.test_vault_token_sinks tests.test_vault_approle_bootstrap "
            "tests.test_vault_broker_policy_bootstrap",
            [step.get("run") for step in steps],
        )

    def test_linux_vault_safety_step_is_structurally_required(self) -> None:
        text = Path(".github/workflows/ci.yml").read_text(
            encoding="utf-8"
        )
        command = (
            "python -m unittest platform.tests.test_secret_resolvers "
            "tests.test_vault_token_sinks tests.test_vault_approle_bootstrap "
            "tests.test_vault_broker_policy_bootstrap"
        )
        for changed in (
            text.replace(command, "python -m unittest tests.test_vault_token_sinks", 1),
            text.replace(command, "python -m unittest platform.tests.test_secret_resolvers", 1),
            text.replace(command, command.replace(" tests.test_vault_approle_bootstrap", ""), 1),
            text.replace(command, command.replace(" tests.test_vault_broker_policy_bootstrap", ""), 1),
            text.replace(
                "      - name: Verify Vault token file safety on Linux\n        run:",
                "      - name: Verify Vault token file safety on Linux\n        continue-on-error: true\n        run:",
                1,
            ),
        ):
            with self.subTest():
                self.assertNotEqual(changed, text)
                self.assertTrue(verification_errors(changed))

    def test_linux_private_materialization_tls_step_is_structurally_required(self) -> None:
        original = self.workflow()
        steps = original["jobs"]["postgres-migration-gate"]["steps"]
        step_index = next(
            (
                index
                for index, step in enumerate(steps)
                if step.get("name") == POSIX_TLS_BOUNDARY_STEP
            ),
            None,
        )
        self.assertIsNotNone(step_index)
        assert step_index is not None
        self.assertEqual(
            " ".join(str(steps[step_index].get("run", "")).split()),
            POSIX_TLS_BOUNDARY_COMMAND,
        )

        missing = copy.deepcopy(original)
        del missing["jobs"]["postgres-migration-gate"]["steps"][step_index]
        allowed_failure = copy.deepcopy(original)
        allowed_failure["jobs"]["postgres-migration-gate"]["steps"][step_index][
            "continue-on-error"
        ] = True

        mutations = [
            ("missing", missing),
            ("allowed_failure", allowed_failure),
        ]
        for module in POSIX_TLS_BOUNDARY_COMMAND.split()[3:]:
            shortened = copy.deepcopy(original)
            shortened["jobs"]["postgres-migration-gate"]["steps"][step_index][
                "run"
            ] = POSIX_TLS_BOUNDARY_COMMAND.replace(f" {module}", "", 1)
            mutations.append((f"missing_{module}", shortened))

        for mutation, changed in mutations:
            with self.subTest(mutation=mutation):
                self.assertTrue(verification_errors(self.workflow_text(changed)))

    def test_linux_jobs_use_fixed_ubuntu_image(self) -> None:
        original = self.workflow()
        for job_name in ("postgres-migration-gate", "browser-e2e"):
            self.assertEqual(original["jobs"][job_name]["runs-on"], "ubuntu-24.04")
            for unsafe in ("ubuntu-latest", "ubuntu-22.04", "self-hosted"):
                changed = copy.deepcopy(original)
                changed["jobs"][job_name]["runs-on"] = unsafe
                with self.subTest(job=job_name, unsafe=unsafe):
                    self.assertTrue(
                        verification_errors(self.workflow_text(changed))
                    )

    def test_every_external_action_in_every_job_is_exactly_approved(self) -> None:
        workflow = self.workflow()
        observed_jobs: set[str] = set()
        for job_name, job in workflow["jobs"].items():
            for step in job.get("steps", []):
                uses = step.get("uses")
                if not isinstance(uses, str) or uses.startswith("./"):
                    continue
                observed_jobs.add(job_name)
                action_name, separator, revision = uses.rpartition("@")
                self.assertEqual(separator, "@")
                self.assertEqual(revision, APPROVED_EXTERNAL_ACTIONS[action_name])
        self.assertEqual(
            observed_jobs,
            {
                "quality-gate",
                "postgres-migration-gate",
                "browser-e2e",
                "windows-desktop-release",
            },
        )

    def test_workflow_token_permissions_are_exactly_contents_read(self) -> None:
        workflow = self.workflow()
        self.assertEqual(workflow["permissions"], CI_READ_ONLY_PERMISSIONS)

        mutations = {
            "missing": None,
            "read_all": "read-all",
            "write_all": "write-all",
            "contents_write": {"contents": "write"},
            "id_token_write": {"contents": "read", "id-token": "write"},
            "extra_read": {"contents": "read", "actions": "read"},
        }
        for mutation, permissions in mutations.items():
            changed = copy.deepcopy(workflow)
            if permissions is None:
                changed.pop("permissions")
            else:
                changed["permissions"] = permissions
            with self.subTest(mutation=mutation):
                errors = verification_errors(self.workflow_text(changed))
                self.assertTrue(
                    any("workflow permissions" in error for error in errors), errors
                )

    def test_each_job_rejects_any_token_permission_expansion(self) -> None:
        original = self.workflow()
        unsafe_permissions = {
            "read_all": "read-all",
            "write_all": "write-all",
            "contents_write": {"contents": "write"},
            "actions_write": {"contents": "read", "actions": "write"},
            "id_token_write": {"contents": "read", "id-token": "write"},
            "extra_read": {"contents": "read", "packages": "read"},
        }
        for job_name in original["jobs"]:
            for mutation, permissions in unsafe_permissions.items():
                changed = copy.deepcopy(original)
                changed["jobs"][job_name]["permissions"] = permissions
                with self.subTest(job=job_name, mutation=mutation):
                    errors = verification_errors(self.workflow_text(changed))
                    self.assertTrue(
                        any(
                            f"{job_name} permissions" in error for error in errors
                        ),
                        errors,
                    )

    def test_each_job_may_repeat_the_exact_read_only_permission(self) -> None:
        original = self.workflow()
        for job_name in original["jobs"]:
            changed = copy.deepcopy(original)
            changed["jobs"][job_name]["permissions"] = dict(
                CI_READ_ONLY_PERMISSIONS
            )
            with self.subTest(job=job_name):
                self.assertEqual(
                    verification_errors(self.workflow_text(changed)),
                    [],
                )

    def test_mutable_tag_in_any_single_job_is_rejected(self) -> None:
        original = self.workflow()
        for job_name, job in original["jobs"].items():
            action_index = next(
                index
                for index, step in enumerate(job.get("steps", []))
                if isinstance(step.get("uses"), str)
                and not step["uses"].startswith("./")
            )
            mutated = copy.deepcopy(original)
            action_name = mutated["jobs"][job_name]["steps"][action_index][
                "uses"
            ].rpartition("@")[0]
            mutated["jobs"][job_name]["steps"][action_index]["uses"] = (
                f"{action_name}@v999"
            )
            with self.subTest(job=job_name):
                errors = verification_errors(self.workflow_text(mutated))
                self.assertTrue(
                    any("approved commit" in error for error in errors), errors
                )

    def test_short_nonhex_and_unknown_sha_are_rejected(self) -> None:
        original = self.workflow()
        cases = {
            "short_sha": "1" * 12,
            "nonhex_sha": "g" * 40,
            "unknown_sha": "0" * 40,
        }
        for case, revision in cases.items():
            mutated = copy.deepcopy(original)
            checkout = mutated["jobs"]["quality-gate"]["steps"][0]
            checkout["uses"] = f"actions/checkout@{revision}"
            with self.subTest(case=case):
                errors = verification_errors(self.workflow_text(mutated))
                self.assertTrue(
                    any("approved commit" in error for error in errors), errors
                )

    def test_unknown_external_action_is_rejected_even_when_sha_pinned(self) -> None:
        mutated = self.workflow()
        mutated["jobs"]["quality-gate"]["steps"][0]["uses"] = (
            "unreviewed/action@" + "0" * 40
        )
        errors = verification_errors(self.workflow_text(mutated))
        self.assertTrue(
            any("unapproved external action" in error for error in errors), errors
        )


if __name__ == "__main__":
    unittest.main()
