import copy
import unittest
from pathlib import Path

import yaml

from scripts.verify_ci_workflow import (
    POSIX_TLS_BOUNDARY_COMMAND,
    POSIX_TLS_BOUNDARY_STEP,
)
from scripts.verify_release_workflow import ROOT, workflow_errors


class ReleaseWorkflowTests(unittest.TestCase):
    def test_repository_workflow_passes(self) -> None:
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(workflow_errors(text), [])

    def test_release_checkout_credentials_cannot_persist(self) -> None:
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        for unsafe in ("true", '"false"'):
            mutated = text.replace(
                "          persist-credentials: false",
                f"          persist-credentials: {unsafe}",
                1,
            )
            with self.subTest(unsafe=unsafe):
                self.assertTrue(
                    any(
                        "persist-credentials" in error
                        for error in workflow_errors(mutated)
                    )
                )

        missing = text.replace(
            "        with:\n          persist-credentials: false\n", "", 1
        )
        self.assertTrue(
            any("persist-credentials" in error for error in workflow_errors(missing))
        )

    def test_missing_integrity_manifest_fails(self) -> None:
        self.assertTrue(workflow_errors("gh release create"))

    def test_phase6_evidence_cannot_be_dropped_or_cross_commit(self) -> None:
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        without_upload = text.replace(
            "      - name: Upload Phase 6 CI rehearsal evidence",
            "      - name: Upload removed evidence",
            1,
        )
        self.assertTrue(workflow_errors(without_upload))

        missing_external_output = text.replace(
            "      PHASE6_EVIDENCE_OUTPUT: ${{ runner.temp }}/phase6-ci-rehearsal-${{ github.sha }}.json\n",
            "",
            1,
        )
        repository_output = text.replace(
            "${{ runner.temp }}/phase6-ci-rehearsal-${{ github.sha }}.json",
            "release/evidence/phase6-ci-rehearsal.json",
        )
        self.assertTrue(workflow_errors(missing_external_output))
        self.assertTrue(workflow_errors(repository_output))

        missing_allowed = text.replace(
            "          if-no-files-found: error",
            "          if-no-files-found: ignore",
            1,
        )
        self.assertTrue(workflow_errors(missing_allowed))

        without_commit_binding = text.replace(
            '            --expected-commit "${{ github.sha }}"',
            "            --expected-commit cross-commit",
            1,
        )
        self.assertTrue(workflow_errors(without_commit_binding))

        without_release_asset = text.replace(
            "          release/assets/phase6-ci-rehearsal.json.sha256\n",
            "",
            1,
        )
        self.assertTrue(workflow_errors(without_release_asset))

    def test_release_browser_e2e_is_fail_closed_and_runs_real_command(self) -> None:
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        without_job = text.replace("  release-browser-e2e:", "  removed-browser-e2e:", 1)
        self.assertTrue(workflow_errors(without_job))

        wrong_command = text.replace("npm run test:e2e", "npm run build", 1)
        self.assertTrue(workflow_errors(wrong_command))

        allowed_failure = text.replace(
            "  release-browser-e2e:\n    runs-on: ubuntu-24.04",
            "  release-browser-e2e:\n    continue-on-error: true\n    runs-on: ubuntu-24.04",
            1,
        )
        self.assertTrue(workflow_errors(allowed_failure))

    def test_every_release_job_and_step_rejects_non_boolean_continue_on_error(self) -> None:
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        original = yaml.safe_load(text)
        def render(workflow: dict) -> str:
            return yaml.safe_dump(workflow, sort_keys=False).replace(
                "- v*.*.*", '- "v*.*.*"'
            )

        unsafe_values = ("true", "${{ always() }}", None, 0, [True], {"value": True})
        for job_name, job in original["jobs"].items():
            for unsafe in unsafe_values:
                mutated = copy.deepcopy(original)
                mutated["jobs"][job_name]["continue-on-error"] = unsafe
                with self.subTest(job=job_name, unsafe=unsafe):
                    self.assertTrue(
                        any(
                            "continue-on-error" in error
                            for error in workflow_errors(render(mutated))
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
                            for error in workflow_errors(render(mutated))
                        )
                    )

        explicit_false = copy.deepcopy(original)
        for job in explicit_false["jobs"].values():
            job["continue-on-error"] = False
            for step in job.get("steps", []):
                if isinstance(step, dict):
                    step["continue-on-error"] = False
        self.assertEqual(
            workflow_errors(render(explicit_false)), []
        )

    def test_no_release_artifact_can_bypass_browser_e2e(self) -> None:
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        container_without_e2e = text.replace(
            "    needs:\n      - release-quality-gate\n      - release-browser-e2e",
            "    needs: release-quality-gate",
            1,
        )
        self.assertTrue(workflow_errors(container_without_e2e))

        windows_without_e2e = text.replace(
            "      - release-browser-e2e\n      - release-codeql\n"
            "      - release-security-gate\n      - verified-container-release",
            "      - release-codeql\n      - release-security-gate\n"
            "      - verified-container-release",
            1,
        )
        self.assertTrue(workflow_errors(windows_without_e2e))

    def test_publication_jobs_cannot_override_success_only_needs_semantics(self) -> None:
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        for job_name in ("verified-container-release", "verified-windows-release"):
            mutated = text.replace(
                f"  {job_name}:\n    needs:",
                f"  {job_name}:\n    if: ${{{{ always() }}}}\n    needs:",
                1,
            )
            self.assertNotEqual(mutated, text)
            with self.subTest(job_name=job_name):
                self.assertTrue(
                    any(
                        "must not override dependency success" in error
                        for error in workflow_errors(mutated)
                    )
                )

    def test_release_publication_requires_real_security_gates(self) -> None:
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        without_codeql = text.replace("  release-codeql:", "  removed-codeql:", 1)
        self.assertTrue(workflow_errors(without_codeql))

        fake_python_audit = text.replace(
            "        run: pip-audit -r platform/requirements.txt",
            "        run: echo skipped",
            1,
        )
        self.assertTrue(workflow_errors(fake_python_audit))

        missing_test_audit = text.replace(
            "      - name: Python test dependency audit\n"
            "        run: pip-audit -r platform/requirements-test.txt\n",
            "",
            1,
        )
        self.assertTrue(workflow_errors(missing_test_audit))

        missing_desktop_build_audit = text.replace(
            "      - name: Python desktop build dependency audit\n"
            "        run: pip-audit -r requirements-desktop-build.txt\n",
            "",
            1,
        )
        self.assertTrue(workflow_errors(missing_desktop_build_audit))

        fake_frontend_audit = text.replace(
            "          npm audit --audit-level=high",
            "          npm run build",
            1,
        )
        self.assertTrue(workflow_errors(fake_frontend_audit))

        production_only_frontend = text.replace(
            "          --include=prod --include=dev --include=optional --include=peer",
            "          --include=prod --omit=dev --include=optional --include=peer",
            1,
        )
        self.assertTrue(workflow_errors(production_only_frontend))

        allowed_failure = text.replace(
            "      - name: Python dependency audit\n        run: pip-audit",
            "      - name: Python dependency audit\n        continue-on-error: true\n        run: pip-audit",
            1,
        )
        self.assertTrue(workflow_errors(allowed_failure))

        container_without_security = text.replace(
            "      - release-codeql\n      - release-security-gate\n"
            "    runs-on: ubuntu-24.04",
            "    runs-on: ubuntu-24.04",
            1,
        )
        self.assertTrue(workflow_errors(container_without_security))

        windows_without_security = text.replace(
            "      - release-codeql\n      - release-security-gate\n"
            "      - verified-container-release",
            "      - verified-container-release",
            1,
        )
        self.assertTrue(workflow_errors(windows_without_security))

    def test_release_requires_online_postgres_migration_gate(self) -> None:
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        mutations = {
            "missing_job": text.replace(
                "  release-postgres-migration-gate:",
                "  removed-postgres-migration-gate:",
                1,
            ),
            "missing_service": text.replace(
                "      postgres:\n        image: postgres:16-alpine",
                "      removed-postgres:\n        image: postgres:16-alpine",
                1,
            ),
            "missing_health_check": text.replace(
                "--health-cmd", "--removed-health-cmd", 1
            ),
            "offline_sql": text.replace(
                "alembic -c alembic.ini upgrade head",
                "alembic -c alembic.ini upgrade head --sql",
                1,
            ),
            "sqlite_substitution": text.replace(
                "postgresql+psycopg://migration_gate:migration_gate@localhost:5432/"
                "email_platform_migration_gate",
                '"sqlite+pysqlite:///:memory:"',
                1,
            ),
            "job_allows_failure": text.replace(
                "  release-postgres-migration-gate:\n    runs-on: ubuntu-24.04",
                "  release-postgres-migration-gate:\n"
                "    continue-on-error: true\n    runs-on: ubuntu-24.04",
                1,
            ),
            "step_allows_failure": text.replace(
                "      - name: Apply PostgreSQL migrations online\n        run:",
                "      - name: Apply PostgreSQL migrations online\n"
                "        continue-on-error: true\n        run:",
                1,
            ),
            "missing_unique_head_check": text.replace(
                "if len(heads) != 1:", "if False:", 1
            ),
            "missing_database_head_check": text.replace(
                "database_head != heads[0]", "database_head == heads[0]", 1
            ),
        }
        gate_start = text.index("  release-postgres-migration-gate:")
        gate_end = text.index("\n  release-codeql:", gate_start)
        gate = text[gate_start:gate_end]
        mutations["unpinned_action"] = (
            text[:gate_start]
            + gate.replace(
                "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
                "actions/setup-python@v5",
                1,
            )
            + text[gate_end:]
        )
        for mutation, changed_workflow in mutations.items():
            with self.subTest(mutation=mutation):
                self.assertNotEqual(changed_workflow, text)
                self.assertTrue(workflow_errors(changed_workflow))

    def test_release_artifacts_cannot_bypass_postgres_migrations(self) -> None:
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        release_without_migrations = text.replace(
            "    needs: release-postgres-migration-gate\n",
            "",
            1,
        )
        self.assertNotEqual(release_without_migrations, text)
        self.assertTrue(workflow_errors(release_without_migrations))

    def test_posix_vault_token_file_checks_run_in_release_linux_gate(self) -> None:
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        gate_start = text.index("  release-postgres-migration-gate:")
        gate_end = text.index("\n  release-codeql:", gate_start)
        self.assertIn(
            "run: python -m unittest platform.tests.test_secret_resolvers "
            "tests.test_vault_token_sinks tests.test_vault_approle_bootstrap "
            "tests.test_vault_broker_policy_bootstrap",
            text[gate_start:gate_end],
        )

    def test_release_linux_vault_safety_step_is_structurally_required(self) -> None:
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
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
                self.assertTrue(workflow_errors(changed))

    def test_release_linux_private_materialization_tls_step_is_required(self) -> None:
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        original = yaml.safe_load(text)
        steps = original["jobs"]["release-postgres-migration-gate"]["steps"]
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
        del missing["jobs"]["release-postgres-migration-gate"]["steps"][step_index]
        allowed_failure = copy.deepcopy(original)
        allowed_failure["jobs"]["release-postgres-migration-gate"]["steps"][step_index][
            "continue-on-error"
        ] = True

        mutations = [
            ("missing", missing),
            ("allowed_failure", allowed_failure),
        ]
        for module in POSIX_TLS_BOUNDARY_COMMAND.split()[3:]:
            shortened = copy.deepcopy(original)
            shortened["jobs"]["release-postgres-migration-gate"]["steps"][step_index][
                "run"
            ] = POSIX_TLS_BOUNDARY_COMMAND.replace(f" {module}", "", 1)
            mutations.append((f"missing_{module}", shortened))

        for mutation, changed in mutations:
            with self.subTest(mutation=mutation):
                self.assertTrue(
                    workflow_errors(yaml.safe_dump(changed, sort_keys=False))
                )

    def test_release_linux_jobs_use_fixed_ubuntu_image(self) -> None:
        text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        original = yaml.safe_load(text)
        for job_name in (
            "release-postgres-migration-gate",
            "release-codeql",
            "release-security-gate",
            "release-browser-e2e",
            "verified-container-release",
        ):
            self.assertEqual(original["jobs"][job_name]["runs-on"], "ubuntu-24.04")
            for unsafe in ("ubuntu-latest", "ubuntu-22.04", "self-hosted"):
                changed = copy.deepcopy(original)
                changed["jobs"][job_name]["runs-on"] = unsafe
                with self.subTest(job=job_name, unsafe=unsafe):
                    self.assertTrue(
                        workflow_errors(yaml.safe_dump(changed, sort_keys=False))
                    )


if __name__ == "__main__":
    unittest.main()
