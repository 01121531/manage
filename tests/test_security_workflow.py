import unittest
from pathlib import Path

import yaml

from scripts.verify_ci_workflow import checkout_credential_errors
from scripts.verify_security_workflow import dependency_gate_step_errors


class SecurityWorkflowTests(unittest.TestCase):
    def test_security_workflow_has_supply_chain_gates(self) -> None:
        workflow = Path(".github/workflows/security.yml")
        self.assertTrue(workflow.exists())
        data = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        self.assertIn("codeql", data["jobs"])
        self.assertIn("security-gate", data["jobs"])
        self.assertIn("container-supply-chain", data["jobs"])
        step_names = [
            step.get("name", "")
            for step in data["jobs"]["security-gate"]["steps"]
            if isinstance(step, dict)
        ]
        self.assertIn("Secret scan", step_names)
        self.assertIn("Verify release manifest", step_names)
        self.assertIn("Verify signoff template", step_names)
        self.assertIn("Python dependency audit", step_names)
        self.assertIn("Python test dependency audit", step_names)
        self.assertIn("Python desktop build dependency audit", step_names)
        self.assertIn("Frontend dependency audit", step_names)
        container_step_names = [
            step.get("name", "")
            for step in data["jobs"]["container-supply-chain"]["steps"]
            if isinstance(step, dict)
        ]
        self.assertIn("Generate Syft SPDX SBOM", container_step_names)
        self.assertIn("Trivy HIGH/CRITICAL image gate", container_step_names)

    def test_security_checkout_credentials_cannot_persist(self) -> None:
        data = yaml.safe_load(
            Path(".github/workflows/security.yml").read_text(encoding="utf-8")
        )
        self.assertEqual(
            checkout_credential_errors(data["jobs"], label="Security"), []
        )
        checkout = data["jobs"]["codeql"]["steps"][0]
        for unsafe in (None, True, "false"):
            mutated = yaml.safe_load(yaml.safe_dump(data))
            candidate = mutated["jobs"]["codeql"]["steps"][0]
            if unsafe is None:
                candidate.pop("with", None)
            else:
                candidate["with"]["persist-credentials"] = unsafe
            with self.subTest(unsafe=unsafe):
                self.assertTrue(
                    checkout_credential_errors(mutated["jobs"], label="Security")
                )
        self.assertIs(checkout["with"]["persist-credentials"], False)

    def test_codeql_is_pinned_fail_closed_and_covers_both_languages(self) -> None:
        data = yaml.safe_load(
            Path(".github/workflows/security.yml").read_text(encoding="utf-8")
        )
        job = data["jobs"]["codeql"]
        self.assertEqual("write", job["permissions"]["security-events"])
        self.assertEqual(
            {"javascript-typescript", "python"},
            set(job["strategy"]["matrix"]["language"]),
        )
        codeql_steps = [
            step
            for step in job["steps"]
            if isinstance(step, dict)
            and str(step.get("uses", "")).startswith("github/codeql-action/")
        ]
        expected_sha = "24ea975727876cf496b1eb0c5b36e96e01600b51"
        self.assertEqual(
            [
                f"github/codeql-action/init@{expected_sha}",
                f"github/codeql-action/analyze@{expected_sha}",
            ],
            [step["uses"] for step in codeql_steps],
        )
        self.assertEqual("${{ matrix.language }}", codeql_steps[0]["with"]["languages"])
        self.assertEqual("security-extended", codeql_steps[0]["with"]["queries"])
        self.assertTrue(
            all(
                "continue-on-error" not in step
                or step["continue-on-error"] is False
                for step in codeql_steps
            )
        )

    def test_dependency_gate_validates_real_fail_closed_commands(self) -> None:
        data = yaml.safe_load(
            Path(".github/workflows/security.yml").read_text(encoding="utf-8")
        )
        job = data["jobs"]["security-gate"]
        self.assertEqual(
            dependency_gate_step_errors(job, require_repository_checks=True), []
        )

        for step_name, replacement in (
            ("Python dependency audit", "echo skipped"),
            ("Python test dependency audit", "echo skipped"),
            ("Python desktop build dependency audit", "echo skipped"),
            ("Frontend dependency audit", "npm run build"),
        ):
            mutated = yaml.safe_load(yaml.safe_dump(job))
            step = next(
                item for item in mutated["steps"] if item.get("name") == step_name
            )
            step["run"] = replacement
            self.assertTrue(
                dependency_gate_step_errors(
                    mutated, require_repository_checks=True
                )
            )

        production_only_frontend = yaml.safe_load(yaml.safe_dump(job))
        next(
            item
            for item in production_only_frontend["steps"]
            if item.get("name") == "Frontend dependency audit"
        )["run"] = (
            "npm audit --audit-level=high "
            "--include=prod --omit=dev --include=optional --include=peer"
        )
        self.assertTrue(
            dependency_gate_step_errors(
                production_only_frontend, require_repository_checks=True
            )
        )

        allowed_failure = yaml.safe_load(yaml.safe_dump(job))
        next(
            item
            for item in allowed_failure["steps"]
            if item.get("name") == "Python dependency audit"
        )["continue-on-error"] = True
        self.assertTrue(
            dependency_gate_step_errors(
                allowed_failure, require_repository_checks=True
            )
        )

        for unsafe in ("true", "${{ always() }}", None, 0, [True], {"value": True}):
            unsafe_job = yaml.safe_load(yaml.safe_dump(job))
            unsafe_job["continue-on-error"] = unsafe
            unsafe_step = yaml.safe_load(yaml.safe_dump(job))
            next(
                item
                for item in unsafe_step["steps"]
                if item.get("name") == "Python dependency audit"
            )["continue-on-error"] = unsafe
            with self.subTest(unsafe=unsafe):
                self.assertTrue(
                    dependency_gate_step_errors(
                        unsafe_job, require_repository_checks=True
                    )
                )
                self.assertTrue(
                    dependency_gate_step_errors(
                        unsafe_step, require_repository_checks=True
                    )
                )
