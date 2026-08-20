import unittest
from pathlib import Path

import yaml


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
        self.assertIn("Frontend dependency audit", step_names)
        container_step_names = [
            step.get("name", "")
            for step in data["jobs"]["container-supply-chain"]["steps"]
            if isinstance(step, dict)
        ]
        self.assertIn("Generate Syft SPDX SBOM", container_step_names)
        self.assertIn("Trivy HIGH/CRITICAL image gate", container_step_names)

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
        self.assertTrue(all(step.get("continue-on-error") is not True for step in codeql_steps))
