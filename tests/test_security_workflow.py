import unittest
from pathlib import Path

import yaml


class SecurityWorkflowTests(unittest.TestCase):
    def test_security_workflow_has_supply_chain_gates(self) -> None:
        workflow = Path(".github/workflows/security.yml")
        self.assertTrue(workflow.exists())
        data = yaml.safe_load(workflow.read_text(encoding="utf-8"))
        self.assertIn("security-gate", data["jobs"])
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

