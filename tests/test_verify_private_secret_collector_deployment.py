from __future__ import annotations

import json
from pathlib import Path
import unittest

from scripts.verify_private_secret_collector_deployment import validate_assets


ROOT = Path(__file__).resolve().parents[1]


class CollectorDeploymentStaticGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = (ROOT / "scripts" / "private_secret_collector_deployment.py").read_text(encoding="utf-8")
        self.policy = (ROOT / "deploy" / "private-secret-collector-deployment-policy.synthetic.json").read_bytes()
        self.template = (ROOT / "deploy" / "evidence-index-envelopes" / "private-secret-collector-acceptance-transaction.synthetic.json").read_bytes()

    def test_assets_pass(self) -> None:
        self.assertEqual(validate_assets(self.source, self.policy, self.template), [])

    def test_rejects_network_capability_and_removed_caller_pin(self) -> None:
        network = "import requests\n" + self.source
        self.assertTrue(any("capability" in item for item in validate_assets(network, self.policy, self.template)))
        drifted = self.source.replace("    expected_prior_generation: str,\n", "")
        self.assertTrue(any("caller-pinned" in item for item in validate_assets(drifted, self.policy, self.template)))

    def test_rejects_policy_enablement_or_configuration(self) -> None:
        policy = json.loads(self.policy)
        policy["executor_integration_enabled"] = True
        raw = json.dumps(policy).encode()
        self.assertTrue(validate_assets(self.source, raw, self.template))

    def test_rejects_template_claim_overstatement_and_acceptance(self) -> None:
        for mutation in ("claim", "production", "receipt"):
            with self.subTest(mutation=mutation):
                template = json.loads(self.template)
                if mutation == "claim":
                    template["claim_boundary"]["trusted_time"] = "verified"
                elif mutation == "production":
                    template["production_acceptance"] = True
                else:
                    template["execution_receipt"] = {"self_authored": True}
                self.assertTrue(validate_assets(self.source, self.policy, json.dumps(template).encode()))


if __name__ == "__main__":
    unittest.main()
