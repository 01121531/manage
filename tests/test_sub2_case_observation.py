from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from scripts.verify_sub2_case_observation import (
    OBSERVATION,
    observation_errors,
)


class Sub2CaseObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.observation = json.loads(OBSERVATION.read_text(encoding="utf-8"))

    def test_repository_observation_is_safe_closed_and_non_authoritative(self) -> None:
        self.assertEqual(observation_errors(self.observation), [])
        self.assertFalse(self.observation["production_acceptance"])
        self.assertEqual(self.observation["review_status"], "unreviewed")
        self.assertEqual(
            self.observation["observation_scope"],
            "request_shape_and_public_frontend_only",
        )
        quality_gate = Path("scripts/quality_gate.ps1").read_text(encoding="utf-8")
        self.assertIn(
            "python scripts/verify_sub2_case_observation.py",
            quality_gate,
        )

    def test_observed_operations_do_not_fill_unproven_workflow_semantics(self) -> None:
        operations = {
            item["operation_id"]: item for item in self.observation["operations"]
        }
        self.assertEqual(
            set(operations),
            {
                "account_list",
                "openai_generate_auth_url",
                "openai_exchange_code",
                "account_create",
                "account_today_stats_batch",
                "account_duplicate",
            },
        )
        self.assertEqual(
            operations["account_create"]["path"],
            "/api/v1/admin/accounts",
        )
        self.assertEqual(
            operations["account_create"]["request"]["header_fields"],
            [],
        )
        self.assertEqual(
            operations["account_duplicate"]["request"]["header_fields"],
            ["Idempotency-Key"],
        )
        self.assertIn(
            "account_create_status_query_not_observed",
            self.observation["negative_findings"],
        )
        self.assertIn(
            "legacy_check_concurrency_limit_not_observed",
            self.observation["negative_findings"],
        )

    def test_observation_contains_no_supplied_secret_or_example_values(self) -> None:
        rendered = json.dumps(self.observation, ensure_ascii=False)
        for forbidden in (
            "eyJhbGciOiJIUzI1NiIs",
            "838304861",
            "a444d12b5fb4b2a0faf651832d9fcafd",
            "841ac7f5802bd1fba94b25ba8ed043278cae158ca71b450205f11a277eb01ebd",
            "95d63612-59cf-4536-ace3-f2cd9b863e695aa296",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, rendered)
        self.assertTrue(
            all(value is False for value in self.observation["redaction"].values())
        )

    def test_schema_rejects_acceptance_review_and_sensitive_material_drift(self) -> None:
        mutations = []

        accepted = copy.deepcopy(self.observation)
        accepted["production_acceptance"] = True
        mutations.append(accepted)

        reviewed = copy.deepcopy(self.observation)
        reviewed["review_status"] = "approved"
        mutations.append(reviewed)

        secret_bearing = copy.deepcopy(self.observation)
        secret_bearing["redaction"]["contains_live_credentials"] = True
        mutations.append(secret_bearing)

        unknown = copy.deepcopy(self.observation)
        unknown["authorization"] = "redacted"
        mutations.append(unknown)

        for document in mutations:
            with self.subTest(document=document):
                self.assertTrue(observation_errors(document))


if __name__ == "__main__":
    unittest.main()
