from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from platform.uploads import AI1_OBSERVED_CONTROL_PLANE_PATHS
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
            "sanitized_authenticated_shapes_and_public_frontend",
        )
        self.assertEqual(
            self.observation["source"]["authenticated_settings_facts"],
            {
                "page_url": "https://ai1.aisb.shop/admin/settings",
                "reported_version": "v0.1.169",
                "admin_api_key_configuration": "configured",
                "admin_api_key_lifecycle": "rotated_after_chat_exposure_with_explicit_user_authorization",
                "admin_api_key_material_handling": "replacement_browser_display_only_not_retained",
                "admin_api_key_security_status": "operator_deferred_to_target_deployment_configuration",
                "admin_api_key_status_path": "/api/v1/admin/settings/admin-api-key",
                "unauthenticated_status_code": 401,
                "idempotency_configuration_visibility": "not_exposed_in_admin_ui",
                "evidence": "authenticated_admin_ui_and_browser_resource_timing",
            },
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
                "account_get_by_id",
                "account_usage",
                "openai_account_quota",
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
        self.assertIn(
            "cannot_reconcile_creation_without_a_returned_account_id",
            operations["account_get_by_id"]["limitations"],
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
        self.assertIn(
            "idempotency_configuration_not_exposed_in_admin_ui",
            self.observation["negative_findings"],
        )

    def test_authenticated_shapes_are_sanitized_and_do_not_claim_creation(self) -> None:
        operations = {
            item["operation_id"]: item for item in self.observation["operations"]
        }
        account_list = operations["account_list"]
        self.assertIn("authenticated_admin_fetch", account_list["evidence"])
        self.assertEqual(account_list["response"]["status_codes"], [200])
        self.assertEqual(
            account_list["response"]["nested_fields"]["data"],
            ["items", "page", "page_size", "pages", "total"],
        )
        today_stats = operations["account_today_stats_batch"]
        self.assertEqual(
            today_stats["response"]["nested_fields"]["data.stats.*"],
            ["cost", "requests", "standard_cost", "tokens", "user_cost"],
        )
        generate = operations["openai_generate_auth_url"]
        self.assertEqual(
            generate["response"]["nested_fields"]["data"],
            ["auth_url", "session_id"],
        )
        self.assertEqual(operations["account_create"]["response"]["status_codes"], [])
        self.assertEqual(operations["openai_exchange_code"]["response"]["status_codes"], [])
        self.assertEqual(operations["account_get_by_id"]["response"]["status_codes"], [200])
        self.assertEqual(
            operations["account_usage"]["response"]["nested_fields"]["data"],
            ["five_hour", "seven_day", "updated_at"],
        )
        self.assertEqual(operations["openai_account_quota"]["response"]["status_codes"], [502])
        self.assertIn(
            "successful_quota_shape_not_observed",
            operations["openai_account_quota"]["limitations"],
        )

    def test_generic_upload_guard_is_bound_to_every_observed_control_path(self) -> None:
        observed_paths = {
            item["path"] for item in self.observation["operations"]
        }

        self.assertEqual(AI1_OBSERVED_CONTROL_PLANE_PATHS, observed_paths)

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

        reusable_exposed_key = copy.deepcopy(self.observation)
        reusable_exposed_key["source"]["authenticated_settings_facts"][
            "admin_api_key_security_status"
        ] = "compromised_do_not_use"
        mutations.append(reusable_exposed_key)

        unknown = copy.deepcopy(self.observation)
        unknown["authorization"] = "redacted"
        mutations.append(unknown)

        unconfigured = copy.deepcopy(self.observation)
        unconfigured["source"]["authenticated_settings_facts"][
            "admin_api_key_configuration"
        ] = "not_configured"
        mutations.append(unconfigured)

        for document in mutations:
            with self.subTest(document=document):
                self.assertTrue(observation_errors(document))


if __name__ == "__main__":
    unittest.main()
