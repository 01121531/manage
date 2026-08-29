from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

from platform.mail_connectors import mail_connector_contract_capabilities
from platform.uploads import sub2_adapter_contract_capabilities
from scripts.provider_contract_conformance import (
    MAIL_CONTRACT,
    SUB2_CONTRACT,
    contract_errors,
    main,
    runtime_conformance_errors,
)


class ProviderContractConformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mail = json.loads(MAIL_CONTRACT.read_text(encoding="utf-8"))
        self.sub2 = json.loads(SUB2_CONTRACT.read_text(encoding="utf-8"))

    def _reviewed_sub2(self) -> dict[str, object]:
        document = copy.deepcopy(self.sub2)
        document.update(
            {
                "synthetic": False,
                "provider_reference": "sub2-provider-contract-42",
                "review_reference": "sub2-independent-review-42",
                "reviewed_at": "2026-08-26T10:00:00Z",
                "source_provenance": {
                    "provider_scope": {
                        "environment": "production",
                        "provider_account_reference": "sub2-provider-account-scope-42",
                    },
                    "source_document_reference": "sub2-api-contract-document-42",
                    "source_version_reference": "sub2-api-contract-version-7",
                    "source_sha256": "a" * 64,
                    "captured_at": "2026-08-26T09:00:00Z",
                    "valid_until": "2099-08-26T09:00:00Z",
                },
            }
        )
        workflow = document["capabilities"]["workflow"]
        workflow["provider_mode"] = "ordered_multi_step"
        for operation, details in workflow["operations"].items():
            details.update(
                {
                    "provider_operation_reference": f"sub2-operation-{operation}",
                    "method": "GET" if operation == "status_query" else "POST",
                    "request_fields": ["correlation_id"],
                    "response_fields": ["result"],
                }
            )
        workflow["idempotency"].update(
            {
                "scope": "provider_account",
                "minimum_retention_seconds": 86400,
                "same_key_same_payload": "same_result",
                "same_key_different_payload": "reject",
            }
        )
        workflow["status_consistency"].update(
            {
                "model": "eventual",
                "maximum_visibility_delay_seconds": 30,
                "minimum_retention_seconds": 86400,
            }
        )
        return document

    def test_repository_synthetic_contracts_are_safe_and_closed(self) -> None:
        self.assertEqual(contract_errors(self.mail, expected_type="mail"), [])
        self.assertEqual(contract_errors(self.sub2, expected_type="sub2"), [])
        self.assertFalse(self.mail["production_acceptance"])
        self.assertFalse(self.sub2["production_acceptance"])
        self.assertTrue(self.mail["synthetic"])
        self.assertTrue(self.sub2["synthetic"])
        quality_gate = Path("scripts/quality_gate.ps1").read_text(encoding="utf-8")
        self.assertIn(
            "python scripts/provider_contract_conformance.py verify-repository",
            quality_gate,
        )

    def test_mail_contract_conforms_to_current_generic_connector(self) -> None:
        self.assertEqual(runtime_conformance_errors(self.mail), [])

    def test_sub2_contract_exposes_current_status_query_gap(self) -> None:
        self.assertEqual(
            runtime_conformance_errors(self.sub2),
            [
                "sub2 provider workflow is unverified",
                "sub2 runtime does not implement status query",
                "sub2 runtime does not implement idempotency lookup",
            ],
        )

    def test_conformance_harness_is_bound_to_runtime_capability_snapshots(self) -> None:
        mail = mail_connector_contract_capabilities()
        sub2 = sub2_adapter_contract_capabilities()

        self.assertTrue(mail["watermark_at_task_start"])
        self.assertEqual(mail["cursor_field"], "after_watermark")
        self.assertEqual(
            mail["watermark_boundary_field"], "received_at_or_before"
        )
        self.assertEqual(mail["watermark_basis_field"], "watermark_basis")
        self.assertEqual(mail["watermark_basis"], "task_created_at")
        self.assertEqual(mail["empty_watermark_statuses"], ("empty", "not_found"))
        self.assertEqual(mail["code_fields"], ("code", "verification_code"))
        self.assertEqual(mail["sender_filter_field"], "sender_filter")
        self.assertEqual(mail["subject_filter_field"], "subject_filter")
        self.assertEqual(mail["sender_fields"], ("sender",))
        self.assertEqual(mail["subject_fields"], ("subject",))
        self.assertEqual(mail["received_at_field"], "received_at")
        self.assertIn(
            "sender_filter",
            self.mail["field_shapes"]["request_fields"],
        )
        self.assertIn(
            "subject_filter",
            self.mail["field_shapes"]["request_fields"],
        )
        self.assertIn(
            "received_at_or_before",
            self.mail["field_shapes"]["request_fields"],
        )
        self.assertIn(
            "received_at_or_before",
            self.mail["field_shapes"]["response_fields"],
        )
        self.assertIn(
            "watermark_basis",
            self.mail["field_shapes"]["response_fields"],
        )
        self.assertIn("received_at", self.mail["field_shapes"]["response_fields"])
        self.assertEqual(sub2["idempotency_name"], "Idempotency-Key")
        self.assertEqual(sub2["provider_idempotency_value"], "upload_job_id")
        self.assertTrue(sub2["lookup_protocol_supported"])
        self.assertEqual(
            set(sub2["lookup_outcomes"]),
            {"succeeded", "failed", "processing", "not_found", "unknown"},
        )
        self.assertFalse(sub2["status_query_supported"])
        self.assertFalse(sub2["idempotency_lookup_supported"])

    def test_rejects_acceptance_unknown_fields_and_sensitive_material_claims(self) -> None:
        mutations = []

        accepted = copy.deepcopy(self.mail)
        accepted["production_acceptance"] = True
        mutations.append(accepted)

        unknown = copy.deepcopy(self.mail)
        unknown["credential"] = "redacted"
        mutations.append(unknown)

        secret_bearing = copy.deepcopy(self.mail)
        secret_bearing["redaction"]["contains_live_credentials"] = True
        mutations.append(secret_bearing)

        real_without_review = copy.deepcopy(self.mail)
        real_without_review["synthetic"] = False
        real_without_review["provider_reference"] = "mail-provider-contract-42"
        real_without_review["review_reference"] = None
        mutations.append(real_without_review)

        wrong_type = copy.deepcopy(self.mail)
        wrong_type["contract_type"] = "sub2"
        mutations.append(wrong_type)

        for index, document in enumerate(mutations):
            with self.subTest(index=index):
                self.assertTrue(contract_errors(document, expected_type="mail"))

    def test_mail_runtime_detects_auth_pagination_and_mapping_drift(self) -> None:
        changed = copy.deepcopy(self.mail)
        changed["transport"]["auth_location"] = "authorization_header"
        changed["capabilities"]["pagination"] = "cursor_pages"
        changed["capabilities"]["code_fields"] = ["otp_value"]

        self.assertEqual(contract_errors(changed, expected_type="mail"), [])
        errors = runtime_conformance_errors(changed)
        self.assertIn("mail runtime authentication location is incompatible", errors)
        self.assertIn("mail runtime does not implement provider pagination", errors)
        self.assertIn("mail runtime code field mapping is incompatible", errors)

    def test_mail_contract_requires_filter_and_watermark_acknowledgement_fields(self) -> None:
        missing_capability = copy.deepcopy(self.mail)
        missing_capability["capabilities"].pop("sender_filter_field")
        missing_request = copy.deepcopy(self.mail)
        missing_request["field_shapes"]["request_fields"].remove("subject_filter")
        missing_response = copy.deepcopy(self.mail)
        missing_response["field_shapes"]["response_fields"].remove("sender")
        missing_boundary_ack = copy.deepcopy(self.mail)
        missing_boundary_ack["field_shapes"]["response_fields"].remove(
            "received_at_or_before"
        )
        missing_basis_ack = copy.deepcopy(self.mail)
        missing_basis_ack["field_shapes"]["response_fields"].remove(
            "watermark_basis"
        )
        missing_received_at = copy.deepcopy(self.mail)
        missing_received_at["field_shapes"]["response_fields"].remove("received_at")

        for document in (
            missing_capability,
            missing_request,
            missing_response,
            missing_boundary_ack,
            missing_basis_ack,
            missing_received_at,
        ):
            with self.subTest(document=document):
                self.assertTrue(contract_errors(document, expected_type="mail"))

        changed = copy.deepcopy(self.mail)
        changed["capabilities"]["sender_filter_field"] = "from_filter"
        changed["field_shapes"]["request_fields"].remove("sender_filter")
        changed["field_shapes"]["request_fields"].append("from_filter")
        self.assertEqual(contract_errors(changed, expected_type="mail"), [])
        self.assertIn(
            "mail runtime sender_filter_field is incompatible",
            runtime_conformance_errors(changed),
        )

    def test_sub2_contract_requires_status_and_unknown_outcome_capabilities(self) -> None:
        missing_status = copy.deepcopy(self.sub2)
        missing_status["capabilities"]["status_query"]["supported"] = False
        missing_lookup = copy.deepcopy(self.sub2)
        missing_lookup["capabilities"]["status_query"]["idempotency_lookup"] = False
        no_unknown = copy.deepcopy(self.sub2)
        no_unknown["capabilities"]["status_query"]["outcomes"].remove("unknown")

        for document in (missing_status, missing_lookup, no_unknown):
            with self.subTest(document=document["capabilities"]["status_query"]):
                self.assertTrue(contract_errors(document, expected_type="sub2"))

    def test_sub2_workflow_is_pending_in_repository_and_complete_when_reviewed(self) -> None:
        workflow = self.sub2["capabilities"]["workflow"]
        self.assertIsNone(workflow["provider_mode"])
        self.assertEqual(
            workflow["operation_order"],
            ["balance_check", "authorization_exchange", "create", "status_query"],
        )
        self.assertTrue(
            all(
                operation["provider_operation_reference"] is None
                for operation in workflow["operations"].values()
            )
        )
        reviewed = self._reviewed_sub2()
        self.assertEqual(contract_errors(reviewed, expected_type="sub2"), [])

    def test_reviewed_contract_requires_current_scoped_source_provenance(self) -> None:
        reviewed = self._reviewed_sub2()
        mutations = []
        wrong_scope = copy.deepcopy(reviewed)
        wrong_scope["source_provenance"]["provider_scope"][
            "provider_account_reference"
        ] = "tbd"
        mutations.append(wrong_scope)
        wrong_digest = copy.deepcopy(reviewed)
        wrong_digest["source_provenance"]["source_sha256"] = "A" * 64
        mutations.append(wrong_digest)
        review_before_capture = copy.deepcopy(reviewed)
        review_before_capture["reviewed_at"] = "2026-08-26T08:00:00Z"
        mutations.append(review_before_capture)
        expired = copy.deepcopy(reviewed)
        expired["source_provenance"]["valid_until"] = "2026-08-27T09:00:00Z"
        mutations.append(expired)
        future_review = copy.deepcopy(reviewed)
        future_review["reviewed_at"] = "2026-08-29T09:00:00Z"
        future_review["source_provenance"]["valid_until"] = (
            "2026-08-30T09:00:00Z"
        )
        mutations.append(future_review)

        evaluated_at = datetime(2026, 8, 28, tzinfo=timezone.utc)
        for document in mutations:
            with self.subTest(document=document["source_provenance"]):
                self.assertTrue(
                    contract_errors(
                        document,
                        expected_type="sub2",
                        evaluated_at=evaluated_at,
                    )
                )

    def test_sub2_workflow_rejects_missing_phase_idempotency_and_query_semantics(self) -> None:
        reviewed = self._reviewed_sub2()
        mutations = []
        wrong_order = copy.deepcopy(reviewed)
        wrong_order["capabilities"]["workflow"]["operation_order"].reverse()
        mutations.append(wrong_order)
        wrong_phase = copy.deepcopy(reviewed)
        wrong_phase["capabilities"]["workflow"]["operations"]["create"][
            "platform_phase"
        ] = "provider_result"
        mutations.append(wrong_phase)
        missing_retention = copy.deepcopy(reviewed)
        missing_retention["capabilities"]["workflow"]["idempotency"][
            "minimum_retention_seconds"
        ] = None
        mutations.append(missing_retention)
        unsafe_not_found = copy.deepcopy(reviewed)
        unsafe_not_found["capabilities"]["workflow"]["status_consistency"][
            "not_found_outcome"
        ] = "failed"
        mutations.append(unsafe_not_found)

        for document in mutations:
            with self.subTest(document=document):
                self.assertTrue(contract_errors(document, expected_type="sub2"))

    def test_sub2_contract_field_shapes_cover_platform_and_result_mappings(self) -> None:
        reviewed = self._reviewed_sub2()
        missing_request = copy.deepcopy(reviewed)
        missing_request["field_shapes"]["request_fields"].remove("policy")
        missing_response = copy.deepcopy(reviewed)
        missing_response["field_shapes"]["response_fields"].remove("status")

        self.assertIn(
            "Sub2 contract request fields are incomplete",
            contract_errors(missing_request, expected_type="sub2"),
        )
        self.assertIn(
            "Sub2 contract response fields are incomplete",
            contract_errors(missing_response, expected_type="sub2"),
        )

    def test_malformed_nested_values_fail_closed_without_type_errors(self) -> None:
        malformed_mail = copy.deepcopy(self.mail)
        malformed_mail["capabilities"]["code_fields"] = [{"field": "code"}]
        malformed_sub2 = copy.deepcopy(self.sub2)
        malformed_sub2["capabilities"]["unknown_http_statuses"] = [
            {"status": 500}
        ]

        self.assertTrue(contract_errors(malformed_mail, expected_type="mail"))
        self.assertTrue(contract_errors(malformed_sub2, expected_type="sub2"))

    def test_contracts_contain_only_field_shapes_not_example_values(self) -> None:
        for document in (self.mail, self.sub2):
            rendered = json.dumps(document, ensure_ascii=False).casefold()
            for forbidden in (
                "bearer ",
                "password",
                "private_key",
                "4111111111111111",
                "verification_code_value",
            ):
                with self.subTest(contract=document["contract_type"], forbidden=forbidden):
                    self.assertNotIn(forbidden, rendered)

    def test_intake_runbook_documents_contract_and_runtime_checks(self) -> None:
        text = (
            Path("deploy/runbooks/target-intake-preflight.md")
            .read_text(encoding="utf-8")
            .casefold()
            .replace("\n", " ")
        )
        for expected in (
            "provider_contract_conformance.py check",
            "--expected-type mail",
            "--expected-type sub2",
            "synthetic contracts cannot satisfy strict intake",
            "status-query gap",
            "balance_check",
            "provider idempotency value is the server-generated `upload_job_id`",
            "phase 4-or-later",
            "exit code 2",
            "not_found",
            "never authorizes an automatic retry",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)

    def test_cli_distinguishes_invalid_contract_from_runtime_gap(self) -> None:
        self.assertEqual(
            main(
                [
                    "check",
                    "--input",
                    str(MAIL_CONTRACT),
                    "--expected-type",
                    "mail",
                ]
            ),
            0,
        )
        self.assertEqual(
            main(
                [
                    "check",
                    "--input",
                    str(SUB2_CONTRACT),
                    "--expected-type",
                    "sub2",
                ]
            ),
            2,
        )
        self.assertEqual(
            main(
                [
                    "check",
                    "--input",
                    str(MAIL_CONTRACT),
                    "--expected-type",
                    "sub2",
                ]
            ),
            1,
        )


if __name__ == "__main__":
    unittest.main()
