from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

from scripts.align_sub2_har_contract import OPERATIONS, alignment_errors


ROOT = Path(__file__).resolve().parents[1]
EVALUATED_AT = datetime(2026, 9, 3, tzinfo=timezone.utc)
SOURCE_SHA256 = "1" * 64
SUMMARY_ARTIFACT_SHA256 = "3" * 64
MAPPING = {
    "balance_check": 1,
    "authorization_exchange": 2,
    "create": 3,
    "status_query": 4,
}


def _entry(
    source_index: int,
    method: str,
    path: str,
    *,
    request_fields: list[str],
    response_fields: list[str],
    headers: list[str] | None = None,
    query: list[str] | None = None,
) -> dict[str, object]:
    return {
        "source_index": source_index,
        "method": method,
        "path": path,
        "query_fields": sorted(query or []),
        "request_header_names": sorted(headers or ["authorization"]),
        "auth_location": "authorization_header",
        "request_body_kind": "json_object",
        "request_fields": sorted(request_fields),
        "status": 200,
        "response_header_names": ["content-type"],
        "response_body_kind": "json_object",
        "response_fields": sorted(response_fields),
    }


def _summary() -> dict[str, object]:
    entries = [
        _entry(
            1,
            "GET",
            "/api/v1/admin/balance",
            request_fields=["account_id"],
            response_fields=["balance"],
        ),
        _entry(
            2,
            "POST",
            "/api/v1/admin/authorization/exchange",
            request_fields=["code"],
            response_fields=["authorization_id"],
        ),
        _entry(
            3,
            "POST",
            "/api/v1/admin/accounts",
            request_fields=["account"],
            response_fields=["external_ref"],
            headers=["authorization", "idempotency-key", "x-platform-task-id"],
        ),
        _entry(
            4,
            "GET",
            "/api/v1/admin/accounts/status",
            request_fields=["idempotency_key"],
            response_fields=["status"],
            query=["idempotency_key"],
        ),
    ]
    return {
        "schema_version": 1,
        "record_type": "sub2_har_shape_summary",
        "provider_origin": "https://provider.example.test",
        "source_sha256": SOURCE_SHA256,
        "production_acceptance": False,
        "entry_count": len(entries),
        "entries": entries,
        "redaction": {
            "contains_header_values": False,
            "contains_query_values": False,
            "contains_request_values": False,
            "contains_response_values": False,
            "contains_source_path": False,
        },
    }


def _contract() -> dict[str, object]:
    contract = json.loads(
        (ROOT / "deploy" / "provider-contracts" / "sub2.synthetic.json").read_text(
            encoding="utf-8"
        )
    )
    contract.update(
        {
            "provider_reference": "provider-contract-2026-09",
            "synthetic": False,
            "review_reference": "review-2026-09",
            "reviewed_at": "2026-09-02T00:00:00Z",
        }
    )
    contract["source_provenance"] = {
        "provider_scope": {
            "environment": "production",
            "provider_account_reference": "provider-account-01",
        },
        "source_document_reference": "sub2-har-capture-01",
        "source_version_reference": "sub2-har-version-01",
        "source_sha256": SUMMARY_ARTIFACT_SHA256,
        "captured_at": "2026-09-01T00:00:00Z",
        "valid_until": "2026-10-01T00:00:00Z",
    }
    workflow = contract["capabilities"]["workflow"]
    workflow["provider_mode"] = "ordered_multi_step"
    operation_shapes = {
        "balance_check": ("GET", ["account_id"], ["balance"]),
        "authorization_exchange": ("POST", ["code"], ["authorization_id"]),
        "create": ("POST", ["account"], ["external_ref"]),
        "status_query": ("GET", ["idempotency_key"], ["status"]),
    }
    for operation in OPERATIONS:
        method, request_fields, response_fields = operation_shapes[operation]
        details = workflow["operations"][operation]
        details.update(
            {
                "provider_operation_reference": f"provider-op-{operation}",
                "method": method,
                "request_fields": request_fields,
                "response_fields": response_fields,
            }
        )
    workflow["idempotency"] = {
        "scope": "provider_account",
        "minimum_retention_seconds": 86400,
        "same_key_same_payload": "same_result",
        "same_key_different_payload": "reject",
    }
    workflow["status_consistency"] = {
        "model": "eventual",
        "maximum_visibility_delay_seconds": 30,
        "minimum_retention_seconds": 86400,
        "not_found_outcome": "unknown",
    }
    return contract


class AlignSub2HarContractTests(unittest.TestCase):
    def test_four_explicit_stage_mappings_align(self) -> None:
        self.assertEqual(
            alignment_errors(
                _summary(),
                _contract(),
                MAPPING,
                summary_artifact_sha256=SUMMARY_ARTIFACT_SHA256,
                evaluated_at=EVALUATED_AT,
            ),
            [],
        )

    def test_rejects_wrong_source_index_method_and_field_overclaims(self) -> None:
        contract = _contract()
        contract["source_provenance"]["source_sha256"] = "2" * 64
        operations = contract["capabilities"]["workflow"]["operations"]
        operations["balance_check"]["method"] = "PUT"
        operations["authorization_exchange"]["request_fields"].append(
            "unobserved_request"
        )
        operations["create"]["response_fields"].append("unobserved_response")
        mapping = {**MAPPING, "status_query": 99}

        errors = alignment_errors(
            _summary(),
            contract,
            mapping,
            summary_artifact_sha256=SUMMARY_ARTIFACT_SHA256,
            evaluated_at=EVALUATED_AT,
        )

        self.assertEqual(
            errors,
            sorted(
                {
                    "authorization_exchange_request_overclaim",
                    "balance_check_method_mismatch",
                    "create_response_overclaim",
                    "source_sha256_mismatch",
                    "status_query_source_missing",
                }
            ),
        )

    def test_rejects_unobserved_idempotency_without_echoing_names(self) -> None:
        summary = deepcopy(_summary())
        summary["entries"][2]["request_header_names"] = ["authorization"]
        summary["entries"][3]["query_fields"] = []
        contract = _contract()
        secret_marker = "TOPSECRETFIELDVALUE"
        contract["capabilities"]["workflow"]["operations"]["create"][
            "request_fields"
        ].append(secret_marker)

        errors = alignment_errors(
            summary,
            contract,
            MAPPING,
            summary_artifact_sha256=SUMMARY_ARTIFACT_SHA256,
            evaluated_at=EVALUATED_AT,
        )

        self.assertIn("create_idempotency_unobserved", errors)
        self.assertIn("create_request_overclaim", errors)
        self.assertIn("create_task_correlation_unobserved", errors)
        self.assertIn("status_query_reference_unobserved", errors)
        self.assertNotIn(secret_marker, " ".join(errors))


if __name__ == "__main__":
    unittest.main()
