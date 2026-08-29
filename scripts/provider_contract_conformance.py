"""Validate redacted provider-contract envelopes and current adapter fit."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.external_json import load_unique_json
from platform.mail_connectors import mail_connector_contract_capabilities
from platform.uploads import sub2_adapter_contract_capabilities


MAIL_CONTRACT = ROOT / "deploy" / "provider-contracts" / "mail.synthetic.json"
SUB2_CONTRACT = ROOT / "deploy" / "provider-contracts" / "sub2.synthetic.json"

_TOP_LEVEL_KEYS = {
    "schema_version",
    "contract_type",
    "provider_reference",
    "synthetic",
    "review_reference",
    "reviewed_at",
    "source_provenance",
    "production_acceptance",
    "transport",
    "capabilities",
    "field_shapes",
    "redaction",
}
_SOURCE_PROVENANCE_KEYS = {
    "provider_scope",
    "source_document_reference",
    "source_version_reference",
    "source_sha256",
    "captured_at",
    "valid_until",
}
_PROVIDER_SCOPE_KEYS = {"environment", "provider_account_reference"}
_TRANSPORT_KEYS = {
    "https_required",
    "redirect_policy",
    "auth_location",
    "max_response_bytes",
}
_FIELD_SHAPE_KEYS = {"request_fields", "response_fields"}
_REDACTION_KEYS = {
    "contains_live_credentials",
    "contains_personal_data",
    "contains_cardholder_data",
    "contains_message_content",
    "contains_verification_codes",
}
_MAIL_CAPABILITY_KEYS = {
    "watermark_at_task_start",
    "watermark_boundary_field",
    "watermark_basis_field",
    "watermark_basis",
    "empty_watermark_statuses",
    "cursor_field",
    "pagination",
    "rate_limit_strategy",
    "waiting_statuses",
    "code_fields",
    "message_id_fields",
    "watermark_fields",
    "sender_filter_field",
    "subject_filter_field",
    "sender_fields",
    "subject_fields",
    "received_at_field",
    "code_digits_min",
    "code_digits_max",
}
_SUB2_CAPABILITY_KEYS = {
    "submit_method",
    "idempotency_location",
    "idempotency_name",
    "provider_idempotency_value",
    "task_correlation_location",
    "task_correlation_name",
    "success_reference_field",
    "pagination",
    "rate_limit_strategy",
    "unknown_http_statuses",
    "status_query",
    "workflow",
}
_STATUS_QUERY_KEYS = {
    "supported",
    "idempotency_lookup",
    "method",
    "reference_location",
    "reference_name",
    "result_field",
    "outcomes",
}
_SUB2_WORKFLOW_KEYS = {
    "operation_order",
    "provider_mode",
    "operations",
    "idempotency",
    "status_consistency",
}
_SUB2_OPERATION_KEYS = {
    "provider_operation_reference",
    "method",
    "request_fields",
    "response_fields",
    "platform_phase",
    "timeout_outcome",
    "automatic_retry",
}
_SUB2_IDEMPOTENCY_KEYS = {
    "scope",
    "minimum_retention_seconds",
    "same_key_same_payload",
    "same_key_different_payload",
}
_SUB2_STATUS_CONSISTENCY_KEYS = {
    "model",
    "maximum_visibility_delay_seconds",
    "minimum_retention_seconds",
    "not_found_outcome",
}
_SUB2_OPERATION_ORDER = (
    "balance_check",
    "authorization_exchange",
    "create",
    "status_query",
)
_SUB2_OPERATION_PHASES = {
    "balance_check": "provider_submit",
    "authorization_exchange": "provider_submit",
    "create": "provider_submit",
    "status_query": "reconciliation_check",
}
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_FIELD_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ENVIRONMENT = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
_UTC_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)
_PLACEHOLDERS = {"example", "placeholder", "tbd", "todo", "unknown"}
_EXPECTED_SUB2_GAP = [
    "sub2 provider workflow is unverified",
    "sub2 runtime does not implement status query",
    "sub2 runtime does not implement idempotency lookup",
]


def _safe_reference(value: Any) -> bool:
    return (
        isinstance(value, str)
        and _REFERENCE.fullmatch(value) is not None
        and value.casefold() not in _PLACEHOLDERS
    )


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or _UTC_TIMESTAMP.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed if parsed.tzinfo == timezone.utc else None


def _field_names(value: Any, *, nonempty: bool = True) -> bool:
    if not isinstance(value, list) or (nonempty and not value):
        return False
    if not all(
        isinstance(item, str) and _FIELD_NAME.fullmatch(item) is not None
        for item in value
    ):
        return False
    return len(value) == len(set(value))


def _status_codes(value: Any) -> bool:
    if not isinstance(value, list) or not value:
        return False
    if not all(isinstance(item, int) and 400 <= item <= 599 for item in value):
        return False
    return value == sorted(set(value))


def _common_errors(
    document: dict[str, Any],
    expected_type: str | None,
    *,
    evaluated_at: datetime | None,
) -> list[str]:
    errors: list[str] = []
    contract_type = document.get("contract_type")
    expected_schema = {"mail": 2, "sub2": 3}.get(contract_type)
    if contract_type not in {"mail", "sub2"} or document.get(
        "schema_version"
    ) != expected_schema:
        errors.append("provider contract identity is invalid")
    if expected_type is not None and contract_type != expected_type:
        errors.append("provider contract type does not match the expected intake item")
    if document.get("production_acceptance") is not False:
        errors.append("provider contract must not claim production acceptance")
    provider_reference = document.get("provider_reference")
    synthetic = document.get("synthetic")
    review_reference = document.get("review_reference")
    reviewed_at = document.get("reviewed_at")
    source = document.get("source_provenance")
    if not _safe_reference(provider_reference) or not isinstance(synthetic, bool):
        errors.append("provider contract reference is invalid")
    elif synthetic:
        if (
            not provider_reference.startswith("synthetic-")
            or review_reference is not None
            or reviewed_at is not None
            or source
            != {
                "provider_scope": {
                    "environment": None,
                    "provider_account_reference": None,
                },
                "source_document_reference": None,
                "source_version_reference": None,
                "source_sha256": None,
                "captured_at": None,
                "valid_until": None,
            }
        ):
            errors.append("synthetic provider contract review metadata is invalid")
    else:
        reviewed = _parse_utc(reviewed_at)
        captured = (
            _parse_utc(source.get("captured_at")) if isinstance(source, dict) else None
        )
        valid_until = (
            _parse_utc(source.get("valid_until")) if isinstance(source, dict) else None
        )
        if not _safe_reference(review_reference) or reviewed is None:
            errors.append("real provider contract requires canonical review metadata")
        if (
            not isinstance(source, dict)
            or set(source) != _SOURCE_PROVENANCE_KEYS
            or not isinstance(source.get("provider_scope"), dict)
            or set(source["provider_scope"]) != _PROVIDER_SCOPE_KEYS
            or not isinstance(source["provider_scope"].get("environment"), str)
            or _ENVIRONMENT.fullmatch(source["provider_scope"]["environment"])
            is None
            or source["provider_scope"]["environment"].casefold() in _PLACEHOLDERS
            or not _safe_reference(
                source["provider_scope"].get("provider_account_reference")
            )
            or not _safe_reference(source.get("source_document_reference"))
            or not _safe_reference(source.get("source_version_reference"))
            or not isinstance(source.get("source_sha256"), str)
            or _SHA256.fullmatch(source["source_sha256"]) is None
            or captured is None
            or valid_until is None
        ):
            errors.append("real provider contract source provenance is invalid")
        elif reviewed is not None and not captured <= reviewed < valid_until:
            errors.append("real provider contract source timeline is invalid")
        elif valid_until <= (evaluated_at or datetime.now(timezone.utc)):
            errors.append("real provider contract source provenance is expired")

    transport = document.get("transport")
    if not isinstance(transport, dict) or set(transport) != _TRANSPORT_KEYS:
        errors.append("provider contract transport schema is invalid")
    else:
        if transport.get("https_required") is not True:
            errors.append("provider contract must require HTTPS")
        if transport.get("redirect_policy") != "forbid":
            errors.append("provider contract must forbid redirects")
        if transport.get("auth_location") not in {
            "authorization_header",
            "request_json.mailbox",
            "request_json.credentials",
        }:
            errors.append("provider contract authentication location is invalid")
        maximum = transport.get("max_response_bytes")
        if not isinstance(maximum, int) or not 1 <= maximum <= 1024 * 1024:
            errors.append("provider contract response-size limit is invalid")

    field_shapes = document.get("field_shapes")
    if not isinstance(field_shapes, dict) or set(field_shapes) != _FIELD_SHAPE_KEYS:
        errors.append("provider contract field-shape schema is invalid")
    elif not _field_names(field_shapes.get("request_fields")) or not _field_names(
        field_shapes.get("response_fields")
    ):
        errors.append("provider contract field shapes are invalid")

    redaction = document.get("redaction")
    if not isinstance(redaction, dict) or set(redaction) != _REDACTION_KEYS:
        errors.append("provider contract redaction schema is invalid")
    elif any(redaction.get(key) is not False for key in _REDACTION_KEYS):
        errors.append("provider contract must contain field shapes only")
    return errors


def _mail_errors(capabilities: Any) -> list[str]:
    if not isinstance(capabilities, dict) or set(capabilities) != _MAIL_CAPABILITY_KEYS:
        return ["mail contract capability schema is invalid"]
    errors: list[str] = []
    if capabilities.get("watermark_at_task_start") is not True:
        errors.append("mail contract must establish a task-start watermark")
    if not _FIELD_NAME.fullmatch(
        str(capabilities.get("watermark_boundary_field", ""))
    ):
        errors.append("mail contract watermark boundary field is invalid")
    if not _FIELD_NAME.fullmatch(
        str(capabilities.get("watermark_basis_field", ""))
    ):
        errors.append("mail contract watermark basis field is invalid")
    if capabilities.get("watermark_basis") != "task_created_at":
        errors.append("mail contract watermark basis must be task_created_at")
    if not _FIELD_NAME.fullmatch(str(capabilities.get("cursor_field", ""))):
        errors.append("mail contract cursor field is invalid")
    if capabilities.get("pagination") not in {"single_response", "cursor_pages"}:
        errors.append("mail contract pagination mode is invalid")
    if capabilities.get("rate_limit_strategy") not in {
        "fixed_poll_interval",
        "retry_after",
        "bounded_backoff",
    }:
        errors.append("mail contract rate-limit strategy is invalid")
    for key in (
        "waiting_statuses",
        "empty_watermark_statuses",
        "code_fields",
        "message_id_fields",
        "watermark_fields",
        "sender_fields",
        "subject_fields",
    ):
        if not _field_names(capabilities.get(key)):
            errors.append(f"mail contract {key} are invalid")
    for key in ("sender_filter_field", "subject_filter_field", "received_at_field"):
        if not _FIELD_NAME.fullmatch(str(capabilities.get(key, ""))):
            errors.append(f"mail contract {key} is invalid")
    minimum = capabilities.get("code_digits_min")
    maximum = capabilities.get("code_digits_max")
    if (
        not isinstance(minimum, int)
        or not isinstance(maximum, int)
        or not 1 <= minimum <= maximum <= 16
    ):
        errors.append("mail contract code digit bounds are invalid")
    return errors


def _sub2_workflow_errors(workflow: Any, *, synthetic: bool) -> list[str]:
    if not isinstance(workflow, dict) or set(workflow) != _SUB2_WORKFLOW_KEYS:
        return ["Sub2 workflow schema is invalid"]
    errors: list[str] = []
    if workflow.get("operation_order") != list(_SUB2_OPERATION_ORDER):
        errors.append("Sub2 workflow operation order is invalid")
    operations = workflow.get("operations")
    if not isinstance(operations, dict) or set(operations) != set(
        _SUB2_OPERATION_ORDER
    ):
        errors.append("Sub2 workflow operation inventory is invalid")
    else:
        for operation in _SUB2_OPERATION_ORDER:
            details = operations.get(operation)
            if not isinstance(details, dict) or set(details) != _SUB2_OPERATION_KEYS:
                errors.append(f"Sub2 workflow {operation} schema is invalid")
                continue
            if (
                details.get("platform_phase") != _SUB2_OPERATION_PHASES[operation]
                or details.get("timeout_outcome") != "unknown"
                or details.get("automatic_retry") is not False
            ):
                errors.append(f"Sub2 workflow {operation} safety mapping is invalid")
            if synthetic:
                if (
                    details.get("provider_operation_reference") is not None
                    or details.get("method") is not None
                    or details.get("request_fields") != []
                    or details.get("response_fields") != []
                ):
                    errors.append(
                        f"synthetic Sub2 workflow {operation} mapping must remain pending"
                    )
            elif (
                not _safe_reference(details.get("provider_operation_reference"))
                or details.get("method") not in {"GET", "POST", "PUT"}
                or not _field_names(details.get("request_fields"))
                or not _field_names(details.get("response_fields"))
            ):
                errors.append(f"reviewed Sub2 workflow {operation} mapping is invalid")

    provider_mode = workflow.get("provider_mode")
    idempotency = workflow.get("idempotency")
    consistency = workflow.get("status_consistency")
    if not isinstance(idempotency, dict) or set(idempotency) != _SUB2_IDEMPOTENCY_KEYS:
        errors.append("Sub2 workflow idempotency schema is invalid")
    if not isinstance(consistency, dict) or set(
        consistency
    ) != _SUB2_STATUS_CONSISTENCY_KEYS:
        errors.append("Sub2 workflow status consistency schema is invalid")
    if synthetic:
        if provider_mode is not None:
            errors.append("synthetic Sub2 provider mode must remain pending")
        if isinstance(idempotency, dict) and any(
            value is not None for value in idempotency.values()
        ):
            errors.append("synthetic Sub2 idempotency semantics must remain pending")
        if isinstance(consistency, dict) and (
            consistency.get("model") is not None
            or consistency.get("maximum_visibility_delay_seconds") is not None
            or consistency.get("minimum_retention_seconds") is not None
            or consistency.get("not_found_outcome") != "unknown"
        ):
            errors.append("synthetic Sub2 status consistency must remain pending")
        return errors

    if provider_mode not in {"atomic_create", "ordered_multi_step"}:
        errors.append("reviewed Sub2 provider mode is invalid")
    if isinstance(idempotency, dict) and (
        idempotency.get("scope")
        not in {"global", "provider_account", "credential", "group"}
        or type(idempotency.get("minimum_retention_seconds")) is not int
        or not 1 <= idempotency["minimum_retention_seconds"] <= 31_536_000
        or idempotency.get("same_key_same_payload") != "same_result"
        or idempotency.get("same_key_different_payload") != "reject"
    ):
        errors.append("reviewed Sub2 idempotency semantics are invalid")
    if isinstance(consistency, dict) and (
        consistency.get("model") not in {"strong", "eventual"}
        or type(consistency.get("maximum_visibility_delay_seconds")) is not int
        or not 0 <= consistency["maximum_visibility_delay_seconds"] <= 86_400
        or type(consistency.get("minimum_retention_seconds")) is not int
        or not 1 <= consistency["minimum_retention_seconds"] <= 31_536_000
        or consistency.get("not_found_outcome") != "unknown"
    ):
        errors.append("reviewed Sub2 status consistency is invalid")
    return errors


def _sub2_errors(capabilities: Any, *, synthetic: bool) -> list[str]:
    if not isinstance(capabilities, dict) or set(capabilities) != _SUB2_CAPABILITY_KEYS:
        return ["Sub2 contract capability schema is invalid"]
    errors: list[str] = []
    if capabilities.get("submit_method") not in {"POST", "PUT"}:
        errors.append("Sub2 contract submit method is invalid")
    for location_key in ("idempotency_location", "task_correlation_location"):
        if capabilities.get(location_key) not in {"header", "request_body"}:
            errors.append(f"Sub2 contract {location_key} is invalid")
    for field_key in (
        "idempotency_name",
        "task_correlation_name",
        "success_reference_field",
    ):
        value = capabilities.get(field_key)
        if not isinstance(value, str) or _FIELD_NAME.fullmatch(value) is None:
            errors.append(f"Sub2 contract {field_key} is invalid")
    if capabilities.get("provider_idempotency_value") != "upload_job_id":
        errors.append("Sub2 contract provider idempotency value is invalid")
    if capabilities.get("pagination") not in {"not_applicable", "cursor_pages"}:
        errors.append("Sub2 contract pagination mode is invalid")
    if capabilities.get("rate_limit_strategy") not in {
        "unknown_on_429",
        "retry_after",
        "bounded_backoff",
    }:
        errors.append("Sub2 contract rate-limit strategy is invalid")
    if not _status_codes(capabilities.get("unknown_http_statuses")):
        errors.append("Sub2 contract unknown HTTP statuses are invalid")

    status_query = capabilities.get("status_query")
    if not isinstance(status_query, dict) or set(status_query) != _STATUS_QUERY_KEYS:
        errors.append("Sub2 status-query schema is invalid")
    else:
        if status_query.get("supported") is not True:
            errors.append("Sub2 contract must provide status query")
        if status_query.get("idempotency_lookup") is not True:
            errors.append("Sub2 contract must provide idempotency lookup")
        if status_query.get("method") not in {"GET", "POST"}:
            errors.append("Sub2 status-query method is invalid")
        if status_query.get("reference_location") not in {
            "path",
            "query",
            "request_body",
        }:
            errors.append("Sub2 status-query reference location is invalid")
        for field_key in ("reference_name", "result_field"):
            value = status_query.get(field_key)
            if not isinstance(value, str) or _FIELD_NAME.fullmatch(value) is None:
                errors.append(f"Sub2 status-query {field_key} is invalid")
        outcomes = status_query.get("outcomes")
        if not _field_names(outcomes) or set(outcomes) != {
            "processing",
            "succeeded",
            "failed",
            "not_found",
            "unknown",
        }:
            errors.append("Sub2 status-query outcomes are incomplete")
    errors.extend(
        _sub2_workflow_errors(capabilities.get("workflow"), synthetic=synthetic)
    )
    return errors


def contract_errors(
    document: Any,
    *,
    expected_type: str | None = None,
    evaluated_at: datetime | None = None,
) -> list[str]:
    if not isinstance(document, dict) or set(document) != _TOP_LEVEL_KEYS:
        return ["provider contract top-level schema is invalid"]
    errors = _common_errors(document, expected_type, evaluated_at=evaluated_at)
    if document.get("contract_type") == "mail":
        capabilities = document.get("capabilities")
        errors.extend(_mail_errors(capabilities))
        field_shapes = document.get("field_shapes")
        if isinstance(capabilities, dict) and isinstance(field_shapes, dict):
            request_fields = field_shapes.get("request_fields")
            response_fields = field_shapes.get("response_fields")
            if isinstance(request_fields, list) and any(
                capabilities.get(key) not in request_fields
                for key in (
                    "watermark_boundary_field",
                    "sender_filter_field",
                    "subject_filter_field",
                )
            ):
                errors.append("mail contract request fields are incomplete")
            if isinstance(response_fields, list) and any(
                not set(capabilities.get(key, ())).issubset(response_fields)
                for key in ("sender_fields", "subject_fields")
            ):
                errors.append("mail contract filter response fields are incomplete")
            if isinstance(response_fields, list) and any(
                capabilities.get(key) not in response_fields
                for key in (
                    "watermark_boundary_field",
                    "watermark_basis_field",
                    "received_at_field",
                )
            ):
                errors.append(
                    "mail contract watermark acknowledgement fields are incomplete"
                )
    elif document.get("contract_type") == "sub2":
        capabilities = document.get("capabilities")
        errors.extend(
            _sub2_errors(
                capabilities,
                synthetic=document.get("synthetic") is True,
            )
        )
        field_shapes = document.get("field_shapes")
        if isinstance(capabilities, dict) and isinstance(field_shapes, dict):
            request_fields = field_shapes.get("request_fields")
            response_fields = field_shapes.get("response_fields")
            if isinstance(request_fields, list) and not {
                "job_id",
                "task_id",
                "business_name",
                "card",
                "policy",
            }.issubset(request_fields):
                errors.append("Sub2 contract request fields are incomplete")
            status_query = capabilities.get("status_query")
            required_response_fields = {capabilities.get("success_reference_field")}
            if isinstance(status_query, dict):
                required_response_fields.add(status_query.get("result_field"))
            if isinstance(response_fields, list) and not required_response_fields.issubset(
                response_fields
            ):
                errors.append("Sub2 contract response fields are incomplete")
    return errors


def runtime_conformance_errors(document: Any) -> list[str]:
    schema_errors = contract_errors(document)
    if schema_errors:
        return ["provider contract must be valid before runtime conformance"]
    transport = document["transport"]
    capabilities = document["capabilities"]
    errors: list[str] = []
    if document["contract_type"] == "mail":
        runtime = mail_connector_contract_capabilities()
        if capabilities["watermark_at_task_start"] is not runtime[
            "watermark_at_task_start"
        ]:
            errors.append("mail runtime task-start watermark is incompatible")
        if transport["max_response_bytes"] > runtime["max_response_bytes"]:
            errors.append("runtime response-size limit is lower than provider contract")
        if transport["auth_location"] != runtime["auth_location"]:
            errors.append("mail runtime authentication location is incompatible")
        if capabilities["cursor_field"] != runtime["cursor_field"]:
            errors.append("mail runtime cursor field is incompatible")
        if capabilities["watermark_boundary_field"] != runtime["watermark_boundary_field"]:
            errors.append("mail runtime watermark boundary field is incompatible")
        if capabilities["watermark_basis_field"] != runtime["watermark_basis_field"]:
            errors.append("mail runtime watermark basis field is incompatible")
        if capabilities["watermark_basis"] != runtime["watermark_basis"]:
            errors.append("mail runtime watermark basis is incompatible")
        for key in (
            "sender_filter_field",
            "subject_filter_field",
            "received_at_field",
        ):
            if capabilities[key] != runtime[key]:
                errors.append(f"mail runtime {key} is incompatible")
        if capabilities["pagination"] != runtime["pagination"]:
            errors.append("mail runtime does not implement provider pagination")
        if capabilities["rate_limit_strategy"] != runtime["rate_limit_strategy"]:
            errors.append("mail runtime rate-limit strategy is incompatible")
        mappings = (
            ("waiting_statuses", "waiting_statuses", "waiting status"),
            (
                "empty_watermark_statuses",
                "empty_watermark_statuses",
                "empty watermark status",
            ),
            ("code_fields", "code_fields", "code field"),
            ("message_id_fields", "message_id_fields", "message-id field"),
            ("watermark_fields", "watermark_fields", "watermark field"),
            ("sender_fields", "sender_fields", "sender field"),
            ("subject_fields", "subject_fields", "subject field"),
        )
        for contract_key, runtime_key, label in mappings:
            if not set(capabilities[contract_key]).issubset(set(runtime[runtime_key])):
                errors.append(f"mail runtime {label} mapping is incompatible")
        if (
            capabilities["code_digits_min"] < runtime["code_digits_min"]
            or capabilities["code_digits_max"] > runtime["code_digits_max"]
        ):
            errors.append("mail runtime code digit bounds are incompatible")
        return errors

    runtime = sub2_adapter_contract_capabilities()
    if transport["max_response_bytes"] > runtime["max_response_bytes"]:
        errors.append("runtime response-size limit is lower than provider contract")
    if transport["auth_location"] != runtime["auth_location"]:
        errors.append("sub2 runtime authentication location is incompatible")
    if capabilities["submit_method"] != runtime["submit_method"]:
        errors.append("sub2 runtime submit method is incompatible")
    if (
        capabilities["idempotency_location"] != runtime["idempotency_location"]
        or capabilities["idempotency_name"].casefold()
        != str(runtime["idempotency_name"]).casefold()
        or capabilities["provider_idempotency_value"]
        != runtime["provider_idempotency_value"]
    ):
        errors.append("sub2 runtime idempotency placement is incompatible")
    if (
        capabilities["task_correlation_location"]
        != runtime["task_correlation_location"]
        or capabilities["task_correlation_name"].casefold()
        != str(runtime["task_correlation_name"]).casefold()
    ):
        errors.append("sub2 runtime task correlation is incompatible")
    if capabilities["success_reference_field"] != runtime["success_reference_field"]:
        errors.append("sub2 runtime success mapping is incompatible")
    if capabilities["pagination"] != runtime["pagination"]:
        errors.append("sub2 runtime does not implement provider pagination")
    if capabilities["rate_limit_strategy"] != runtime["rate_limit_strategy"]:
        errors.append("sub2 runtime rate-limit strategy is incompatible")
    if set(capabilities["unknown_http_statuses"]).intersection(
        runtime["definitive_rejection_statuses"]
    ):
        errors.append("sub2 runtime unknown-outcome classification is incompatible")
    if not runtime["lookup_protocol_supported"] or set(
        capabilities["status_query"]["outcomes"]
    ) != set(runtime["lookup_outcomes"]):
        errors.append("sub2 runtime lookup outcome protocol is incompatible")
    if capabilities["workflow"]["provider_mode"] is None:
        errors.append("sub2 provider workflow is unverified")
    elif capabilities["workflow"]["provider_mode"] == "ordered_multi_step":
        errors.append("sub2 runtime does not implement reviewed multi-step workflow")
    if not runtime["status_query_supported"]:
        errors.append("sub2 runtime does not implement status query")
    if not runtime["idempotency_lookup_supported"]:
        errors.append("sub2 runtime does not implement idempotency lookup")
    return errors


def _load(path: Path) -> Any:
    return load_unique_json(path)


def _verify_repository() -> list[str]:
    errors: list[str] = []
    try:
        mail = _load(MAIL_CONTRACT)
        sub2 = _load(SUB2_CONTRACT)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return ["repository provider contracts are unreadable"]
    errors.extend(contract_errors(mail, expected_type="mail"))
    errors.extend(contract_errors(sub2, expected_type="sub2"))
    if not errors and runtime_conformance_errors(mail):
        errors.append("synthetic mail contract must fit the current generic connector")
    if not errors and runtime_conformance_errors(sub2) != _EXPECTED_SUB2_GAP:
        errors.append("synthetic Sub2 contract no longer exposes the reviewed runtime gap")
    return errors


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify-repository")
    check = commands.add_parser("check")
    check.add_argument("--input", required=True, type=Path)
    check.add_argument("--expected-type", required=True, choices=("mail", "sub2"))
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "verify-repository":
        errors = _verify_repository()
        if errors:
            print("; ".join(errors), file=sys.stderr)
            return 1
        print(
            "provider-contracts-ok mail=conformant "
            "sub2=workflow-and-query-gap production_acceptance=false"
        )
        return 0
    try:
        document = _load(arguments.input)
    except (OSError, UnicodeError, json.JSONDecodeError):
        print("provider-contract-invalid", file=sys.stderr)
        return 1
    errors = contract_errors(document, expected_type=arguments.expected_type)
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    conformance = runtime_conformance_errors(document)
    if conformance:
        print("; ".join(conformance), file=sys.stderr)
        return 2
    print(
        f"provider-contract-conformant type={arguments.expected_type} "
        "production_acceptance=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
