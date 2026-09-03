"""Validate the non-authoritative Sub2 interface observation from the case site."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.external_json import MAX_INTAKE_JSON_BYTES, load_unique_json


OBSERVATION = ROOT / "deploy" / "provider-observations" / "sub2-case-2026-09-01.json"

_TOP_LEVEL_KEYS = {
    "schema_version",
    "record_type",
    "observed_at",
    "observation_scope",
    "production_acceptance",
    "review_status",
    "source",
    "operations",
    "negative_findings",
    "remaining_required_inputs",
    "redaction",
}
_SOURCE_KEYS = {
    "page_url",
    "authentication_state",
    "scanned_same_origin_script_count",
    "assets",
    "user_supplied_examples",
}
_ASSET_KEYS = {"name", "url", "sha256", "byte_length"}
_EXAMPLE_KEYS = {"operation_id", "scope"}
_OPERATION_KEYS = {
    "operation_id",
    "evidence",
    "method",
    "path",
    "request",
    "response",
    "limitations",
}
_REQUEST_KEYS = {"path_fields", "query_fields", "header_fields", "body_fields"}
_RESPONSE_KEYS = {"header_fields", "body_fields", "derived_fields"}
_REDACTION_KEYS = {
    "contains_live_credentials",
    "contains_personal_data",
    "contains_cardholder_data",
    "contains_message_content",
    "contains_verification_codes",
    "contains_cookie_values",
    "contains_session_values",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FIELD = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")

_EXPECTED_ASSETS = (
    (
        "index-BO-GxV3d.js",
        "https://ai1.aisb.shop/assets/index-BO-GxV3d.js",
        "ccb6a54723a4be14442fdb39531e4691cd41937f7a66c42b7cda62e86ac7ef36",
        174500,
    ),
    (
        "AccountsView-CMV6VUuq.js",
        "https://ai1.aisb.shop/assets/AccountsView-CMV6VUuq.js",
        "989a33965eb180e1b37245a3cdbc478a158c32928deb35d7bba0452ea922c0d1",
        669867,
    ),
)
_EXPECTED_OPERATIONS = (
    ("account_list", "GET", "/api/v1/admin/accounts"),
    (
        "account_get_by_id",
        "GET",
        "/api/v1/admin/accounts/{account_id}",
    ),
    (
        "openai_generate_auth_url",
        "POST",
        "/api/v1/admin/openai/generate-auth-url",
    ),
    ("openai_exchange_code", "POST", "/api/v1/admin/openai/exchange-code"),
    ("account_create", "POST", "/api/v1/admin/accounts"),
    (
        "account_today_stats_batch",
        "POST",
        "/api/v1/admin/accounts/today-stats/batch",
    ),
    (
        "account_duplicate",
        "POST",
        "/api/v1/admin/accounts/{account_id}/duplicate",
    ),
)
_REQUIRED_NEGATIVE_FINDINGS = {
    "balance_check_endpoint_not_observed",
    "legacy_check_concurrency_limit_not_observed",
    "account_create_idempotency_header_not_observed",
    "account_create_status_query_not_observed",
    "authenticated_response_samples_not_captured",
    "provider_idempotency_and_consistency_semantics_not_proven",
}


def _exact_mapping(value: Any, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def _strings(value: Any, *, allow_empty: bool = False) -> bool:
    return (
        isinstance(value, list)
        and (allow_empty or bool(value))
        and len(value) == len(set(value))
        and all(
            isinstance(item, str)
            and bool(item)
            and item.strip() == item
            for item in value
        )
    )


def _field_list(value: Any) -> bool:
    return _strings(value, allow_empty=True) and all(
        _FIELD.fullmatch(item) is not None for item in value
    )


def observation_errors(document: Any) -> list[str]:
    if not _exact_mapping(document, _TOP_LEVEL_KEYS):
        return ["Sub2 case observation top-level schema is invalid"]
    errors: list[str] = []
    try:
        observed_at = datetime.fromisoformat(
            str(document.get("observed_at", "")).replace("Z", "+00:00")
        )
    except ValueError:
        observed_at = None
    if (
        document.get("schema_version") != 1
        or document.get("record_type") != "sub2_public_interface_observation"
        or document.get("observation_scope")
        != "request_shape_and_public_frontend_only"
        or document.get("production_acceptance") is not False
        or document.get("review_status") != "unreviewed"
        or observed_at is None
        or observed_at.tzinfo is None
    ):
        errors.append("Sub2 case observation identity is invalid")

    source = document.get("source")
    if not _exact_mapping(source, _SOURCE_KEYS):
        errors.append("Sub2 case observation source schema is invalid")
    else:
        assets = source.get("assets")
        if (
            source.get("page_url")
            != "https://ai1.aisb.shop/login?redirect=/admin/dashboard"
            or source.get("authentication_state") != "logged_out_redirect"
            or source.get("scanned_same_origin_script_count") != 64
            or not isinstance(assets, list)
            or len(assets) != len(_EXPECTED_ASSETS)
        ):
            errors.append("Sub2 case observation source identity is invalid")
        else:
            for asset, expected in zip(assets, _EXPECTED_ASSETS, strict=True):
                if (
                    not _exact_mapping(asset, _ASSET_KEYS)
                    or tuple(asset.get(key) for key in ("name", "url", "sha256", "byte_length"))
                    != expected
                    or _SHA256.fullmatch(str(asset.get("sha256", ""))) is None
                ):
                    errors.append("Sub2 case observation asset inventory is invalid")
                    break
        examples = source.get("user_supplied_examples")
        expected_example_ids = {
            "openai_generate_auth_url",
            "openai_exchange_code",
            "account_today_stats_batch",
        }
        if (
            not isinstance(examples, list)
            or {item.get("operation_id") for item in examples if isinstance(item, dict)}
            != expected_example_ids
            or any(
                not _exact_mapping(item, _EXAMPLE_KEYS)
                or item.get("scope") != "request_shape_only"
                for item in examples
            )
        ):
            errors.append("Sub2 case observation example inventory is invalid")

    operations = document.get("operations")
    if (
        not isinstance(operations, list)
        or len(operations) != len(_EXPECTED_OPERATIONS)
    ):
        errors.append("Sub2 case observation operation inventory is invalid")
    else:
        for operation, expected in zip(operations, _EXPECTED_OPERATIONS, strict=True):
            if (
                not _exact_mapping(operation, _OPERATION_KEYS)
                or tuple(operation.get(key) for key in ("operation_id", "method", "path"))
                != expected
                or not _strings(operation.get("evidence"))
                or not _strings(operation.get("limitations"))
            ):
                errors.append("Sub2 case observation operation mapping is invalid")
                continue
            request = operation.get("request")
            response = operation.get("response")
            if (
                not _exact_mapping(request, _REQUEST_KEYS)
                or any(not _field_list(request.get(key)) for key in _REQUEST_KEYS)
                or not _exact_mapping(response, _RESPONSE_KEYS)
                or any(not _field_list(response.get(key)) for key in _RESPONSE_KEYS)
            ):
                errors.append(
                    f"Sub2 case observation {operation['operation_id']} field shape is invalid"
                )

    findings = document.get("negative_findings")
    if not _strings(findings) or set(findings) != _REQUIRED_NEGATIVE_FINDINGS:
        errors.append("Sub2 case observation negative findings are incomplete")
    if not _strings(document.get("remaining_required_inputs")):
        errors.append("Sub2 case observation remaining-input inventory is invalid")
    redaction = document.get("redaction")
    if not _exact_mapping(redaction, _REDACTION_KEYS) or any(
        value is not False for value in redaction.values()
    ):
        errors.append("Sub2 case observation redaction boundary is invalid")
    return errors


def _load(path: Path) -> Any:
    return load_unique_json(path, max_bytes=MAX_INTAKE_JSON_BYTES)


def main() -> int:
    try:
        document = _load(OBSERVATION)
    except (OSError, UnicodeError, json.JSONDecodeError):
        print("sub2-case-observation-invalid", file=sys.stderr)
        return 1
    errors = observation_errors(document)
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    print(
        "sub2-case-observation-ok operations=7 source=public-frontend-and-request-shapes "
        "production_acceptance=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
