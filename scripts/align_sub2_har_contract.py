"""Align a value-free Sub2 HAR summary with one reviewed candidate contract."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
from pathlib import Path
import re
import sys
import urllib.parse
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
_loaded_platform = sys.modules.get("platform")
if _loaded_platform is not None and not hasattr(_loaded_platform, "__path__"):
    del sys.modules["platform"]

from platform.json_boundary import JsonBoundaryError, parse_unique_json_bytes
from scripts.external_json import read_stable_bytes_with_metadata
from scripts.provider_contract_conformance import contract_errors


MAX_INPUT_BYTES = 5 * 1024 * 1024
MAX_ENTRIES = 500
MAX_FIELDS = 256
OPERATIONS = (
    "balance_check",
    "authorization_exchange",
    "create",
    "status_query",
)
_SUMMARY_KEYS = {
    "schema_version",
    "record_type",
    "provider_origin",
    "source_sha256",
    "production_acceptance",
    "entry_count",
    "entries",
    "redaction",
}
_ENTRY_KEYS = {
    "source_index",
    "method",
    "path",
    "query_fields",
    "request_header_names",
    "auth_location",
    "request_body_kind",
    "request_fields",
    "status",
    "response_header_names",
    "response_body_kind",
    "response_fields",
}
_REDACTION = {
    "contains_header_values": False,
    "contains_query_values": False,
    "contains_request_values": False,
    "contains_response_values": False,
    "contains_source_path": False,
}
_METHODS = {"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"}
_BODY_KINDS = {
    "encoded_uninspected",
    "json_array",
    "json_object",
    "json_scalar",
    "non_json",
    "oversized_uninspected",
    "unavailable",
}
_FIELD = re.compile(r"^[A-Za-z0-9_.\[\]-]{1,160}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class Sub2HarContractAlignmentError(RuntimeError):
    """One external input cannot be safely loaded."""


def _external_json(path: Path) -> tuple[object, str]:
    try:
        if not path.is_absolute():
            raise OSError
        resolved = path.resolve(strict=True)
        if resolved.is_relative_to(ROOT.resolve()):
            raise OSError
        raw, metadata = read_stable_bytes_with_metadata(
            path,
            max_bytes=MAX_INPUT_BYTES,
        )
        if metadata.st_nlink != 1:
            raise OSError
        return parse_unique_json_bytes(raw), hashlib.sha256(raw).hexdigest()
    except (OSError, RuntimeError, JsonBoundaryError):
        raise Sub2HarContractAlignmentError(
            "Sub2 HAR contract alignment input is invalid"
        ) from None


def _field_list(value: object) -> bool:
    return (
        isinstance(value, list)
        and len(value) <= MAX_FIELDS
        and all(isinstance(item, str) and _FIELD.fullmatch(item) for item in value)
        and value == sorted(set(value))
    )


def _https_origin(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port or 443
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.hostname is not None
        and parsed.username is None
        and parsed.password is None
        and parsed.path == ""
        and not parsed.query
        and not parsed.fragment
        and 1 <= port <= 65535
    )


def _summary_entries(document: object) -> dict[int, dict[str, Any]] | None:
    if (
        not isinstance(document, dict)
        or set(document) != _SUMMARY_KEYS
        or document.get("schema_version") != 1
        or document.get("record_type") != "sub2_har_shape_summary"
        or document.get("production_acceptance") is not False
        or document.get("redaction") != _REDACTION
        or not _https_origin(document.get("provider_origin"))
        or not isinstance(document.get("source_sha256"), str)
        or _SHA256.fullmatch(document["source_sha256"]) is None
    ):
        return None
    entries = document.get("entries")
    count = document.get("entry_count")
    if (
        not isinstance(entries, list)
        or not 1 <= len(entries) <= MAX_ENTRIES
        or type(count) is not int
        or count != len(entries)
    ):
        return None
    indexed: dict[int, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != _ENTRY_KEYS:
            return None
        source_index = entry.get("source_index")
        status = entry.get("status")
        path = entry.get("path")
        if (
            type(source_index) is not int
            or source_index <= 0
            or source_index in indexed
            or entry.get("method") not in _METHODS
            or not isinstance(path, str)
            or len(path) > 512
            or not path.startswith("/api/v1/admin/")
            or any(character in path for character in "?#@")
            or entry.get("auth_location")
            not in {"authorization_header", "cookie", "not_observed"}
            or entry.get("request_body_kind") not in _BODY_KINDS
            or entry.get("response_body_kind") not in _BODY_KINDS
            or type(status) is not int
            or not 0 <= status <= 599
            or any(
                not _field_list(entry.get(name))
                for name in (
                    "query_fields",
                    "request_header_names",
                    "request_fields",
                    "response_header_names",
                    "response_fields",
                )
            )
        ):
            return None
        indexed[source_index] = entry
    return indexed


def _request_field_observed(entry: Mapping[str, Any], field: str) -> bool:
    if field in entry["request_fields"] or field in entry["query_fields"]:
        return True
    folded = field.casefold()
    return any(name.casefold() == folded for name in entry["request_header_names"])


def _response_field_observed(entry: Mapping[str, Any], field: str) -> bool:
    if field in entry["response_fields"]:
        return True
    folded = field.casefold()
    return any(name.casefold() == folded for name in entry["response_header_names"])


def _location_observed(
    entry: Mapping[str, Any],
    *,
    location: str,
    name: str,
) -> bool:
    if location == "header":
        folded = name.casefold()
        return any(
            field.casefold() == folded for field in entry["request_header_names"]
        )
    if location == "request_body":
        return name in entry["request_fields"]
    if location == "query":
        return name in entry["query_fields"]
    if location == "path":
        return "{" + name + "}" in entry["path"]
    return False


def alignment_errors(
    summary: object,
    contract: object,
    source_indices: Mapping[str, int],
    *,
    summary_artifact_sha256: str,
    evaluated_at: datetime | None = None,
) -> list[str]:
    """Return fixed gap codes without echoing either external document."""

    entries = _summary_entries(summary)
    if (
        entries is None
        or not isinstance(summary_artifact_sha256, str)
        or _SHA256.fullmatch(summary_artifact_sha256) is None
    ):
        return ["summary_invalid"]
    if contract_errors(
        contract,
        expected_type="sub2",
        evaluated_at=evaluated_at,
    ):
        return ["contract_invalid"]
    assert isinstance(contract, dict)
    if contract.get("synthetic") is not False:
        return ["contract_not_reviewed"]
    if set(source_indices) != set(OPERATIONS) or any(
        type(source_indices.get(operation)) is not int
        or source_indices[operation] <= 0
        for operation in OPERATIONS
    ):
        return ["source_mapping_invalid"]

    errors: list[str] = []
    source = contract["source_provenance"]
    if source.get("source_sha256") != summary_artifact_sha256:
        errors.append("source_sha256_mismatch")
    capabilities = contract["capabilities"]
    workflow = capabilities["workflow"]
    operations = workflow["operations"]
    selected: dict[str, dict[str, Any]] = {}
    for operation in OPERATIONS:
        entry = entries.get(source_indices[operation])
        if entry is None:
            errors.append(f"{operation}_source_missing")
            continue
        selected[operation] = entry
        details = operations[operation]
        if details["method"] != entry["method"]:
            errors.append(f"{operation}_method_mismatch")
        if any(
            not _request_field_observed(entry, field)
            for field in details["request_fields"]
        ):
            errors.append(f"{operation}_request_overclaim")
        if any(
            not _response_field_observed(entry, field)
            for field in details["response_fields"]
        ):
            errors.append(f"{operation}_response_overclaim")

    create = selected.get("create")
    if create is not None:
        if capabilities["submit_method"] != create["method"]:
            errors.append("create_submit_method_mismatch")
        if not _location_observed(
            create,
            location=capabilities["idempotency_location"],
            name=capabilities["idempotency_name"],
        ):
            errors.append("create_idempotency_unobserved")
        if not _location_observed(
            create,
            location=capabilities["task_correlation_location"],
            name=capabilities["task_correlation_name"],
        ):
            errors.append("create_task_correlation_unobserved")
        if not _response_field_observed(
            create,
            capabilities["success_reference_field"],
        ):
            errors.append("create_success_reference_unobserved")

    status_entry = selected.get("status_query")
    status_query = capabilities["status_query"]
    if status_entry is not None:
        if status_query["method"] != status_entry["method"]:
            errors.append("status_query_capability_method_mismatch")
        if not _location_observed(
            status_entry,
            location=status_query["reference_location"],
            name=status_query["reference_name"],
        ):
            errors.append("status_query_reference_unobserved")
        if not _response_field_observed(status_entry, status_query["result_field"]):
            errors.append("status_query_result_unobserved")
    return sorted(set(errors))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    for operation in OPERATIONS:
        parser.add_argument(
            "--" + operation.replace("_", "-") + "-index",
            type=int,
            required=True,
        )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    try:
        summary, summary_artifact_sha256 = _external_json(options.summary)
        contract, _ = _external_json(options.contract)
    except Sub2HarContractAlignmentError:
        print("sub2-har-contract-alignment-invalid", file=sys.stderr)
        return 1
    source_indices = {
        operation: getattr(options, operation + "_index") for operation in OPERATIONS
    }
    errors = alignment_errors(
        summary,
        contract,
        source_indices,
        summary_artifact_sha256=summary_artifact_sha256,
    )
    if errors:
        for error in errors:
            print(f"sub2-har-contract-alignment-gap code={error}", file=sys.stderr)
        return 2
    print(
        "sub2-har-contract-alignment-ok operations=4 "
        "production_acceptance=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
