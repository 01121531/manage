"""Static fail-closed gate for the T143 collector deployment contract."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.external_json import parse_unique_json_bytes, read_stable_bytes
from scripts.private_secret_collector_deployment import (
    POLICY,
    TEMPLATE,
    MAX_JSON_BYTES,
    parse_policy,
)


TOOL = ROOT / "scripts" / "private_secret_collector_deployment.py"
MAX_SOURCE_BYTES = 256 * 1024
_TEMPLATE_FIELDS = {
    "schema_version", "record_type", "synthetic", "transaction_status",
    "production_acceptance", "not_committed_eligible", "deployment_policy",
    "readiness_receipt", "execution_receipt", "claim_boundary",
}
_UNVERIFIED_AXES = {
    "runtime_byte_execution", "token_current_validity", "token_revocation",
    "permission_enforcement", "egress_enforcement", "provider_native", "trusted_time",
    "global_cas_linearizability", "fork_protection", "rollback_protection",
    "sink_immutability", "durability", "reviewer_independence",
}
_REQUIRED_PINS = {
    "expected_policy_sha256", "expected_readiness_sha256", "expected_execution_sha256",
    "expected_request_sha256", "expected_previous_github_collection_head_sha256",
    "expected_current_worm_collection_head_sha256", "expected_github_collection_head_sha256",
    "expected_worm_collection_head_sha256", "expected_collection_prior_head_sha256",
    "expected_collection_ledger_id", "expected_collection_sequence", "expected_prior_head_sha256",
    "expected_ledger_id", "expected_sequence", "expected_prior_generation",
}
_PREFLIGHT_PINS = {
    "expected_policy_sha256", "expected_readiness_sha256", "expected_request_sha256",
    "expected_previous_github_collection_head_sha256",
    "expected_current_worm_collection_head_sha256",
    "expected_collection_prior_head_sha256", "expected_collection_ledger_id",
    "expected_collection_sequence",
}


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    ).hexdigest()


def _function(tree: ast.AST, name: str) -> ast.FunctionDef | None:
    return next((node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name), None)


def validate_assets(source: str, policy_raw: bytes, template_raw: bytes) -> list[str]:
    errors: list[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ["collector deployment verifier is not valid Python"]
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    forbidden_imports = imports & {"requests", "httpx", "urllib", "socket", "subprocess", "boto3", "botocore"}
    if forbidden_imports:
        errors.append("collector deployment verifier has network, provider, or process capability")
    for marker in (
        'POLICY_KIND = "private_secret_external_collector_deployment_policy"',
        'READINESS_KIND = "private_secret_external_collector_readiness"',
        'EXECUTION_KIND = "private_secret_external_collector_execution_receipt"',
        '"actions:read", "attestations:read"',
        '"POST /app/installations/{installation_id}/access_tokens"',
        '"GET {approved_attestation_bundle_origin}{opaque_path}"',
        'github["jwt_audience"] is not None',
        'github["jwt_max_ttl_seconds"] <= 600',
        'github["token_max_ttl_seconds"] <= 3600',
        'github["authorization_on_redirect"] != "forbidden"',
        'head["automatic_retry"] is not False',
        'if any(value != "unverified" for value in boundary.values())',
        '"production_acceptance"] is not False',
        '"not_committed_eligible"] is not False',
    ):
        if marker not in source:
            errors.append(f"collector deployment verifier is missing {marker}")
    function = _function(tree, "verify_acceptance_transaction")
    if function is None:
        errors.append("collector deployment verifier is missing acceptance transaction verification")
    else:
        parameters = {argument.arg for argument in (*function.args.args, *function.args.kwonlyargs)}
        if not _REQUIRED_PINS.issubset(parameters):
            errors.append("acceptance transaction is not fully caller-pinned")
        calls = [
            node.func.id
            for node in ast.walk(function)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        ]
        if calls.count("parse_policy") != 1 or calls.count("_validate_readiness") != 1 or calls.count("_validate_execution") != 1:
            errors.append("acceptance transaction validation flow has drifted")

    preflight = _function(tree, "verify_readiness_preflight")
    if preflight is None:
        errors.append("collector deployment verifier is missing readiness preflight verification")
    else:
        parameters = {argument.arg for argument in (*preflight.args.args, *preflight.args.kwonlyargs)}
        if not _PREFLIGHT_PINS.issubset(parameters):
            errors.append("readiness preflight is not fully caller-pinned")
        calls = [
            node.func.id
            for node in ast.walk(preflight)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        ]
        if calls.count("parse_policy") != 1 or calls.count("_validate_readiness") != 1:
            errors.append("readiness preflight validation flow has drifted")
        if any(name in calls for name in {"_external_blob", "read_stable_bytes", "open"}):
            errors.append("readiness preflight must remain a pure bytes verifier")

    try:
        policy = parse_policy(policy_raw, allow_synthetic=True)
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        errors.append("collector deployment policy is invalid")
    else:
        configured = ("deployment", "github", "target", "runner", "raw_sink", "trusted_time", "latest_head", "upstream_bindings", "trust_anchors", "review")
        if (
            policy.get("synthetic") is not True
            or policy.get("policy_status") != "unconfigured"
            or policy.get("production_acceptance") is not False
            or policy.get("not_committed_eligible") is not False
            or policy.get("executor_integration_enabled") is not False
            or policy.get("handoff_integration_enabled") is not False
            or any(policy.get(field) is not None for field in configured)
        ):
            errors.append("collector deployment policy must remain disabled and unconfigured")
    try:
        template = parse_unique_json_bytes(template_raw)
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        errors.append("collector acceptance template is not unique-key JSON")
    else:
        boundary: Any = template.get("claim_boundary") if isinstance(template, dict) else None
        if (
            not isinstance(template, dict)
            or set(template) != _TEMPLATE_FIELDS
            or template.get("schema_version") != 1
            or template.get("record_type") != "private_secret_external_collector_acceptance_transaction"
            or template.get("synthetic") is not True
            or template.get("transaction_status") != "pending"
            or template.get("production_acceptance") is not False
            or template.get("not_committed_eligible") is not False
            or any(template.get(field) is not None for field in ("deployment_policy", "readiness_receipt", "execution_receipt"))
            or not isinstance(boundary, dict)
            or set(boundary) != _UNVERIFIED_AXES
            or any(value != "unverified" for value in boundary.values())
        ):
            errors.append("collector acceptance template must remain pending and unverified")
    return errors


def main() -> int:
    try:
        errors = validate_assets(
            read_stable_bytes(TOOL, max_bytes=MAX_SOURCE_BYTES).decode("utf-8"),
            read_stable_bytes(POLICY, max_bytes=MAX_JSON_BYTES),
            read_stable_bytes(TEMPLATE, max_bytes=MAX_JSON_BYTES),
        )
    except (OSError, UnicodeError, ValueError):
        print("private-secret-collector-deployment-static-error: assets cannot be read", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"private-secret-collector-deployment-static-error: {error}", file=sys.stderr)
        return 1
    print(
        "private-secret-collector-deployment-static-ok policy=unconfigured transaction=pending "
        "executor_integration_enabled=false handoff_integration_enabled=false "
        "provider-native=unverified trusted-time=unverified global-cas-linearizability=unverified "
        "fork-protection=unverified rollback-protection=unverified durability=unverified "
        "reviewer-independence=unverified production_acceptance=false not_committed_eligible=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
