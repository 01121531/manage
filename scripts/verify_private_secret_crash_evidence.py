"""Statically guard the offline private-secret crash-evidence boundary."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

try:
    from scripts.external_json import parse_unique_json_bytes, read_stable_bytes
    from scripts.external_text import load_stable_text
except ModuleNotFoundError:  # Direct ``python scripts/...`` execution.
    from external_json import parse_unique_json_bytes, read_stable_bytes  # type: ignore[no-redef]
    from external_text import load_stable_text  # type: ignore[no-redef]


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "scripts" / "private_secret_crash_evidence.py"
POLICY = ROOT / "deploy" / "private-secret-runtime-policy.json"
TEMPLATE = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "private-secret-crash.synthetic.json"
)
MAX_TOOL_BYTES = 64 * 1024
MAX_ASSET_BYTES = 16 * 1024

_FORBIDDEN_IMPORTS = {
    "subprocess",
    "socket",
    "requests",
    "httpx",
    "urllib.request",
    "scripts.private_secret_materialization",
    "scripts.private_secret_residue",
    "scripts.kubernetes_tls_rotation_backend",
    "scripts.tls_rotation_executor",
    "scripts.tls_rotation_runner",
}
_FORBIDDEN_CALLS = {
    "Popen",
    "check_call",
    "check_output",
    "run",
    "system",
    "kubectl",
    "docker",
    "materialize_private_secret_bytes",
    "cleanup_private_secret_residue_from_inventory",
    "inventory_private_secret_residues",
    "capture_private_secret_residue_inventory",
    "generate",
    "create",
    "open",
    "write_bytes",
    "write_text",
    "unlink",
    "link",
    "replace",
    "rename",
    "mkdir",
    "makedirs",
    "prepare_write_once_file",
    "publish_write_once_file",
}
_FORBIDDEN_TEXT = (
    "shell=True",
    "kubectl ",
    "docker ",
    'add_parser("generate"',
    'add_parser("create"',
)
_FORBIDDEN_CLAIM = re.compile(r"(?<![A-Za-z])(verified|attested)(?![A-Za-z])", re.I)
_TRUE_ACCEPTANCE = re.compile(
    r"production_acceptance(?:[\"']|\s)*[:=](?:\s)*True\b", re.I
)

_EXPECTED_POLICY: dict[str, Any] = {
    "schema_version": 1,
    "policy_kind": "private_secret_runtime_root_policy",
    "policy_effect": "repository_contract_only",
    "production_acceptance": False,
    "platform": "posix",
    "runtime_root": {
        "environment_variable": "EMAIL_PLATFORM_PRIVATE_SECRET_RUNTIME_ROOT",
        "path_policy": "absolute_repository_external",
        "owner": "effective_uid",
        "mode": "0700",
        "link_policy": "no_follow",
    },
    "claim": {
        "id_policy": "32_lowercase_hex",
        "directory_mode": "0700",
        "exact_entries": ["claim.json", "lease", "secret"],
        "claim_mode": "0400",
        "lease_mode": "0600",
        "secret_mode": "0400",
        "lease_mechanism": "posix_flock_exclusive_nonblocking",
    },
    "cleanup": {
        "scope": "one_authenticated_claim",
        "bulk_cleanup": False,
        "age_or_pid_heuristics": False,
        "secure_erasure_claimed": False,
    },
}

_TEMPLATE_FIELDS = {
    "schema_version",
    "evidence_kind",
    "synthetic",
    "evidence_status",
    "origin_authentication",
    "production_acceptance",
    "attempt_id",
    "scope",
    "runtime_root_policy_sha256",
    "claim_id",
    "before_inventory",
    "cleanup",
    "after_inventory",
    "alert",
    "review",
    "prohibited_content",
    "integrity",
}
_PROHIBITED_CONTENT_FIELDS = {
    "contains_secret_values",
    "contains_source_sha256",
    "contains_runtime_paths",
    "contains_kubeconfig",
    "contains_pem_values",
    "contains_token_values",
    "contains_raw_logs",
    "contains_pid_or_age_heuristics",
    "contains_personal_data",
}

_REQUIRED_TOOL_MARKERS = (
    "Offline verification for reviewed private-secret crash-drill assertions.",
    "This module never collects runtime state and never authenticates artifact origin.",
    "def validate_runtime_policy(",
    "def validate_envelope(",
    "def verify_evidence(",
    "def verify_repository_assets(",
    "parse_unique_json_bytes(raw)",
    "read_stable_bytes_with_metadata(",
    "metadata.st_nlink != 1",
    'payload["origin_authentication"] != "unverified"',
    'payload["production_acceptance"] is not False',
    'scope.get("kind") == "github_actions_linux_ci"',
    'scope.get("kind") == "kubernetes_target_host"',
    "target_inventory_path is not None",
    "expected_commit",
    "expected_workflow_sha256",
    'inventory_value.get("synthetic") is not False',
    'inventory_value.get("inventory_status") != "reviewed"',
    "_verify_transition(envelope[\"claim_id\"], before_records, after_records)",
    'item.get("state") == "unknown"',
    'before_matches[0].get("state") != "cleanup_candidate"',
    "before_siblings != after_records",
    "len(set(references)) != 3",
    'alert["result"] != "delivered"',
    '"result": "not_applicable"',
    "add_mutually_exclusive_group(required=True)",
    'status=pending origin-authentication=unverified',
    'status=reviewed-assertion origin-authentication=unverified',
    'production_acceptance=false',
)


def _called_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _tool_errors(source: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ["private-secret crash evidence tool is not valid Python"]
    errors: list[str] = []
    for marker in _REQUIRED_TOOL_MARKERS:
        if marker not in source:
            errors.append(f"private-secret crash evidence tool is missing {marker}")
    if source.count("parse_unique_json_bytes(raw)") != 3:
        errors.append(
            "private-secret crash evidence tool must uniquely parse all three JSON boundaries"
        )
    for marker in _FORBIDDEN_TEXT:
        if marker in source:
            errors.append(f"private-secret crash evidence tool exposes runtime command {marker}")
    if _FORBIDDEN_CLAIM.search(source):
        errors.append("private-secret crash evidence tool overstates origin authentication")
    if _TRUE_ACCEPTANCE.search(source):
        errors.append("private-secret crash evidence tool enables production acceptance")

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = {alias.name for alias in node.names}
            if names.intersection(_FORBIDDEN_IMPORTS):
                errors.append("private-secret crash evidence tool imports a runtime capability")
                break
        if isinstance(node, ast.ImportFrom) and node.module in _FORBIDDEN_IMPORTS:
            errors.append("private-secret crash evidence tool imports a runtime capability")
            break
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _called_name(node) in _FORBIDDEN_CALLS:
            errors.append(
                "private-secret crash evidence tool calls a mutation or runtime capability"
            )
            break
    return errors


def _json_value(raw: bytes, label: str) -> tuple[object | None, list[str]]:
    try:
        return parse_unique_json_bytes(raw), []
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        return None, [f"{label} is not unique valid JSON"]


def _json_semantic_errors(value: object, label: str) -> list[str]:
    rendered = json.dumps(value, ensure_ascii=True, sort_keys=True)
    errors: list[str] = []
    if _FORBIDDEN_CLAIM.search(rendered):
        errors.append(f"{label} overstates origin authentication")
    if isinstance(value, dict) and value.get("production_acceptance") is not False:
        errors.append(f"{label} must keep production_acceptance false")
    return errors


def _policy_errors(raw: bytes) -> list[str]:
    value, errors = _json_value(raw, "private-secret runtime policy")
    if errors:
        return errors
    errors.extend(_json_semantic_errors(value, "private-secret runtime policy"))
    if value != _EXPECTED_POLICY:
        errors.append("private-secret runtime policy has drifted")
    return errors


def _canonical_payload_digest(document: dict[str, Any]) -> str:
    payload = {key: value for key, value in document.items() if key != "integrity"}
    raw = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _template_errors(raw: bytes) -> list[str]:
    value, errors = _json_value(raw, "private-secret crash evidence template")
    if errors:
        return errors
    errors.extend(_json_semantic_errors(value, "private-secret crash evidence template"))
    if not isinstance(value, dict) or set(value) != _TEMPLATE_FIELDS:
        return [*errors, "private-secret crash evidence template schema has drifted"]
    pending_fields = (
        "attempt_id",
        "runtime_root_policy_sha256",
        "claim_id",
        "before_inventory",
        "cleanup",
        "after_inventory",
        "alert",
        "review",
    )
    if (
        value.get("schema_version") != 1
        or value.get("evidence_kind")
        != "private_secret_materialization_crash_drill_intake"
        or value.get("synthetic") is not True
        or value.get("evidence_status") != "pending"
        or value.get("origin_authentication") != "unverified"
        or value.get("scope") != {"kind": "pending"}
        or any(value.get(field) is not None for field in pending_fields)
    ):
        errors.append("private-secret crash evidence template must remain pending")
    prohibited = value.get("prohibited_content")
    if (
        not isinstance(prohibited, dict)
        or set(prohibited) != _PROHIBITED_CONTENT_FIELDS
        or any(item is not False for item in prohibited.values())
    ):
        errors.append("private-secret crash evidence template redaction contract has drifted")
    integrity = value.get("integrity")
    if (
        not isinstance(integrity, dict)
        or set(integrity) != {"payload_sha256"}
        or integrity.get("payload_sha256") != _canonical_payload_digest(value)
    ):
        errors.append("private-secret crash evidence template is not canonically sealed")
    return errors


def validate_assets(tool_source: str, policy_raw: bytes, template_raw: bytes) -> list[str]:
    errors = _tool_errors(tool_source)
    errors.extend(_policy_errors(policy_raw))
    errors.extend(_template_errors(template_raw))
    return errors


def main() -> int:
    try:
        errors = validate_assets(
            load_stable_text(TOOL, max_bytes=MAX_TOOL_BYTES),
            read_stable_bytes(POLICY, max_bytes=MAX_ASSET_BYTES),
            read_stable_bytes(TEMPLATE, max_bytes=MAX_ASSET_BYTES),
        )
    except (OSError, UnicodeError, ValueError):
        print("private-secret-crash-evidence-static-error: assets cannot be read", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"private-secret-crash-evidence-static-error: {error}", file=sys.stderr)
        return 1
    print(
        "private-secret-crash-evidence-static-ok "
        "origin-authentication=unverified production_acceptance=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
