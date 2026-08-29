"""Static fail-closed gate for the T148 archive receipt/custody verifier."""

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


ARCHIVE = ROOT / "scripts" / "private_secret_collection_archive_receipt.py"
REVIEW = ROOT / "scripts" / "private_secret_collection_review_decision.py"
POLICY = ROOT / "deploy" / "private-secret-collection-archive-policy.synthetic.json"
TEMPLATE = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "private-secret-collection-archive-receipt.synthetic.json"
)

PROVIDER_DOMAIN = "email-platform/private-secret-collection-archive-provider/v1"
CUSTODY_DOMAIN = "email-platform/private-secret-collection-archive-custody/v1"
POLICY_FIELDS = {
    "schema_version", "policy_kind", "synthetic", "policy_status",
    "policy_effect", "production_acceptance", "not_committed_eligible",
    "archive_contract", "provider_signer", "custody_signer",
    "verifier_identity", "time_constraints", "review", "integrity",
}
RECEIPT_FIELDS = {
    "schema_version", "receipt_kind", "synthetic", "receipt_status",
    "production_acceptance", "not_committed_eligible", "payload",
    "provider_signature", "custody_checkpoint", "custody_signature",
    "claim_boundary", "prohibited_content", "integrity",
}
PAYLOAD_FIELDS = {
    "receipt_id", "decision_id", "provider_reference", "custody_reference",
    "archived_at", "readback_at", "expires_at", "archive_policy_sha256",
    "review_decision_sha256", "review_policy_sha256", "input_manifest_sha256",
    "review_verifier_source_sha256", "archive_verifier_source_sha256",
    "release_commit", "release_manifest_sha256", "archive_readback_sha256",
    "provider_config_sha256", "retention_snapshot_sha256", "provider_kind",
    "storage_identity_fingerprint_sha256", "object_reference",
    "immutable_version_reference", "write_mode", "retention_mode",
    "ledger_id", "sequence", "prior_receipt_sha256",
    "prior_checkpoint_sha256",
}
CHECKPOINT_FIELDS = {
    "checkpoint_kind", "ledger_id", "sequence", "prior_receipt_sha256",
    "prior_checkpoint_sha256",
    "receipt_id", "decision_id", "receipt_payload_sha256",
    "archive_readback_sha256", "object_reference",
    "immutable_version_reference", "custody_reference",
}
CLAIM_FIELDS = {
    "provider_native", "trusted_time", "global_replay_protection",
    "decision_id_uniqueness", "verifier_release_provenance",
    "provider_real_identity", "custody_real_identity", "sink_immutability",
    "durability", "fork_protection", "rollback_protection",
}
PROHIBITED_FIELDS = {
    "contains_token_values", "contains_private_keys", "contains_secret_values",
    "contains_authorization_headers", "contains_raw_provider_responses",
    "contains_raw_evidence_bytes", "contains_repository_external_paths",
}
PINS = {
    "expected_receipt_sha256", "expected_policy_sha256",
    "expected_archive_readback_sha256", "expected_provider_config_sha256",
    "expected_retention_snapshot_sha256", "expected_verifier_source_sha256",
    "expected_prior_receipt_sha256", "expected_review_decision_sha256",
    "expected_prior_checkpoint_sha256",
    "expected_review_policy_sha256", "expected_input_manifest_sha256",
    "expected_review_verifier_source_sha256", "expected_release_commit",
    "expected_release_manifest_sha256", "expected_decision_id",
    "expected_receipt_id", "expected_ledger_id", "expected_sequence",
    "verification_time",
}


def _canonical_digest(value: object) -> str:
    raw = json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _literal(tree: ast.AST, name: str) -> object | None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == name for target in targets):
                try:
                    return ast.literal_eval(node.value)
                except (TypeError, ValueError):
                    return None
    return None


def _function(tree: ast.AST, name: str) -> ast.FunctionDef | None:
    return next(
        (
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == name
        ),
        None,
    )


def _call_name(node: ast.Call) -> str:
    parts: list[str] = []
    value: ast.AST = node.func
    while isinstance(value, ast.Attribute):
        parts.append(value.attr)
        value = value.value
    if isinstance(value, ast.Name):
        parts.append(value.id)
    return ".".join(reversed(parts))


def _calls(node: ast.AST | None) -> list[str]:
    if node is None:
        return []
    return [_call_name(item) for item in ast.walk(node) if isinstance(item, ast.Call)]


def _required_kwonly(function: ast.FunctionDef | None, name: str) -> bool:
    if function is None:
        return False
    return any(
        argument.arg == name and default is None
        for argument, default in zip(
            function.args.kwonlyargs, function.args.kw_defaults, strict=True
        )
    )


def _class_fields(tree: ast.AST, name: str) -> set[str] | None:
    class_node = next(
        (
            node for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) and node.name == name
        ),
        None,
    )
    if class_node is None:
        return None
    return {
        node.target.id
        for node in class_node.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    }


def _asset(raw: bytes, *, fields: set[str], label: str) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        value = parse_unique_json_bytes(raw)
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        return None, [f"{label} is not unique-key JSON"]
    if not isinstance(value, dict) or set(value) != fields:
        return None, [f"{label} schema is not closed"]
    integrity = value.get("integrity")
    if not isinstance(integrity, dict) or set(integrity) != {"payload_sha256"}:
        return None, [f"{label} integrity is not closed"]
    payload = {key: item for key, item in value.items() if key != "integrity"}
    if integrity.get("payload_sha256") != _canonical_digest(payload):
        return None, [f"{label} canonical integrity has drifted"]
    return value, []


def collect_errors(
    *,
    archive_source: str | None = None,
    review_source: str | None = None,
    policy_raw: bytes | None = None,
    receipt_raw: bytes | None = None,
) -> list[str]:
    try:
        source = archive_source if archive_source is not None else ARCHIVE.read_text(encoding="utf-8")
        review_text = review_source if review_source is not None else REVIEW.read_text(encoding="utf-8")
        policy_bytes = (
            policy_raw
            if policy_raw is not None
            else read_stable_bytes(POLICY, max_bytes=256 * 1024)
        )
        receipt_bytes = (
            receipt_raw
            if receipt_raw is not None
            else read_stable_bytes(TEMPLATE, max_bytes=256 * 1024)
        )
        tree = ast.parse(source)
        review_tree = ast.parse(review_text)
    except (OSError, SyntaxError, TypeError, ValueError) as error:
        return [f"archive verifier inputs are unreadable: {type(error).__name__}"]

    errors: list[str] = []
    forbidden_modules = {
        "requests", "httpx", "urllib", "socket", "subprocess", "asyncio",
        "shutil", "tempfile",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            names = {(node.module or "").split(".")[0]}
        else:
            continue
        if names & forbidden_modules:
            errors.append("archive verifier imports network, process, or mutation capability")
            break
    calls = _calls(tree)
    forbidden_leaf_calls = {
        "write_bytes", "write_text", "unlink", "rename", "replace", "remove",
        "Popen", "run", "generate", "sign", "link", "mkdir", "rmdir",
    }
    if any(name.split(".")[-1] in forbidden_leaf_calls for name in calls):
        errors.append("archive verifier can sign, execute, or mutate external state")

    literals = (
        ("PROVIDER_DOMAIN", PROVIDER_DOMAIN, "provider signature domain"),
        ("CUSTODY_DOMAIN", CUSTODY_DOMAIN, "custody signature domain"),
        ("_PAYLOAD_FIELDS", PAYLOAD_FIELDS, "receipt payload schema"),
        ("_CHECKPOINT_FIELDS", CHECKPOINT_FIELDS, "custody checkpoint schema"),
        ("_CLAIM_FIELDS", CLAIM_FIELDS, "claim boundary schema"),
        ("_PROHIBITED_FIELDS", PROHIBITED_FIELDS, "prohibited-content schema"),
    )
    for name, expected, label in literals:
        if _literal(tree, name) != expected:
            errors.append(f"archive {label} has drifted")

    core = _function(tree, "verify_archive_receipt_bytes")
    wrapper = _function(tree, "verify_archive_receipt")
    if core is None:
        errors.append("archive pure bytes core is missing")
    else:
        forbidden_core = {
            "_read_blob", "_unchanged", "read_stable_bytes",
            "read_stable_bytes_with_metadata", "Path.read_bytes", "Path.read_text",
            "review.verify_decision", "open",
        }
        if any(
            name in forbidden_core or name.split(".")[-1] in {"read_bytes", "read_text"}
            for name in _calls(core)
        ):
            errors.append("archive pure bytes core performs filesystem or upstream I/O")
    for function, label in ((core, "bytes core"), (wrapper, "path wrapper")):
        for pin in PINS:
            if not _required_kwonly(function, pin):
                errors.append(f"archive {label} must require caller {pin}")
    wrapper_calls = _calls(wrapper)
    for name, expected in (
        ("_read_blob", 7),
        ("review.verify_decision", 1),
        ("verify_archive_receipt_bytes", 1),
        ("_unchanged", 1),
    ):
        if wrapper_calls.count(name) != expected:
            errors.append(f"archive path wrapper must call {name} exactly {expected} times")

    required_markers = (
        "domain.encode(\"ascii\") + b\"\\0\" + _canonical_bytes(payload)",
        "domain=PROVIDER_DOMAIN",
        "domain=CUSTODY_DOMAIN",
        "provider_key_id in prohibited_keys",
        "custody_key_id in prohibited_keys",
        "verified_review.reviewer_key_id",
        "*verified_review.upstream_key_ids",
        "checkpoint != _checkpoint_for(payload)",
        "prior_payload[\"sequence\"] != expected_sequence - 1",
        "prior_checkpoint_sha256, expected_prior_checkpoint_sha256",
        "payload[\"prior_checkpoint_sha256\"] != prior_checkpoint_sha256",
        "prior_payload[\"decision_id\"] == payload[\"decision_id\"]",
        "prior_payload[\"archive_readback_sha256\"] == payload[\"archive_readback_sha256\"]",
        "prior_payload[\"object_reference\"] == payload[\"object_reference\"]",
        "prior_payload[\"immutable_version_reference\"]",
        "not policy_reviewed <= archived_at <= readback_at <= observed_at <= expires_at",
        "expected_prior_receipt_sha256 != ZERO_SHA256",
        "production_acceptance=False",
        "not_committed_eligible=False",
    )
    for marker in required_markers:
        if marker not in source:
            errors.append(f"archive verifier is missing {marker}")

    review_fields = _class_fields(review_tree, "VerifiedReviewDecision")
    if review_fields is None or "upstream_key_ids" not in review_fields:
        errors.append("T147 frozen result omits upstream signer key identities")
    if "upstream_key_ids=(" not in review_text:
        errors.append("T147 verifier does not populate frozen upstream signer identities")

    for option in (
        "receipt", "policy", "archive-readback", "provider-config",
        "retention-snapshot", "review-decision", "review-policy", "input-manifest",
        "prior-receipt", "expected-receipt-sha256", "expected-policy-sha256",
        "expected-archive-readback-sha256", "expected-provider-config-sha256",
        "expected-retention-snapshot-sha256", "expected-verifier-source-sha256",
        "expected-prior-receipt-sha256", "expected-review-decision-sha256",
        "expected-prior-checkpoint-sha256",
        "expected-review-policy-sha256", "expected-input-manifest-sha256",
        "expected-review-verifier-source-sha256", "expected-release-commit",
        "expected-release-manifest-sha256", "expected-decision-id",
        "expected-receipt-id", "expected-ledger-id", "expected-sequence",
        "verification-time",
    ):
        if f'"{option}"' not in source and f'"--{option}"' not in source:
            errors.append(f"archive CLI omits {option}")
    for marker in (
        "provider-native=unverified", "trusted-time=unverified",
        "global-replay-protection=unverified", "decision-id-uniqueness=unverified",
        "verifier-release-provenance=unverified", "sink-immutability=unverified",
        "durability=unverified", "fork-protection=unverified",
        "rollback-protection=unverified", "production_acceptance=false",
        "not_committed_eligible=false",
    ):
        if marker not in source:
            errors.append(f"archive status boundary is missing {marker}")

    policy, asset_errors = _asset(
        policy_bytes, fields=POLICY_FIELDS, label="archive policy"
    )
    errors.extend(asset_errors)
    if policy is not None and (
        policy.get("schema_version") != 1
        or policy.get("policy_kind") != "private_secret_collection_archive_policy"
        or policy.get("synthetic") is not True
        or policy.get("policy_status") != "pending"
        or policy.get("policy_effect") != "offline_archive_receipt_authentication_only"
        or policy.get("production_acceptance") is not False
        or policy.get("not_committed_eligible") is not False
        or any(
            policy.get(field) is not None
            for field in (
                "archive_contract", "provider_signer", "custody_signer",
                "verifier_identity", "time_constraints", "review",
            )
        )
    ):
        errors.append("archive policy must remain pending and unconfigured")

    receipt, asset_errors = _asset(
        receipt_bytes, fields=RECEIPT_FIELDS, label="archive receipt template"
    )
    errors.extend(asset_errors)
    if receipt is not None and (
        receipt.get("schema_version") != 1
        or receipt.get("receipt_kind")
        != "private_secret_collection_review_archive_receipt"
        or receipt.get("synthetic") is not True
        or receipt.get("receipt_status") != "pending"
        or receipt.get("production_acceptance") is not False
        or receipt.get("not_committed_eligible") is not False
        or any(
            receipt.get(field) is not None
            for field in (
                "payload", "provider_signature", "custody_checkpoint",
                "custody_signature",
            )
        )
        or receipt.get("claim_boundary")
        != {field: "unverified" for field in CLAIM_FIELDS}
        or receipt.get("prohibited_content")
        != {field: False for field in PROHIBITED_FIELDS}
    ):
        errors.append("archive receipt template must remain pending and unverified")
    return errors


def main() -> int:
    errors = collect_errors()
    if errors:
        for error in errors:
            print(f"private-secret-collection-archive-static-error: {error}", file=sys.stderr)
        return 1
    print(
        "private-secret-collection-archive-static-ok status=pending "
        "provider-signature=unverified custody-signature=unverified "
        "provider-native=unverified trusted-time=unverified "
        "global-replay-protection=unverified decision-id-uniqueness=unverified "
        "verifier-release-provenance=unverified sink-immutability=unverified "
        "durability=unverified fork-protection=unverified "
        "rollback-protection=unverified production_acceptance=false "
        "not_committed_eligible=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
