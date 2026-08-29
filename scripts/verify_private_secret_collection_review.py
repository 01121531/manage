"""Static fail-closed gate for the T147 external review decision verifier."""

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


REVIEW = ROOT / "scripts" / "private_secret_collection_review_decision.py"
BACKED = ROOT / "scripts" / "private_secret_collection_backed_acceptance.py"
POLICY = ROOT / "deploy" / "private-secret-collection-review-policy.synthetic.json"
TEMPLATE = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "private-secret-collection-review-decision.synthetic.json"
)

DOMAIN = "email-platform/private-secret-collection-review/v1"
POLICY_FIELDS = {
    "schema_version", "policy_kind", "synthetic", "policy_status",
    "policy_effect", "production_acceptance", "not_committed_eligible",
    "reviewer", "verifier_identity", "time_constraints", "review", "integrity",
}
DECISION_FIELDS = {
    "schema_version", "decision_kind", "synthetic", "decision_status",
    "production_acceptance", "not_committed_eligible", "payload", "signature",
    "claim_boundary", "prohibited_content", "integrity",
}
PAYLOAD_FIELDS = {
    "decision_id", "reviewer_reference", "reviewed_at", "expires_at",
    "policy_sha256", "input_manifest_sha256",
    "t143_acceptance_projection_sha256", "readiness_projection_sha256",
    "github_collection_projection_sha256", "worm_collection_projection_sha256",
    "release_commit", "release_manifest_sha256", "verifier_source_sha256",
}
CLAIM_FIELDS = {
    "provider_native", "trusted_time", "global_replay_protection",
    "decision_id_uniqueness", "verifier_release_provenance",
    "reviewer_real_identity", "sink_immutability", "durability",
    "fork_protection", "rollback_protection",
}
PROHIBITED_FIELDS = {
    "contains_token_values", "contains_private_keys", "contains_secret_values",
    "contains_authorization_headers", "contains_raw_provider_responses",
    "contains_raw_evidence_bytes", "contains_repository_external_paths",
}
PINS = {
    "expected_decision_sha256", "expected_policy_sha256",
    "expected_input_manifest_sha256", "expected_verifier_source_sha256",
    "expected_release_commit", "expected_release_manifest_sha256",
    "expected_decision_id", "verification_time",
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
            node
            for node in ast.walk(tree)
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
    review_source: str | None = None,
    backed_source: str | None = None,
    policy_raw: bytes | None = None,
    decision_raw: bytes | None = None,
) -> list[str]:
    try:
        source = review_source if review_source is not None else REVIEW.read_text(encoding="utf-8")
        backed_text = backed_source if backed_source is not None else BACKED.read_text(encoding="utf-8")
        policy_bytes = (
            policy_raw
            if policy_raw is not None
            else read_stable_bytes(POLICY, max_bytes=256 * 1024)
        )
        decision_bytes = (
            decision_raw
            if decision_raw is not None
            else read_stable_bytes(TEMPLATE, max_bytes=256 * 1024)
        )
        tree = ast.parse(source)
        backed_tree = ast.parse(backed_text)
    except (OSError, SyntaxError, TypeError, ValueError) as error:
        return [f"review verifier inputs are unreadable: {type(error).__name__}"]

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
            errors.append("review verifier imports network, process, or mutation capability")
            break
    forbidden_calls = {
        "open", "Path.write_bytes", "Path.write_text", "Path.unlink", "Path.rename",
        "Path.replace", "os.remove", "os.unlink", "os.replace", "os.rename",
        "subprocess.run", "subprocess.Popen", "Ed25519PrivateKey.generate",
    }
    calls = _calls(tree)
    forbidden_leaf_calls = {
        "write_bytes", "write_text", "unlink", "rename", "replace", "remove",
        "Popen", "run", "generate", "sign",
    }
    if any(
        name in forbidden_calls or name.split(".")[-1] in forbidden_leaf_calls
        for name in calls
    ):
        errors.append("review verifier can sign, execute, or mutate external state")

    if _literal(tree, "SIGNATURE_DOMAIN") != DOMAIN:
        errors.append("review signature domain has drifted")
    if _literal(tree, "_PAYLOAD_FIELDS") != PAYLOAD_FIELDS:
        errors.append("review decision payload schema is not closed")
    if _literal(tree, "_CLAIM_BOUNDARY_FIELDS") != CLAIM_FIELDS:
        errors.append("review claim boundary schema has drifted")
    if _literal(tree, "_PROHIBITED_FIELDS") != PROHIBITED_FIELDS:
        errors.append("review prohibited-content schema has drifted")

    pure = _function(tree, "verify_decision_bytes")
    wrapper = _function(tree, "verify_decision")
    if pure is None:
        errors.append("review pure bytes core is missing")
    else:
        pure_forbidden = {
            "_read_blob", "_unchanged", "read_stable_bytes",
            "read_stable_bytes_with_metadata", "stable_file_identity",
            "Path.read_bytes", "Path.read_text", "open",
        }
        if any(
            name in pure_forbidden or name.split(".")[-1] in {"read_bytes", "read_text"}
            for name in _calls(pure)
        ):
            errors.append("review pure bytes core performs filesystem I/O")
    for function, label in ((pure, "bytes core"), (wrapper, "path wrapper")):
        for pin in PINS:
            if not _required_kwonly(function, pin):
                errors.append(f"review {label} must require caller {pin}")
    wrapper_calls = _calls(wrapper)
    for name, expected in (
        ("_read_blob", 3),
        ("backed.verify_input_manifest_projection", 1),
        ("verify_decision_bytes", 1),
        ("_unchanged", 1),
    ):
        if wrapper_calls.count(name) != expected:
            errors.append(f"review path wrapper must call {name} exactly {expected} times")

    backed_projection = _function(backed_tree, "verify_input_manifest_projection")
    if backed_projection is None or _calls(backed_projection).count(
        "_verify_collection_backed_acceptance"
    ) != 1:
        errors.append("review upstream lacks one closed T146 projection acquisition")
    backed_dataclass = next(
        (
            node for node in ast.walk(backed_tree)
            if isinstance(node, ast.ClassDef)
            and node.name == "VerifiedCollectionBackedAcceptance"
        ),
        None,
    )
    if backed_dataclass is None:
        errors.append("review upstream frozen projection type is missing")

    required_markers = (
        "Ed25519PublicKey.from_public_bytes(reviewer_key).verify(",
        "SIGNATURE_DOMAIN.encode(\"ascii\") + b\"\\0\" + _canonical_bytes(payload)",
        "anchor[\"key_id\"] in prohibited_key_ids",
        "verified_acceptance.t143_trust_anchor_key_ids",
        "verified_acceptance.github_collection.collector_key_id",
        "verified_acceptance.github_collection.ledger_key_id",
        "verified_acceptance.worm_collection.provider_signer_key_id",
        "verified_acceptance.worm_collection.ledger_signer_key_id",
        "payload[\"reviewer_reference\"] == policy[\"review\"][\"reviewer_reference\"]",
        "not policy_reviewed <= reviewed_at <= observed_at <= expires_at",
        "_projection_digests(verified_acceptance)",
        "manifest_sha256, expected_input_manifest_sha256",
        "production_acceptance=False",
        "not_committed_eligible=False",
    )
    for marker in required_markers:
        if marker not in source:
            errors.append(f"review verifier is missing {marker}")
    for option in (
        "--decision", "--policy", "--input-manifest",
        "--expected-decision-sha256", "--expected-policy-sha256",
        "--expected-input-manifest-sha256", "--expected-verifier-source-sha256",
        "--expected-release-commit", "--expected-release-manifest-sha256",
        "--expected-decision-id", "--verification-time",
    ):
        if source.count(f'\"{option}\"') != 1:
            errors.append(f"review CLI must require exactly one {option}")
    for marker in (
        "provider-native=unverified", "trusted-time=unverified",
        "global-replay-protection=unverified", "decision-id-uniqueness=unverified",
        "verifier-release-provenance=unverified", "sink-immutability=unverified",
        "durability=unverified", "fork-protection=unverified",
        "rollback-protection=unverified", "production_acceptance=false",
        "not_committed_eligible=false",
    ):
        if marker not in source:
            errors.append(f"review status boundary is missing {marker}")

    policy, asset_errors = _asset(
        policy_bytes, fields=POLICY_FIELDS, label="review policy"
    )
    errors.extend(asset_errors)
    if policy is not None and (
        policy.get("schema_version") != 1
        or policy.get("policy_kind") != "private_secret_collection_review_policy"
        or policy.get("synthetic") is not True
        or policy.get("policy_status") != "pending"
        or policy.get("policy_effect") != "offline_review_authentication_only"
        or policy.get("production_acceptance") is not False
        or policy.get("not_committed_eligible") is not False
        or any(
            policy.get(field) is not None
            for field in ("reviewer", "verifier_identity", "time_constraints", "review")
        )
    ):
        errors.append("review policy must remain pending and unconfigured")

    decision, asset_errors = _asset(
        decision_bytes, fields=DECISION_FIELDS, label="review decision template"
    )
    errors.extend(asset_errors)
    if decision is not None and (
        decision.get("schema_version") != 1
        or decision.get("decision_kind")
        != "private_secret_collection_backed_review_decision"
        or decision.get("synthetic") is not True
        or decision.get("decision_status") != "pending"
        or decision.get("production_acceptance") is not False
        or decision.get("not_committed_eligible") is not False
        or decision.get("payload") is not None
        or decision.get("signature") is not None
        or decision.get("claim_boundary")
        != {field: "unverified" for field in CLAIM_FIELDS}
        or decision.get("prohibited_content")
        != {field: False for field in PROHIBITED_FIELDS}
    ):
        errors.append("review decision template must remain pending and unverified")
    return errors


def main() -> int:
    errors = collect_errors()
    if errors:
        for error in errors:
            print(f"private-secret-collection-review-static-error: {error}", file=sys.stderr)
        return 1
    print(
        "private-secret-collection-review-static-ok status=pending "
        "reviewer-authentication=unverified provider-native=unverified "
        "trusted-time=unverified global-replay-protection=unverified "
        "decision-id-uniqueness=unverified verifier-release-provenance=unverified "
        "sink-immutability=unverified durability=unverified "
        "fork-protection=unverified rollback-protection=unverified "
        "production_acceptance=false not_committed_eligible=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
