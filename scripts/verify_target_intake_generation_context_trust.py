"""Statically lock the pending generation-context external handoff boundary."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import sys

try:
    from scripts.target_intake_generation_context_trust import (
        AUTHORITY_CONTRACT,
        POLICY_KIND,
        PROVIDER_HEAD_CONTRACT,
        READINESS_RECORD_TYPE,
        REQUIRED_SUBJECT_BINDINGS,
        SUBJECT_DOMAIN,
        TRUSTED_TIME_CONTRACT,
        GenerationContextTrustError,
        parse_policy,
        parse_readiness,
    )
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from target_intake_generation_context_trust import (
        AUTHORITY_CONTRACT,
        POLICY_KIND,
        PROVIDER_HEAD_CONTRACT,
        READINESS_RECORD_TYPE,
        REQUIRED_SUBJECT_BINDINGS,
        SUBJECT_DOMAIN,
        TRUSTED_TIME_CONTRACT,
        GenerationContextTrustError,
        parse_policy,
        parse_readiness,
    )


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "scripts" / "target_intake_generation_context_trust.py"
POLICY = (
    ROOT / "deploy" / "target-intake-generation-context-handoff-policy.synthetic.json"
)
READINESS = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "target-intake-generation-context-handoff-readiness.synthetic.json"
)
QUALITY_GATE = ROOT / "scripts" / "quality_gate.ps1"
ATTRIBUTES = ROOT / ".gitattributes"
REQUIRED_LF_ATTRIBUTES = (
    "deploy/target-intake-generation-context-handoff-policy.synthetic.json text eol=lf",
    "deploy/evidence-index-envelopes/target-intake-generation-context-handoff-readiness.synthetic.json text eol=lf",
)
REQUIRED_OUTPUT_MARKERS = (
    "status=unconfigured readiness=pending",
    "production_acceptance=false",
    "not_committed_eligible=false",
    "authoring-integration=disabled",
    "recovery-integration=disabled",
    "no-generation-publication-performed=true",
    "policy-pin-authority=unverified",
    "context-signer-authentication=unverified",
    "context-signer-role-scope=unverified",
    "trust-anchor-validity=unverified",
    "trust-anchor-revocation=unverified",
    "trusted-timestamp=unverified",
    "timestamp-replay-protection=unverified",
    "provider-native-head=unverified",
    "provider-head-cas=unverified",
    "global-fork-protection=unverified",
    "global-rollback-protection=unverified",
)
_FORBIDDEN_IMPORT_ROOTS = {
    "httpx",
    "requests",
    "socket",
    "subprocess",
    "time",
    "urllib",
}
_FORBIDDEN_CALL_NAMES = {
    "open",
    "remove",
    "rename",
    "replace",
    "unlink",
    "write_bytes",
    "write_text",
}


def _literal_assignment(tree: ast.Module, name: str) -> object | None:
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name
        ):
            try:
                return ast.literal_eval(node.value)
            except (TypeError, ValueError):
                return None
    return None


def _function(tree: ast.Module, name: str) -> ast.FunctionDef | None:
    return next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == name
        ),
        None,
    )


def _called_names(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    return {
        call.func.id if isinstance(call.func, ast.Name) else call.func.attr
        for call in ast.walk(node)
        if isinstance(call, ast.Call)
        and isinstance(call.func, (ast.Name, ast.Attribute))
    }


def trust_contract_errors(
    source: str,
    policy_raw: bytes,
    readiness_raw: bytes,
    quality_gate: str,
    attributes: str,
) -> list[str]:
    errors: list[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ["generation-context handoff validator must parse as Python"]

    expected_literals = {
        "POLICY_KIND": POLICY_KIND,
        "READINESS_RECORD_TYPE": READINESS_RECORD_TYPE,
        "SUBJECT_DOMAIN": SUBJECT_DOMAIN,
        "REQUIRED_SUBJECT_BINDINGS": REQUIRED_SUBJECT_BINDINGS,
        "AUTHORITY_CONTRACT": AUTHORITY_CONTRACT,
        "TRUSTED_TIME_CONTRACT": TRUSTED_TIME_CONTRACT,
        "PROVIDER_HEAD_CONTRACT": PROVIDER_HEAD_CONTRACT,
    }
    for name, expected in expected_literals.items():
        if _literal_assignment(tree, name) != expected:
            errors.append(f"generation-context handoff {name} must remain exact")

    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])
    forbidden_imports = sorted(imported_roots & _FORBIDDEN_IMPORT_ROOTS)
    if forbidden_imports:
        errors.append(
            "generation-context handoff verification must not import network, "
            "subprocess, or host-time modules"
        )

    forbidden_calls = sorted(_called_names(tree) & _FORBIDDEN_CALL_NAMES)
    if forbidden_calls:
        errors.append(
            "generation-context handoff verification must remain read-only"
        )

    reader = _function(tree, "_read_single_link")
    reader_calls = _called_names(reader)
    if (
        "read_stable_bytes_with_metadata" not in reader_calls
        or reader is None
        or "metadata.st_nlink != 1" not in ast.unparse(reader)
    ):
        errors.append(
            "generation-context policy and readiness must use one stable single-link read"
        )

    verifier = _function(tree, "verify_repository")
    verifier_calls = _called_names(verifier)
    if not {
        "_read_single_link",
        "parse_policy",
        "parse_readiness",
    }.issubset(verifier_calls):
        errors.append(
            "generation-context repository verification must validate both closed artifacts"
        )

    policy_validator = _function(tree, "validate_policy")
    if not {
        "_closed",
        "_unconfigured_context_authority",
        "_unconfigured_trusted_timestamp",
        "_unconfigured_provider_head",
    }.issubset(_called_names(policy_validator)):
        errors.append(
            "generation-context policy must validate every authority and provider boundary"
        )

    readiness_validator = _function(tree, "validate_readiness")
    readiness_calls = _called_names(readiness_validator)
    if not {"_closed", "compare_digest", "_canonical_digest"}.issubset(
        readiness_calls
    ):
        errors.append(
            "generation-context readiness must bind policy and canonical payload integrity"
        )

    if any(marker not in source for marker in REQUIRED_OUTPUT_MARKERS):
        errors.append(
            "generation-context handoff output must preserve every unverified boundary"
        )
    if "python scripts/target_intake_generation_context_trust.py verify-repository" not in quality_gate:
        errors.append(
            "generation-context handoff verification must remain in the quality gate"
        )
    attribute_lines = tuple(line.strip() for line in attributes.splitlines() if line.strip())
    if any(line not in attribute_lines for line in REQUIRED_LF_ATTRIBUTES):
        errors.append(
            "generation-context handoff artifact bytes must remain LF-stable across checkouts"
        )

    policy_sha256 = hashlib.sha256(policy_raw).hexdigest()
    try:
        policy = parse_policy(policy_raw)
        readiness = parse_readiness(
            readiness_raw, policy_artifact_sha256=policy_sha256
        )
    except GenerationContextTrustError:
        errors.append(
            "generation-context repository policy/readiness artifacts are invalid"
        )
    else:
        if (
            policy.get("policy_status") != "unconfigured"
            or policy.get("authoring_integration_enabled") is not False
            or policy.get("recovery_integration_enabled") is not False
            or readiness.get("readiness_status") != "pending"
            or readiness.get("production_acceptance") is not False
            or readiness.get("not_committed_eligible") is not False
        ):
            errors.append(
                "generation-context handoff must remain unconfigured, pending, and non-accepting"
            )
    return errors


def main() -> int:
    try:
        source = CONTRACT.read_text(encoding="utf-8")
        policy_raw = POLICY.read_bytes()
        readiness_raw = READINESS.read_bytes()
        quality_gate = QUALITY_GATE.read_text(encoding="utf-8")
        attributes = ATTRIBUTES.read_text(encoding="utf-8")
    except OSError as error:
        print(str(error), file=sys.stderr)
        return 1
    errors = trust_contract_errors(
        source, policy_raw, readiness_raw, quality_gate, attributes
    )
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    policy = json.loads(policy_raw)
    print(
        "target-intake-generation-context-handoff-static-ok "
        f"status={policy['policy_status']} readiness=pending "
        "production_acceptance=false no-write-no-network=true"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
