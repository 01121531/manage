"""Statically lock the pending external runtime-attestation handoff boundary."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import sys

try:
    from scripts.target_intake_runtime_attestation_trust import (
        RuntimeAttestationTrustError,
        parse_policy,
        parse_readiness,
    )
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from target_intake_runtime_attestation_trust import (
        RuntimeAttestationTrustError,
        parse_policy,
        parse_readiness,
    )


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "scripts" / "target_intake_runtime_attestation_trust.py"
POLICY = ROOT / "deploy" / "target-intake-runtime-attestation-policy.synthetic.json"
READINESS = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "target-intake-runtime-attestation-readiness.synthetic.json"
)
QUALITY_GATE = ROOT / "scripts" / "quality_gate.ps1"
ATTRIBUTES = ROOT / ".gitattributes"
RUNBOOK = ROOT / "deploy" / "runbooks" / "target-intake-preflight.md"
SIGNOFF = ROOT / "deploy" / "production-signoff-template.md"
REQUIREMENTS = ROOT / "deploy" / "target-intake-requirements.json"
CONSUMER_PATHS = (
    ROOT / "scripts" / "target_intake_generation.py",
    ROOT / "scripts" / "target_intake_preflight.py",
    ROOT / "scripts" / "target_intake_snapshot_launcher.py",
    ROOT / "scripts" / "deploy_release.py",
    ROOT / "scripts" / "rollback_release.py",
    ROOT / "scripts" / "rolling_release.py",
)
EXPECTED_POLICY_KIND = "target_intake_runtime_attestation_policy_v1"
EXPECTED_READINESS_RECORD_TYPE = "target_intake_runtime_attestation_readiness"
EXPECTED_SUBJECT_DOMAIN = "email-platform/target-intake-runtime-attestation-handoff/v1"
EXPECTED_REQUIRED_SUBJECT_BINDINGS = (
    "terminal_manifest_payload_sha256",
    "terminal_manifest_file_sha256",
    "terminal_receipt_payload_sha256",
    "terminal_receipt_file_sha256",
    "generation_sequence",
    "validation_context_sha256",
    "validator_contract_sha256",
    "replay_runtime_sha256",
    "execution_profile_sha256",
    "runtime_artifact_kind",
    "runtime_artifact_digest",
    "runtime_artifact_immutable_reference",
    "provenance_subject_digest",
    "deploy_selected_digest",
    "target_observed_digest",
    "target_process_identity_sha256",
    "target_loaded_evidence_sha256",
    "expected_prior_provider_head",
    "proposed_provider_sequence",
    "cas_request_id",
)
EXPECTED_AUTHORITY_CONTRACTS = {
    "PUBLISHER_CONTRACT": {
        "signer_role": "target_intake_runtime_publisher_authority",
        "usage_scope": "target_intake_runtime_publisher_v1_only",
        "signature_domain": "email-platform/target-intake-runtime-attestation-handoff/publisher/v1",
    },
    "PROVENANCE_CONTRACT": {
        "signer_role": "target_intake_runtime_provenance_authority",
        "usage_scope": "target_intake_runtime_provenance_v1_only",
        "signature_domain": "email-platform/target-intake-runtime-attestation-handoff/provenance/v1",
    },
    "TARGET_OBSERVER_CONTRACT": {
        "signer_role": "target_intake_runtime_target_observer_authority",
        "usage_scope": "target_intake_runtime_target_observer_v1_only",
        "signature_domain": "email-platform/target-intake-runtime-attestation-handoff/target-observer/v1",
    },
    "TRUSTED_TIME_CONTRACT": {
        "signer_role": "target_intake_runtime_trusted_time_authority",
        "usage_scope": "target_intake_runtime_trusted_time_v1_only",
        "signature_domain": "email-platform/target-intake-runtime-attestation-handoff/trusted-time/v1",
    },
    "PROVIDER_HEAD_CONTRACT": {
        "signer_role": "target_intake_runtime_head_authority",
        "usage_scope": "target_intake_runtime_head_authority_v1_only",
        "signature_domain": "email-platform/target-intake-runtime-attestation-handoff/provider-head/v1",
    },
}
EXPECTED_GENERATION_CONTEXT_FORBIDDEN_IDENTITIES = (
    "target_intake_generation_context_authority",
    "target_intake_generation_context_authority_v1_only",
    "email-platform/target-intake-generation-context-handoff/context-authority/v1",
    "target_intake_generation_trusted_time_authority",
    "target_intake_generation_trusted_time_v1_only",
    "email-platform/target-intake-generation-context-handoff/trusted-time/v1",
    "target_intake_generation_head_authority",
    "target_intake_generation_head_authority_v1_only",
    "email-platform/target-intake-generation-context-handoff/provider-head/v1",
)
REQUIRED_LF_ATTRIBUTES = (
    "deploy/target-intake-runtime-attestation-policy.synthetic.json text eol=lf",
    "deploy/evidence-index-envelopes/target-intake-runtime-attestation-readiness.synthetic.json text eol=lf",
)
REQUIRED_OUTPUT_MARKERS = (
    "status=unconfigured readiness=pending",
    "production_acceptance=false",
    "not_committed_eligible=false",
    "authoring-integration=disabled",
    "recovery-integration=disabled",
    "deployment-integration=disabled",
    "runtime-acceptance-integration=disabled",
    "generation-context-role-domain-scope-reuse=forbidden",
    "no-repository-signature-generated=true",
    "no-provider-mutation-performed=true",
    "no-target-observation-claimed=true",
    "runtime-publisher-authentication=unverified",
    "trust-anchor-validity=unverified",
    "trust-anchor-revocation=unverified",
    "provenance-attestation=unverified",
    "immutable-artifact-version=unverified",
    "deploy-digest-selection=unverified",
    "target-observed-runtime-digest=unverified",
    "target-process-identity=unverified",
    "target-loaded-evidence=unverified",
    "trusted-timestamp=unverified",
    "provider-native-head=unverified",
    "provider-head-cas=unverified",
    "global-fork-protection=unverified",
    "global-rollback-protection=unverified",
    "runtime-authority=unverified",
    "original-execution=unverified",
)
REQUIRED_DOCUMENT_MARKERS = (
    (
        "## Runtime bundle/image external attestation readiness",
        "python scripts/target_intake_runtime_attestation_trust.py verify-repository",
        "five distinct runtime-specific",
        "Comparing only Docker",
        "does not retroactively prove the original authoring runtime",
    ),
    (
        "Runtime bundle/image external-attestation closed-v1 synthetic policy SHA-256",
        "Runtime-attestation handoff acknowledgement: policy is `unconfigured`",
    ),
    (
        "A separate closed-v1 synthetic runtime-attestation policy",
        "original execution remain explicitly unverified",
    ),
)
_ALLOWED_IMPORT_ROOTS = {
    "__future__",
    "argparse",
    "external_json",
    "hashlib",
    "hmac",
    "json",
    "pathlib",
    "re",
    "scripts",
    "sys",
    "typing",
}
_FORBIDDEN_CALL_NAMES = {
    "chmod",
    "generate",
    "generate_private_key",
    "hardlink_to",
    "link_to",
    "mkdir",
    "open",
    "private_bytes",
    "remove",
    "rename",
    "replace",
    "rmdir",
    "sign",
    "symlink_to",
    "touch",
    "truncate",
    "unlink",
    "write",
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
    consumer_sources: tuple[str, ...],
    documentation_sources: tuple[str, str, str],
) -> list[str]:
    errors: list[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ["runtime-attestation handoff validator must parse as Python"]

    expected_literals: dict[str, object] = {
        "POLICY_KIND": EXPECTED_POLICY_KIND,
        "READINESS_RECORD_TYPE": EXPECTED_READINESS_RECORD_TYPE,
        "SUBJECT_DOMAIN": EXPECTED_SUBJECT_DOMAIN,
        "REQUIRED_SUBJECT_BINDINGS": EXPECTED_REQUIRED_SUBJECT_BINDINGS,
        "GENERATION_CONTEXT_FORBIDDEN_IDENTITIES": (
            EXPECTED_GENERATION_CONTEXT_FORBIDDEN_IDENTITIES
        ),
        **EXPECTED_AUTHORITY_CONTRACTS,
    }
    for name, expected in expected_literals.items():
        if _literal_assignment(tree, name) != expected:
            errors.append(f"runtime-attestation handoff {name} must remain exact")

    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])
    if imported_roots - _ALLOWED_IMPORT_ROOTS:
        errors.append(
            "runtime-attestation handoff imports exceed the read-only allowlist"
        )
    if _called_names(tree) & _FORBIDDEN_CALL_NAMES:
        errors.append(
            "runtime-attestation handoff must not write, sign, or generate keys"
        )

    separation = _function(tree, "_ensure_authority_separation")
    separation_text = ast.unparse(separation) if separation is not None else ""
    if (
        separation is None
        or "len(identities) != 15" not in separation_text
        or "GENERATION_CONTEXT_FORBIDDEN_IDENTITIES" not in separation_text
    ):
        errors.append(
            "runtime-attestation handoff must enforce five-way and generation-context isolation"
        )

    reader = _function(tree, "_read_single_link")
    if (
        reader is None
        or "read_stable_bytes_with_metadata" not in _called_names(reader)
        or "metadata.st_nlink != 1" not in ast.unparse(reader)
    ):
        errors.append(
            "runtime-attestation policy and readiness must use one stable single-link read"
        )

    verifier = _function(tree, "verify_repository")
    if not {
        "_read_single_link",
        "parse_policy",
        "parse_readiness",
    }.issubset(_called_names(verifier)):
        errors.append(
            "runtime-attestation repository verification must validate both closed artifacts"
        )

    policy_validator = _function(tree, "validate_policy")
    if not {
        "_closed",
        "_ensure_authority_separation",
        "_unconfigured_publisher",
        "_unconfigured_provenance",
        "_unconfigured_target_observer",
        "_unconfigured_trusted_timestamp",
        "_unconfigured_provider_head",
    }.issubset(_called_names(policy_validator)):
        errors.append(
            "runtime-attestation policy must validate every authority and evidence boundary"
        )

    readiness_validator = _function(tree, "validate_readiness")
    if not {"_closed", "compare_digest", "_canonical_digest"}.issubset(
        _called_names(readiness_validator)
    ):
        errors.append(
            "runtime-attestation readiness must bind policy and canonical payload integrity"
        )

    if any(marker not in source for marker in REQUIRED_OUTPUT_MARKERS):
        errors.append(
            "runtime-attestation handoff output must preserve every unverified boundary"
        )
    for command in (
        "python scripts/target_intake_runtime_attestation_trust.py verify-repository",
        "python scripts/verify_target_intake_runtime_attestation_trust.py",
    ):
        if command not in quality_gate:
            errors.append(
                "runtime-attestation handoff verification must remain in the quality gate"
            )
    attribute_lines = tuple(
        line.strip() for line in attributes.splitlines() if line.strip()
    )
    if any(line not in attribute_lines for line in REQUIRED_LF_ATTRIBUTES):
        errors.append(
            "runtime-attestation handoff artifact bytes must remain LF-stable across checkouts"
        )
    if any("target_intake_runtime_attestation_trust" in item for item in consumer_sources):
        errors.append(
            "unconfigured runtime-attestation handoff must not be consumed by authoring, recovery, or deployment"
        )
    for markers, document in zip(REQUIRED_DOCUMENT_MARKERS, documentation_sources):
        if any(marker not in document for marker in markers):
            errors.append(
                "runtime-attestation handoff documentation must preserve the external evidence boundary"
            )

    policy_sha256 = hashlib.sha256(policy_raw).hexdigest()
    try:
        policy = parse_policy(policy_raw)
        readiness = parse_readiness(
            readiness_raw, policy_artifact_sha256=policy_sha256
        )
    except RuntimeAttestationTrustError:
        errors.append(
            "runtime-attestation repository policy/readiness artifacts are invalid"
        )
    else:
        if (
            policy.get("policy_status") != "unconfigured"
            or policy.get("authoring_integration_enabled") is not False
            or policy.get("recovery_integration_enabled") is not False
            or policy.get("deployment_integration_enabled") is not False
            or policy.get("runtime_acceptance_integration_enabled") is not False
            or readiness.get("readiness_status") != "pending"
            or readiness.get("production_acceptance") is not False
            or readiness.get("not_committed_eligible") is not False
        ):
            errors.append(
                "runtime-attestation handoff must remain unconfigured, pending, and non-accepting"
            )
    return errors


def main() -> int:
    try:
        source = CONTRACT.read_text(encoding="utf-8")
        policy_raw = POLICY.read_bytes()
        readiness_raw = READINESS.read_bytes()
        quality_gate = QUALITY_GATE.read_text(encoding="utf-8")
        attributes = ATTRIBUTES.read_text(encoding="utf-8")
        consumer_sources = tuple(
            path.read_text(encoding="utf-8") for path in CONSUMER_PATHS
        )
        documentation_sources = (
            RUNBOOK.read_text(encoding="utf-8"),
            SIGNOFF.read_text(encoding="utf-8"),
            REQUIREMENTS.read_text(encoding="utf-8"),
        )
    except OSError as error:
        print(str(error), file=sys.stderr)
        return 1
    errors = trust_contract_errors(
        source,
        policy_raw,
        readiness_raw,
        quality_gate,
        attributes,
        consumer_sources,
        documentation_sources,
    )
    if errors:
        print("; ".join(errors), file=sys.stderr)
        return 1
    print(
        "target-intake-runtime-attestation-handoff-static-ok "
        "status=unconfigured readiness=pending production_acceptance=false "
        "no-write-no-network-no-signing=true integration=disabled"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
