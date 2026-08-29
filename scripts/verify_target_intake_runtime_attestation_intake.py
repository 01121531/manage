"""Statically lock the T205 synthetic runtime-attestation intake boundary."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import sys
from typing import Mapping

try:
    from scripts.target_intake_runtime_attestation_intake import (
        EXPECTED_FIXTURE_SUBJECT_SHA256,
        RuntimeAttestationIntakeError,
        verify_runtime_attestation_protocol_bytes,
    )
except ModuleNotFoundError:  # Direct script loading from scripts/.
    from target_intake_runtime_attestation_intake import (
        EXPECTED_FIXTURE_SUBJECT_SHA256,
        RuntimeAttestationIntakeError,
        verify_runtime_attestation_protocol_bytes,
    )


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "scripts" / "target_intake_runtime_attestation_intake.py"
POLICY = ROOT / "deploy" / "target-intake-runtime-attestation-policy.synthetic.json"
PROFILE = ROOT / "deploy" / "target-intake-runtime-attestation-profile.synthetic.json"
EVIDENCE = (
    ROOT
    / "deploy"
    / "evidence-index-envelopes"
    / "target-intake-runtime-attestation-evidence.synthetic.json"
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

EXPECTED_POLICY_SHA256 = "b56cd792f52b5b5984f69ea8b562e2e07068049e342e04b76eeb97d0333991b0"
EXPECTED_PROFILE_SHA256 = "ead2607f1100cf8141d64022d45be2f78a3b19021ff80df53a890be4961c640d"
EXPECTED_EVIDENCE_SHA256 = "cb8d5466a5a9710b934df14da81cc769d8e36b79d46f386af683e2b556ee37f6"
EXPECTED_SUBJECT_SHA256 = "5f5d42ed25b9d4c5ad62f53aa4368273642dcdace47c5eb61d2e3997abd6d4bf"

_ALLOWED_IMPORT_ROOTS = {
    "__future__",
    "argparse",
    "dataclasses",
    "datetime",
    "external_json",
    "hashlib",
    "hmac",
    "json",
    "pathlib",
    "re",
    "scripts",
    "sys",
    "target_intake_runtime_attestation_trust",
    "typing",
}
_FORBIDDEN_CORE_NAMES = {
    "Path",
    "open",
    "read_stable_bytes_with_metadata",
    "socket",
    "subprocess",
    "time",
    "urlopen",
    "write_atomic_bytes",
}
_FORBIDDEN_CORE_ATTRIBUTES = {
    "chmod",
    "generate",
    "generate_private_key",
    "mkdir",
    "now",
    "open",
    "replace",
    "run",
    "sign",
    "touch",
    "unlink",
    "write_bytes",
    "write_text",
}
_CORE_ROOTS = {
    "verify_runtime_attestation_protocol_bytes",
    "parse_profile",
    "parse_evidence",
}
_REQUIRED_OUTPUT_MARKERS = (
    "profile=configured-offline-fixture-only",
    "protocol-bindings=verified",
    "publisher-authentication=unverified",
    "provenance-authentication=unverified",
    "trust-root-currentness=unverified",
    "revocation-freshness=unverified",
    "target-observer-authentication=unverified",
    "trusted-time=unverified",
    "provider-cas=unverified",
    "global-fork-protection=unverified",
    "global-rollback-protection=unverified",
    "runtime-authority=unverified",
    "original-execution=unverified",
    "production_acceptance=false",
    "no-write-no-network-no-host-time-no-subprocess-no-signing=true",
)
_REQUIRED_DOCUMENT_MARKERS = (
    "## Configured offline runtime-attestation fixture intake",
    "python scripts/target_intake_runtime_attestation_intake.py verify-repository-fixture",
    "protocol bindings only",
    "hermetic_build_claim=false",
    "does not authenticate the original provider bytes",
)
_REQUIRED_SIGNOFF_MARKERS = (
    "Runtime-attestation configured offline-fixture profile",
    "Runtime-attestation protocol-only acknowledgement",
)
_REQUIRED_REQUIREMENTS_MARKERS = (
    "configured offline-fixture-only runtime-attestation verification profile",
    "Sigstore bundle v0.3",
    "GitHub SLSA provenance v1",
    "protocol bindings do not authenticate",
)
_REQUIRED_ATTRIBUTES = (
    "deploy/target-intake-runtime-attestation-profile.synthetic.json text eol=lf",
    "deploy/evidence-index-envelopes/target-intake-runtime-attestation-evidence.synthetic.json text eol=lf",
)


def _literal_assignment(tree: ast.AST, name: str) -> object | None:
    for node in getattr(tree, "body", ()):
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
        ):
            try:
                return ast.literal_eval(node.value)
            except (TypeError, ValueError):
                return None
    return None


def _function_map(tree: ast.AST) -> dict[str, ast.FunctionDef]:
    return {
        node.name: node
        for node in getattr(tree, "body", ())
        if isinstance(node, ast.FunctionDef)
    }


def _called_local_names(node: ast.AST, functions: Mapping[str, ast.FunctionDef]) -> set[str]:
    return {
        call.func.id
        for call in ast.walk(node)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id in functions
    }


def _core_closure(functions: Mapping[str, ast.FunctionDef]) -> set[str]:
    pending = list(_CORE_ROOTS)
    selected: set[str] = set()
    while pending:
        name = pending.pop()
        if name in selected or name not in functions:
            continue
        selected.add(name)
        pending.extend(_called_local_names(functions[name], functions) - selected)
    return selected


def _import_roots(tree: ast.AST) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


def intake_contract_errors(
    *,
    source: str,
    policy_raw: bytes,
    profile_raw: bytes,
    evidence_raw: bytes,
    quality_gate: str,
    attributes: str,
    runbook: str,
    signoff: str,
    requirements: str,
    consumer_sources: tuple[str, ...],
) -> list[str]:
    errors: list[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ["runtime-attestation intake must parse as Python"]
    functions = _function_map(tree)
    if not _CORE_ROOTS.issubset(functions):
        errors.append("runtime-attestation pure bytes entrypoints are missing")
        return errors
    if _import_roots(tree) - _ALLOWED_IMPORT_ROOTS:
        errors.append("runtime-attestation intake imports exceed the closed allowlist")
    expected_literals = {
        "PROFILE_KIND": "target_intake_runtime_attestation_verification_profile_v1",
        "RECORD_TYPE": "target_intake_runtime_attestation_evidence_v1",
        "SIGSTORE_PROFILE": "sigstore_cosign_bundle_v0_3_offline_v1",
        "GITHUB_PROFILE": "github_artifact_attestation_slsa_v1_offline_v1",
        "SIGSTORE_MEDIA_TYPE": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "INTOTO_STATEMENT_TYPE": "https://in-toto.io/Statement/v1",
        "SLSA_PREDICATE_TYPE": "https://slsa.dev/provenance/v1",
        "EXPECTED_FIXTURE_SUBJECT_SHA256": EXPECTED_SUBJECT_SHA256,
    }
    if any(_literal_assignment(tree, name) != value for name, value in expected_literals.items()):
        errors.append("runtime-attestation provider profile or subject anchors drifted")
    if '"assertions"' in source:
        errors.append("runtime-attestation input must not accept caller-authored success assertions")

    closure = _core_closure(functions)
    if not {
        "_parse_canonical",
        "validate_profile",
        "validate_evidence",
        "_validate_sigstore",
        "_validate_github",
        "_validate_trust",
        "_validate_deployment",
        "_validate_target",
        "_validate_timestamp",
        "_validate_head",
    }.issubset(closure):
        errors.append("runtime-attestation pure bytes closure is incomplete")
    for name in closure:
        for node in ast.walk(functions[name]):
            if isinstance(node, ast.Name) and node.id in _FORBIDDEN_CORE_NAMES:
                errors.append("runtime-attestation pure bytes core performs external I/O")
                break
            if isinstance(node, ast.Attribute) and node.attr in _FORBIDDEN_CORE_ATTRIBUTES:
                errors.append("runtime-attestation pure bytes core performs external I/O")
                break

    core_text = ast.unparse(functions["verify_runtime_attestation_protocol_bytes"])
    for marker in (
        "expected_policy_sha256",
        "expected_profile_sha256",
        "expected_runtime_subject_sha256=expected_runtime_subject_sha256",
        "hashlib.sha256(policy_raw).hexdigest()",
        "hashlib.sha256(profile_raw).hexdigest()",
        "parse_policy(policy_raw)",
    ):
        if marker not in core_text:
            errors.append("runtime-attestation caller pins or T204 policy binding drifted")
            break
    parse_text = ast.unparse(functions["_parse_canonical"])
    if "parse_unique_json_bytes" not in parse_text or "raw != _artifact_bytes(value)" not in parse_text:
        errors.append("runtime-attestation intake must require unique canonical JSON bytes")

    for marker in _REQUIRED_OUTPUT_MARKERS:
        if marker not in source:
            errors.append("runtime-attestation output overstates or omits a trust boundary")
            break
    for command in (
        "python scripts/target_intake_runtime_attestation_intake.py verify-repository-fixture",
        "python scripts/verify_target_intake_runtime_attestation_intake.py",
    ):
        if command not in quality_gate:
            errors.append("runtime-attestation intake verification is missing from quality gate")
            break
    attribute_lines = {line.strip() for line in attributes.splitlines() if line.strip()}
    if any(item not in attribute_lines for item in _REQUIRED_ATTRIBUTES):
        errors.append("runtime-attestation configured fixture bytes must remain LF-stable")
    if any("target_intake_runtime_attestation_intake" in source for source in consumer_sources):
        errors.append("runtime-attestation fixture intake must not be consumed by deployment or authoring")
    if any(marker not in runbook for marker in _REQUIRED_DOCUMENT_MARKERS):
        errors.append("runtime-attestation intake runbook boundary is incomplete")
    if any(marker not in signoff for marker in _REQUIRED_SIGNOFF_MARKERS):
        errors.append("runtime-attestation intake signoff boundary is incomplete")
    if any(marker not in requirements for marker in _REQUIRED_REQUIREMENTS_MARKERS):
        errors.append("runtime-attestation intake requirement boundary is incomplete")

    actual_hashes = (
        hashlib.sha256(policy_raw).hexdigest(),
        hashlib.sha256(profile_raw).hexdigest(),
        hashlib.sha256(evidence_raw).hexdigest(),
    )
    if actual_hashes != (
        EXPECTED_POLICY_SHA256,
        EXPECTED_PROFILE_SHA256,
        EXPECTED_EVIDENCE_SHA256,
    ):
        errors.append("runtime-attestation policy/profile/evidence raw anchors drifted")
    if EXPECTED_FIXTURE_SUBJECT_SHA256 != EXPECTED_SUBJECT_SHA256:
        errors.append("runtime-attestation independent fixture subject anchor drifted")
    try:
        verified = verify_runtime_attestation_protocol_bytes(
            policy_raw=policy_raw,
            profile_raw=profile_raw,
            evidence_raw=evidence_raw,
            expected_policy_sha256=EXPECTED_POLICY_SHA256,
            expected_profile_sha256=EXPECTED_PROFILE_SHA256,
            expected_runtime_subject_sha256=EXPECTED_SUBJECT_SHA256,
        )
    except RuntimeAttestationIntakeError:
        errors.append("runtime-attestation configured fixture is invalid")
    else:
        if (
            verified.runtime_subject_sha256 != EXPECTED_SUBJECT_SHA256
            or not verified.runtime_artifact_digest.startswith("sha256:")
        ):
            errors.append("runtime-attestation configured fixture result drifted")
    return errors


def _read(path: Path) -> bytes:
    return path.read_bytes()


def main() -> int:
    try:
        errors = intake_contract_errors(
            source=CONTRACT.read_text(encoding="utf-8"),
            policy_raw=_read(POLICY),
            profile_raw=_read(PROFILE),
            evidence_raw=_read(EVIDENCE),
            quality_gate=QUALITY_GATE.read_text(encoding="utf-8"),
            attributes=ATTRIBUTES.read_text(encoding="utf-8"),
            runbook=RUNBOOK.read_text(encoding="utf-8"),
            signoff=SIGNOFF.read_text(encoding="utf-8"),
            requirements=REQUIREMENTS.read_text(encoding="utf-8"),
            consumer_sources=tuple(path.read_text(encoding="utf-8") for path in CONSUMER_PATHS),
        )
    except OSError:
        print("runtime-attestation-intake-static-error: assets cannot be read", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"runtime-attestation-intake-static-error: {error}", file=sys.stderr)
        return 1
    print(
        "runtime-attestation-intake-static-ok pure-bytes=true canonical=true "
        "caller-pins=policy-profile-subject provider-profile=github-sigstore "
        "integration=disabled production_acceptance=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
