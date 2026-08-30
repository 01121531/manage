"""Statically lock the T207 external-evidence intake boundary."""

from __future__ import annotations

import ast
from pathlib import Path
import sys

try:
    from scripts.target_intake_runtime_attestation_external_evidence import (
        EXPECTED_POLICY_SHA256,
        verify_repository_policy,
    )
except ModuleNotFoundError:
    from target_intake_runtime_attestation_external_evidence import (
        EXPECTED_POLICY_SHA256,
        verify_repository_policy,
    )


ROOT = Path(__file__).resolve().parents[1]
INTAKE = ROOT / "scripts" / "target_intake_runtime_attestation_external_evidence.py"
GENERATOR = ROOT / "scripts" / "create_runtime_attestation_external_evidence_index.py"
POLICY = ROOT / "deploy" / "runtime-attestation-external-evidence-policy.json"
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
CONSUMER_ROOTS = (ROOT / "platform", ROOT / "infra")
FORBIDDEN_IMPORTS = {"socket", "subprocess", "urllib", "requests", "httpx"}
FORBIDDEN_CALLS = {
    "urlopen", "request", "post", "put", "delete", "run", "Popen",
    "generate_private_key", "load_pem_private_key", "load_der_private_key", "sign",
}


def _capability_errors() -> list[str]:
    errors: list[str] = []
    source = INTAKE.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ["T207 intake must parse as Python"]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".", 1)[0] in FORBIDDEN_IMPORTS:
                    errors.append("T207 intake imports network or subprocess capability")
        elif isinstance(node, ast.ImportFrom) and node.module and node.module.split(".", 1)[0] in FORBIDDEN_IMPORTS:
            errors.append("T207 intake imports network or subprocess capability")
        elif isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ""
            if name in FORBIDDEN_CALLS:
                errors.append(f"T207 intake calls forbidden capability {name}")
    for marker in (
        "original_execution_verified: bool = False",
        "runtime_authority_verified: bool = False",
        "production_acceptance: bool = False",
        '"trust_root_currentness": "unverified"',
        '"provider_native_cas": "unverified"',
        "_verify_cosign_payload",
        "_verify_github_bundle",
        "expected_manifest_sha256",
        "expected_policy_sha256",
        "metadata.st_nlink != 1",
        "expected_identity=blob.identity",
        "_POLICY_INTEGRATION_FIELDS",
        "_POLICY_PROVIDER_FIELDS",
        "_POLICY_RELEASE_FIELDS",
        "_POLICY_OBSERVER_FIELDS",
        "_POLICY_TRUST_FIELDS",
        '_closed(value.get("provider_custody"), _POLICY_PROVIDER_FIELDS',
        '_closed(value.get("target_observer"), _POLICY_OBSERVER_FIELDS',
        '_closed(value.get("trust_currentness"), _POLICY_TRUST_FIELDS',
    ):
        if marker not in source:
            errors.append(f"T207 intake boundary is missing: {marker}")
    return errors


def verify_static_contract() -> list[str]:
    errors = _capability_errors()
    if not GENERATOR.exists() or not POLICY.exists():
        errors.append("T207 generator or policy is missing")
    release = RELEASE.read_text(encoding="utf-8")
    required_release = (
        "cosign-release: v3.1.3",
        "docker buildx imagetools inspect --raw",
        "gh attestation trusted-root",
        "gh attestation trusted-root --verify-only",
        "cosign verify-blob",
        "gh attestation verify",
        "create_runtime_attestation_external_evidence_index.py",
        "runtime-attestation.external-evidence-index.json",
    )
    if any(marker not in release for marker in required_release):
        errors.append("release workflow does not capture and index the T207 evidence set")
    capture = release.find("- name: Capture raw provider evidence before promotion")
    verify = release.find("- name: Verify keyless image signature and SBOM attestation")
    index = release.find("- name: Build caller-pinnable external evidence index")
    promote = release.find("- name: Publish verified release tag")
    if min(capture, verify, index, promote) < 0 or not capture < verify < index < promote:
        errors.append("T207 capture, verification, indexing, and promotion order drifted")
    capture_text = release[capture:verify]
    if "jq" in capture_text or "github-provenance.bundle.jsonl" not in capture_text:
        errors.append("raw release bundles must be copied without parse-reserialization")
    for root in CONSUMER_ROOTS:
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="replace")
            if "target_intake_runtime_attestation_external_evidence" in text:
                errors.append("production consumer imports T207 external evidence intake")
    quality = (ROOT / "scripts" / "quality_gate.ps1").read_text(encoding="utf-8")
    runbook = (ROOT / "deploy" / "runbooks" / "target-intake-preflight.md").read_text(encoding="utf-8")
    signoff = (ROOT / "deploy" / "production-signoff-template.md").read_text(encoding="utf-8")
    if "verify_target_intake_runtime_attestation_external_evidence.py" not in quality:
        errors.append("T207 static verification is missing from the quality gate")
    marker = "captured external evidence is not runtime authority"
    if marker not in runbook or marker not in signoff:
        errors.append("T207 authority boundary is missing from runbook or signoff")
    try:
        output = verify_repository_policy()
    except Exception:
        errors.append("T207 repository policy is invalid")
    else:
        if EXPECTED_POLICY_SHA256 not in output or "production_acceptance=false" not in output:
            errors.append("T207 repository policy output overstates authority")
    return errors


def main() -> int:
    try:
        errors = verify_static_contract()
    except OSError:
        print("runtime-attestation-external-static-error: assets cannot be read", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"runtime-attestation-external-static-error: {error}", file=sys.stderr)
        return 1
    print(
        "runtime-attestation-external-static-ok external-index=caller-pinned "
        "target-observer=unconfigured provider-native-cas=unverified "
        "runtime-authority=unverified production_acceptance=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
