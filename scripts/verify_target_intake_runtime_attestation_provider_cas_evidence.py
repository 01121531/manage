"""Statically lock the T210 provider CAS evidence intake boundary."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import sys

try:
    from scripts.target_intake_runtime_attestation_provider_cas_evidence import (
        EXPECTED_POLICY_SHA256,
        EXPECTED_SYNTHETIC_EVIDENCE_SHA256,
        POLICY,
        SELECTION_POLICY,
        SELECTION_POLICY_SHA256,
        SYNTHETIC_ARTIFACT_ROOT,
        SYNTHETIC_EVIDENCE,
        verify_repository_fixture,
    )
except ModuleNotFoundError:
    from target_intake_runtime_attestation_provider_cas_evidence import (
        EXPECTED_POLICY_SHA256,
        EXPECTED_SYNTHETIC_EVIDENCE_SHA256,
        POLICY,
        SELECTION_POLICY,
        SELECTION_POLICY_SHA256,
        SYNTHETIC_ARTIFACT_ROOT,
        SYNTHETIC_EVIDENCE,
        verify_repository_fixture,
    )


ROOT = Path(__file__).resolve().parents[1]
INTAKE = ROOT / "scripts" / "target_intake_runtime_attestation_provider_cas_evidence.py"
CONSUMER_ROOTS = (ROOT / "platform", ROOT / "infra")
FORBIDDEN_IMPORTS = {"socket", "subprocess", "urllib", "requests", "httpx"}
FORBIDDEN_CALLS = {
    "urlopen",
    "request",
    "post",
    "put",
    "delete",
    "run",
    "Popen",
    "generate_private_key",
    "sign",
    "now",
    "utcnow",
    "write_bytes",
    "write_text",
    "unlink",
    "mkdir",
}


def _capability_errors() -> list[str]:
    errors: list[str] = []
    source = INTAKE.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ["T210 provider CAS evidence intake must parse as Python"]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".", 1)[0] in FORBIDDEN_IMPORTS:
                    errors.append("T210 provider CAS evidence imports an online capability")
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module
            and node.module.split(".", 1)[0] in FORBIDDEN_IMPORTS
        ):
            errors.append("T210 provider CAS evidence imports an online capability")
        elif isinstance(node, ast.Call):
            name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else node.func.attr
                if isinstance(node.func, ast.Attribute)
                else ""
            )
            if name in FORBIDDEN_CALLS:
                errors.append(
                    f"T210 provider CAS evidence calls forbidden capability {name}"
                )
    required = (
        "SELECTION_POLICY_SHA256",
        "stale_automatic_retry_count",
        "stale_failure_outcomes",
        "cross_host_writers_distinct=True",
        "metadata.st_nlink != 1",
        "expected_identity=value.identity",
        "reviewer_authority_verified: bool = False",
        "provider_response_authentication_verified: bool = False",
        "provider_native_cas_verified: bool = False",
        "retention_delete_denial_verified: bool = False",
        "provider_custody_verified: bool = False",
        "trusted_time_verified: bool = False",
        "production_acceptance: bool = False",
        "allow_synthetic: bool = False",
        "_reject_placeholder(value)",
        "EXTERNAL_MANIFEST_NAME",
    )
    for marker in required:
        if marker not in source:
            errors.append(f"T210 provider CAS evidence boundary is missing: {marker}")
    return errors


def verify_static_contract() -> list[str]:
    errors = _capability_errors()
    if hashlib.sha256(SELECTION_POLICY.read_bytes()).hexdigest() != SELECTION_POLICY_SHA256:
        errors.append("T209 selection policy predecessor raw pin drifted")
    if hashlib.sha256(POLICY.read_bytes()).hexdigest() != EXPECTED_POLICY_SHA256:
        errors.append("T210 provider CAS evidence policy raw pin drifted")
    if (
        hashlib.sha256(SYNTHETIC_EVIDENCE.read_bytes()).hexdigest()
        != EXPECTED_SYNTHETIC_EVIDENCE_SHA256
    ):
        errors.append("T210 provider CAS evidence fixture raw pin drifted")
    try:
        evidence = json.loads(SYNTHETIC_EVIDENCE.read_bytes())
    except Exception:
        errors.append("T210 provider CAS evidence fixture cannot be parsed")
    else:
        expected_names = {item["path"] for item in evidence.get("artifacts", [])}
        actual_names = {path.name for path in SYNTHETIC_ARTIFACT_ROOT.iterdir()}
        if actual_names != expected_names:
            errors.append("T210 provider CAS raw artifact inventory drifted")
        for item in evidence.get("artifacts", []):
            path = SYNTHETIC_ARTIFACT_ROOT / item["path"]
            try:
                raw = path.read_bytes()
            except OSError:
                errors.append("T210 provider CAS raw artifact is missing")
                continue
            if (
                len(raw) != item.get("size")
                or hashlib.sha256(raw).hexdigest() != item.get("raw_sha256")
            ):
                errors.append("T210 provider CAS raw artifact binding drifted")
    for root in CONSUMER_ROOTS:
        for path in root.rglob("*.py"):
            if "target_intake_runtime_attestation_provider_cas_evidence" in path.read_text(
                encoding="utf-8", errors="replace"
            ):
                errors.append("production consumer imports T210 provider CAS evidence intake")
    quality = (ROOT / "scripts" / "quality_gate.ps1").read_text(encoding="utf-8")
    if (
        "target_intake_runtime_attestation_provider_cas_evidence.py verify-repository"
        not in quality
        or "verify_target_intake_runtime_attestation_provider_cas_evidence.py"
        not in quality
    ):
        errors.append("T210 provider CAS evidence verification is missing from quality gate")
    runbook = (
        ROOT / "deploy" / "runbooks" / "target-intake-preflight.md"
    ).read_text(encoding="utf-8")
    signoff = (ROOT / "deploy" / "production-signoff-template.md").read_text(
        encoding="utf-8"
    )
    marker = "CAS evidence structure does not establish provider authority or custody"
    if marker not in runbook or marker not in signoff:
        errors.append("T210 provider CAS evidence authority boundary is undocumented")
    try:
        output = verify_repository_fixture()
    except Exception:
        errors.append("T210 repository provider CAS evidence fixture is invalid")
    else:
        for marker in (
            "provider-response-authentication=unverified",
            "provider-native-cas=unverified",
            "retention-delete-denial=unverified",
            "provider-custody=unverified",
            "trusted-time=unverified",
            "production_acceptance=false",
        ):
            if marker not in output:
                errors.append("T210 provider CAS evidence output overstates authority")
                break
    return errors


def main() -> int:
    try:
        errors = verify_static_contract()
    except OSError:
        print(
            "runtime-attestation-provider-cas-evidence-static-error: assets cannot be read",
            file=sys.stderr,
        )
        return 1
    if errors:
        for error in errors:
            print(
                f"runtime-attestation-provider-cas-evidence-static-error: {error}",
                file=sys.stderr,
            )
        return 1
    print(
        "runtime-attestation-provider-cas-evidence-static-ok "
        "selection-profile-pinned=true artifact-inventory=exact "
        "provider-native-cas=unverified provider-custody=unverified "
        "production_acceptance=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
