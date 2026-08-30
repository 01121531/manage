"""Statically lock the T209 provider-selection boundary."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import sys

try:
    from scripts.target_intake_runtime_attestation_provider_selection import (
        EXPECTED_POLICY_SHA256,
        EXPECTED_SYNTHETIC_PROFILE_SHA256,
        PREDECESSOR_POLICY_SHA256,
        verify_repository_fixture,
    )
except ModuleNotFoundError:
    from target_intake_runtime_attestation_provider_selection import (
        EXPECTED_POLICY_SHA256,
        EXPECTED_SYNTHETIC_PROFILE_SHA256,
        PREDECESSOR_POLICY_SHA256,
        verify_repository_fixture,
    )


ROOT = Path(__file__).resolve().parents[1]
INTAKE = ROOT / "scripts" / "target_intake_runtime_attestation_provider_selection.py"
POLICY = ROOT / "deploy" / "runtime-attestation-provider-selection-policy.json"
PROFILE = (
    ROOT / "deploy" / "runtime-attestation-provider-selection-profile.synthetic.json"
)
PREDECESSOR = ROOT / "deploy" / "runtime-attestation-external-evidence-policy.json"
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
}


def _capability_errors() -> list[str]:
    errors: list[str] = []
    source = INTAKE.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ["T209 provider selection intake must parse as Python"]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".", 1)[0] in FORBIDDEN_IMPORTS:
                    errors.append("T209 provider selection imports an online capability")
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module
            and node.module.split(".", 1)[0] in FORBIDDEN_IMPORTS
        ):
            errors.append("T209 provider selection imports an online capability")
        elif isinstance(node, ast.Call):
            name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else node.func.attr
                if isinstance(node.func, ast.Attribute)
                else ""
            )
            if name in FORBIDDEN_CALLS:
                errors.append(f"T209 provider selection calls forbidden capability {name}")
    required = (
        "PREDECESSOR_POLICY_SHA256",
        "selected_provider_kind",
        "head_and_entry_must_be_distinct",
        "no_automatic_retry",
        "post_write_readback_required",
        "protected_version_delete_denial_required",
        "reviewer_authority_verified: bool = False",
        "provider_native_cas_verified: bool = False",
        "provider_custody_verified: bool = False",
        "production_acceptance: bool = False",
        "metadata.st_nlink != 1",
        "expected_identity=value.identity",
        "allow_synthetic: bool = False",
        "_reject_placeholder(value)",
    )
    for marker in required:
        if marker not in source:
            errors.append(f"T209 provider selection boundary is missing: {marker}")
    return errors


def verify_static_contract() -> list[str]:
    errors = _capability_errors()
    if hashlib.sha256(PREDECESSOR.read_bytes()).hexdigest() != PREDECESSOR_POLICY_SHA256:
        errors.append("T207 predecessor policy raw pin drifted")
    if hashlib.sha256(POLICY.read_bytes()).hexdigest() != EXPECTED_POLICY_SHA256:
        errors.append("T209 provider selection policy raw pin drifted")
    if (
        hashlib.sha256(PROFILE.read_bytes()).hexdigest()
        != EXPECTED_SYNTHETIC_PROFILE_SHA256
    ):
        errors.append("T209 provider selection fixture raw pin drifted")
    for root in CONSUMER_ROOTS:
        for path in root.rglob("*.py"):
            if "target_intake_runtime_attestation_provider_selection" in path.read_text(
                encoding="utf-8", errors="replace"
            ):
                errors.append("production consumer imports T209 provider selection intake")
    quality = (ROOT / "scripts" / "quality_gate.ps1").read_text(encoding="utf-8")
    if (
        "target_intake_runtime_attestation_provider_selection.py verify-repository"
        not in quality
        or "verify_target_intake_runtime_attestation_provider_selection.py"
        not in quality
    ):
        errors.append("T209 provider selection verification is missing from quality gate")
    runbook = (
        ROOT / "deploy" / "runbooks" / "target-intake-preflight.md"
    ).read_text(encoding="utf-8")
    signoff = (ROOT / "deploy" / "production-signoff-template.md").read_text(
        encoding="utf-8"
    )
    marker = "provider selection does not establish provider custody"
    if marker not in runbook or marker not in signoff:
        errors.append("T209 provider-selection authority boundary is undocumented")
    try:
        output = verify_repository_fixture()
    except Exception:
        errors.append("T209 repository provider-selection fixture is invalid")
    else:
        for marker in (
            "reviewer-authority=unverified",
            "provider-native-cas=unverified",
            "provider-custody=unverified",
            "production_acceptance=false",
        ):
            if marker not in output:
                errors.append("T209 provider selection output overstates authority")
                break
    return errors


def main() -> int:
    try:
        errors = verify_static_contract()
    except OSError:
        print(
            "runtime-attestation-provider-selection-static-error: assets cannot be read",
            file=sys.stderr,
        )
        return 1
    if errors:
        for error in errors:
            print(
                f"runtime-attestation-provider-selection-static-error: {error}",
                file=sys.stderr,
            )
        return 1
    print(
        "runtime-attestation-provider-selection-static-ok unique-selection=true "
        "predecessor-pinned=true provider-native-cas=unverified "
        "provider-custody=unverified production_acceptance=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
