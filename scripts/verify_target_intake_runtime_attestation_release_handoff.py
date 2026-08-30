"""Static gate for the T208 three-image external evidence handoff."""

from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts" / "target_intake_runtime_attestation_release_handoff.py"
QUALITY_GATE = ROOT / "scripts" / "quality_gate.ps1"
RUNBOOK = ROOT / "deploy" / "runbooks" / "target-intake-preflight.md"
SIGNOFF = ROOT / "deploy" / "production-signoff-template.md"
PRODUCTION_CONSUMERS = (
    ROOT / "scripts" / "deploy_release.py",
    ROOT / "scripts" / "rolling_release.py",
    ROOT / "scripts" / "rollback_release.py",
    ROOT / "scripts" / "target_intake_preflight.py",
)


def _imports(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".", 1)[0])
    return names


def verification_errors(
    source: str,
    quality_gate: str,
    runbook: str,
    signoff: str,
    consumers: tuple[str, ...],
) -> list[str]:
    errors: list[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ["release handoff verifier source is invalid"]
    forbidden_imports = {
        "aiohttp", "boto3", "cryptography", "http", "requests", "socket",
        "subprocess", "time", "urllib",
    }
    if _imports(tree).intersection(forbidden_imports):
        errors.append("release handoff verifier must not gain network, process, signing, or host-time capability")
    forbidden_calls = (
        ".open(", ".write_bytes(", ".write_text(", "open(", "Popen(", "run(",
        "urlopen(", "requests.", "socket.", "sign(", "generate_private_key(",
    )
    for marker in forbidden_calls:
        if marker in source:
            errors.append(f"release handoff verifier has forbidden capability marker: {marker}")
    for marker in (
        'HANDOFF_KIND = "runtime_attestation_release_handoff_v1"',
        'EXPECTED_NAMES = ("api", "web", "edge")',
        '"handoff_manifest_pin": "caller_supplied"',
        '"index_pins": "independently_retained"',
        '"runtime_authority": "unverified"',
        "production_acceptance: bool = False",
        "verify_external_evidence(",
        "result.workflow_ref == release[\"workflow_ref\"]",
        "result.run_id == release[\"run_id\"]",
        "result.run_attempt == release[\"run_attempt\"]",
        "expected_manifest_sha256=str(record[\"manifest_sha256\"])",
        "expected_policy_sha256=expected_policy",
        "release handoff changed during verification",
        "target-observer=unverified",
        "provider-native-cas=unverified",
        "original-execution=unverified",
        "runtime-authority=unverified",
        "production_acceptance=false",
    ):
        if marker not in source:
            errors.append(f"release handoff verifier is missing: {marker}")
    if "python scripts/verify_target_intake_runtime_attestation_release_handoff.py" not in quality_gate:
        errors.append("release handoff static gate is not registered in the quality gate")
    for marker in (
        "T208 three-image external evidence handoff",
        "caller-supplied handoff pin",
        "GitHub Release assets are persistence copies, not provider custody",
        "real tag release has not been executed",
    ):
        if marker not in runbook:
            errors.append(f"release handoff runbook is missing: {marker}")
    for marker in (
        "Caller-pinned T208 three-image release handoff",
        "GitHub Release persistence is not provider-native custody",
        "Real tag workflow execution and independent download review",
    ):
        if marker not in signoff:
            errors.append(f"release handoff signoff boundary is missing: {marker}")
    for consumer in consumers:
        if "target_intake_runtime_attestation_release_handoff" in consumer:
            errors.append("release handoff must remain disconnected from production consumers")
    return errors


def main() -> int:
    try:
        source = SOURCE.read_text(encoding="utf-8")
        quality_gate = QUALITY_GATE.read_text(encoding="utf-8")
        runbook = RUNBOOK.read_text(encoding="utf-8")
        signoff = SIGNOFF.read_text(encoding="utf-8")
        consumers = tuple(path.read_text(encoding="utf-8") for path in PRODUCTION_CONSUMERS)
    except (OSError, UnicodeError):
        print("runtime-attestation-release-handoff-static-error: repository assets cannot be read")
        return 1
    errors = verification_errors(source, quality_gate, runbook, signoff, consumers)
    if errors:
        for error in errors:
            print(f"runtime-attestation-release-handoff-static-error: {error}")
        return 1
    print(
        "runtime-attestation-release-handoff-static-ok images=api,web,edge "
        "caller-pins=handoff-policy production-consumer=disconnected "
        "runtime-authority=unverified production_acceptance=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
