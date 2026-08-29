"""Statically lock the T206 pure-bytes provider fixture boundary."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import sys

try:
    from scripts.target_intake_runtime_attestation_provider_fixture import (
        EXPECTED_ADAPTER_PROFILE_SHA256,
        EXPECTED_EVIDENCE_INDEX_SHA256,
        verify_repository_fixture,
    )
except ModuleNotFoundError:
    from target_intake_runtime_attestation_provider_fixture import (
        EXPECTED_ADAPTER_PROFILE_SHA256,
        EXPECTED_EVIDENCE_INDEX_SHA256,
        verify_repository_fixture,
    )


ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "scripts" / "target_intake_runtime_attestation_provider_adapter.py"
CRYPTO = ROOT / "scripts" / "runtime_attestation_crypto.py"
T204 = ROOT / "scripts" / "target_intake_runtime_attestation_trust.py"
T205 = ROOT / "scripts" / "target_intake_runtime_attestation_intake.py"
PROFILE = ROOT / "deploy" / "runtime-attestation-provider-fixtures" / "provider-adapter-profile.synthetic.json"
INDEX = ROOT / "deploy" / "runtime-attestation-provider-fixtures" / "provider-evidence-index.synthetic.json"

EXPECTED_T204_SOURCE_SHA256 = "c9d07269a42ebcf7014ab0252161a004355e6ff32ba16af7cb0a9584d4398097"
EXPECTED_T205_SOURCE_SHA256 = "d519cbace8830572c55e0be07efbefee3ec4ef3a9f8ee15c3a674c12eaff8ca3"
FORBIDDEN_IMPORTS = {"pathlib", "socket", "subprocess", "urllib", "requests", "http", "os"}
FORBIDDEN_CALLS = {
    "open", "read_stable_bytes", "read_stable_bytes_with_metadata", "urlopen", "run", "Popen",
    "generate_private_key", "load_pem_private_key", "load_der_private_key", "sign", "now", "utcnow", "time",
}
CONSUMER_ROOTS = (ROOT / "platform", ROOT / "infra")


def _normalized_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def _check_pure(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, UnicodeError, SyntaxError):
        return [f"{path.name} must parse as UTF-8 Python"]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".", 1)[0] in FORBIDDEN_IMPORTS:
                    errors.append(f"{path.name} imports external-I/O capability")
        elif isinstance(node, ast.ImportFrom) and node.module and node.module.split(".", 1)[0] in FORBIDDEN_IMPORTS:
            errors.append(f"{path.name} imports external-I/O capability")
        elif isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ""
            if name in FORBIDDEN_CALLS:
                errors.append(f"{path.name} calls forbidden capability {name}")
    return errors


def verify_static_contract() -> list[str]:
    errors = _check_pure(ADAPTER) + _check_pure(CRYPTO)
    adapter_source = ADAPTER.read_text(encoding="utf-8")
    crypto_source = CRYPTO.read_text(encoding="utf-8")
    required_adapter = (
        "verify_ecdsa_signature(cosign_cert.public_key(), cosign_signature, raw_inputs.cosign_payload)",
        "verify_ecdsa_signature(github_cert.public_key(), github_signature, pae_raw)",
        "statement_raw = decode_base64(envelope[\"payload\"]",
        "pae_raw = dsse_pae(INTOTO_PAYLOAD_TYPE, statement_raw)",
        "production_acceptance=False",
        "provider_native_cas_verified=False",
        "original_execution_verified=False",
        "runtime_authority_verified=False",
    )
    required_crypto = (
        "b\"DSSEv1 \"",
        "hashlib.sha256(expected_signature).digest()",
        "verify_ed25519_signature(public_key_raw, signature_record[4:], note_text)",
        "verify_ecdsa_signature(leaf.public_key(), signature, _set_from_implicit(signed_attrs))",
    )
    if any(marker not in adapter_source for marker in required_adapter):
        errors.append("provider adapter exact-byte signature or negative-authority contract drifted")
    if any(marker not in crypto_source for marker in required_crypto):
        errors.append("provider cryptographic protocol contract drifted")
    if _normalized_sha(T204) != EXPECTED_T204_SOURCE_SHA256 or _normalized_sha(T205) != EXPECTED_T205_SOURCE_SHA256:
        errors.append("T204/T205 frozen verifier source drifted")
    if hashlib.sha256(PROFILE.read_bytes()).hexdigest() != EXPECTED_ADAPTER_PROFILE_SHA256:
        errors.append("adapter profile raw pin drifted")
    if hashlib.sha256(INDEX.read_bytes()).hexdigest() != EXPECTED_EVIDENCE_INDEX_SHA256:
        errors.append("provider evidence index raw pin drifted")
    for root in CONSUMER_ROOTS:
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="replace")
            if "target_intake_runtime_attestation_provider" in text:
                errors.append("production consumer imports the synthetic provider fixture")
    quality = (ROOT / "scripts" / "quality_gate.ps1").read_text(encoding="utf-8")
    if "verify_target_intake_runtime_attestation_provider_adapter.py" not in quality or "target_intake_runtime_attestation_provider_fixture.py" not in quality:
        errors.append("T206 fixture verification is missing from the quality gate")
    runbook = (ROOT / "deploy" / "runbooks" / "target-intake-preflight.md").read_text(encoding="utf-8")
    signoff = (ROOT / "deploy" / "production-signoff-template.md").read_text(encoding="utf-8")
    marker = "fixture cryptography does not establish provider authority"
    if marker not in runbook or marker not in signoff:
        errors.append("T206 authority boundary is missing from runbook or signoff")
    try:
        output = verify_repository_fixture()
    except Exception:
        errors.append("pinned T206 repository fixture is invalid")
    else:
        if "production_acceptance=false" not in output or "provider-native-cas=unverified" not in output:
            errors.append("T206 repository result overstates authority")
    return errors


def main() -> int:
    try:
        errors = verify_static_contract()
    except OSError:
        print("runtime-attestation-provider-static-error: assets cannot be read", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"runtime-attestation-provider-static-error: {error}", file=sys.stderr)
        return 1
    print("runtime-attestation-provider-static-ok pure-bytes=true raw-signature-inputs=true fixture-crypto=true provider-authority=unverified production_acceptance=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
