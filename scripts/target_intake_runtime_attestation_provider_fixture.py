"""Repository wrapper for the pinned T206 synthetic provider fixture."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

try:
    from scripts.external_json import StableFileError, read_stable_bytes_with_metadata
    from scripts.target_intake_runtime_attestation_provider_adapter import (
        RawProviderInputs,
        RuntimeAttestationProviderError,
        RuntimeAttestationProviderPins,
        verify_runtime_attestation_provider_bytes,
    )
except ModuleNotFoundError:
    from external_json import StableFileError, read_stable_bytes_with_metadata
    from target_intake_runtime_attestation_provider_adapter import (
        RawProviderInputs,
        RuntimeAttestationProviderError,
        RuntimeAttestationProviderPins,
        verify_runtime_attestation_provider_bytes,
    )


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "deploy" / "runtime-attestation-provider-fixtures"
T204_POLICY = ROOT / "deploy" / "target-intake-runtime-attestation-policy.synthetic.json"
T205_PROFILE = ROOT / "deploy" / "target-intake-runtime-attestation-profile.synthetic.json"
T205_EVIDENCE = ROOT / "deploy" / "evidence-index-envelopes" / "target-intake-runtime-attestation-evidence.synthetic.json"
ADAPTER_PROFILE = FIXTURES / "provider-adapter-profile.synthetic.json"
EVIDENCE_INDEX = FIXTURES / "provider-evidence-index.synthetic.json"

EXPECTED_T204_POLICY_SHA256 = "b56cd792f52b5b5984f69ea8b562e2e07068049e342e04b76eeb97d0333991b0"
EXPECTED_T205_PROFILE_SHA256 = "ead2607f1100cf8141d64022d45be2f78a3b19021ff80df53a890be4961c640d"
EXPECTED_T205_EVIDENCE_SHA256 = "cb8d5466a5a9710b934df14da81cc769d8e36b79d46f386af683e2b556ee37f6"
EXPECTED_RUNTIME_SUBJECT_SHA256 = "5f5d42ed25b9d4c5ad62f53aa4368273642dcdace47c5eb61d2e3997abd6d4bf"
EXPECTED_ADAPTER_PROFILE_SHA256 = "1aa420ff5f27dada1c1e916aaa58559f1538245b008059bdb8276ec8ade0be36"
EXPECTED_EVIDENCE_INDEX_SHA256 = "853bbccb85d167756c1a0e03af650d32e94f15bc62aa9e2b4c4e2732e0dc56be"
EXPECTED_COSIGN_EXECUTABLE_SHA256 = "3154fea0b8393aa8a3596a501e3f4140899b054a5781ed27d975bc2c0334edb2"
EXPECTED_GITHUB_EXECUTABLE_SHA256 = "9b97fa7b8bdeb8b3aaebea674e504117143ed4f5a22ebee140efa5154d8004f1"

ASSET_PATHS = {
    "cosign_payload": FIXTURES / "cosign-payload.synthetic.json",
    "cosign_bundle": FIXTURES / "cosign-message-signature.bundle.synthetic.json",
    "github_bundle": FIXTURES / "github-provenance.bundle.synthetic.jsonl",
    "trusted_root": FIXTURES / "trusted-root.synthetic.json",
    "revocation_snapshot": FIXTURES / "revocation-snapshot.synthetic.json",
    "rekor_checkpoint": FIXTURES / "rekor-checkpoint.synthetic.txt",
    "cosign_timestamp": FIXTURES / "cosign-rfc3161.synthetic.tsr.b64",
    "github_timestamp": FIXTURES / "github-rfc3161.synthetic.tsr.b64",
    "target_observer": FIXTURES / "target-observer-envelope.synthetic.json",
    "provider_write_receipt": FIXTURES / "provider-cas-write-receipt.synthetic.json",
    "provider_read_receipt": FIXTURES / "provider-cas-read-receipt.synthetic.json",
    "cosign_cli_result": FIXTURES / "cosign-verify-result.synthetic.json",
    "github_cli_result": FIXTURES / "github-attestation-verify-result.synthetic.json",
}


def _read(path: Path, maximum: int = 4_194_304) -> bytes:
    try:
        raw, metadata = read_stable_bytes_with_metadata(path, max_bytes=maximum)
    except (OSError, StableFileError) as error:
        raise RuntimeAttestationProviderError("provider fixture cannot be read safely") from error
    if metadata.st_nlink != 1:
        raise RuntimeAttestationProviderError("provider fixture cannot be read safely")
    return raw


def verify_repository_fixture() -> str:
    verified = verify_runtime_attestation_provider_bytes(
        t204_policy_raw=_read(T204_POLICY),
        t205_profile_raw=_read(T205_PROFILE),
        t205_evidence_raw=_read(T205_EVIDENCE),
        adapter_profile_raw=_read(ADAPTER_PROFILE),
        evidence_index_raw=_read(EVIDENCE_INDEX),
        raw_inputs=RawProviderInputs(**{name: _read(path) for name, path in ASSET_PATHS.items()}),
        pins=RuntimeAttestationProviderPins(
            t204_policy_sha256=EXPECTED_T204_POLICY_SHA256,
            t205_profile_sha256=EXPECTED_T205_PROFILE_SHA256,
            t205_evidence_sha256=EXPECTED_T205_EVIDENCE_SHA256,
            t205_runtime_subject_sha256=EXPECTED_RUNTIME_SUBJECT_SHA256,
            adapter_profile_sha256=EXPECTED_ADAPTER_PROFILE_SHA256,
            evidence_index_sha256=EXPECTED_EVIDENCE_INDEX_SHA256,
            cosign_executable_sha256=EXPECTED_COSIGN_EXECUTABLE_SHA256,
            github_executable_sha256=EXPECTED_GITHUB_EXECUTABLE_SHA256,
        ),
    )
    return (
        "runtime-attestation-provider-fixture-ok "
        "cosign-raw-message-signature=fixture-verified "
        "github-dsse-pae=fixture-verified rfc3161-cms=fixture-verified "
        "rekor-inclusion-checkpoint=fixture-verified "
        "target-observer-signature=fixture-verified provider-receipt-signature=fixture-verified "
        "trust-root-currentness=unverified revocation-freshness=unverified "
        "provider-native-cas=unverified provider-custody=unverified "
        "original-execution=unverified runtime-authority=unverified production_acceptance=false "
        f"subject_sha256={verified.runtime_subject_sha256}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the pinned synthetic T206 provider fixture.")
    parser.parse_args()
    try:
        print(verify_repository_fixture())
    except RuntimeAttestationProviderError as error:
        print(f"runtime-attestation-provider-fixture-error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
