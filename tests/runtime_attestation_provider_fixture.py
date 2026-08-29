"""Test loader for the pinned T206 provider fixture."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json

from scripts.target_intake_runtime_attestation_provider_adapter import (
    RawProviderInputs,
    RuntimeAttestationProviderPins,
    verify_runtime_attestation_provider_bytes,
)
from scripts import target_intake_runtime_attestation_provider_fixture as repository


def artifact(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii")


def load_fixture() -> tuple[dict[str, bytes], RawProviderInputs, RuntimeAttestationProviderPins]:
    fixed = {
        "t204_policy_raw": repository.T204_POLICY.read_bytes(),
        "t205_profile_raw": repository.T205_PROFILE.read_bytes(),
        "t205_evidence_raw": repository.T205_EVIDENCE.read_bytes(),
        "adapter_profile_raw": repository.ADAPTER_PROFILE.read_bytes(),
        "evidence_index_raw": repository.EVIDENCE_INDEX.read_bytes(),
    }
    inputs = RawProviderInputs(**{name: path.read_bytes() for name, path in repository.ASSET_PATHS.items()})
    pins = RuntimeAttestationProviderPins(
        t204_policy_sha256=repository.EXPECTED_T204_POLICY_SHA256,
        t205_profile_sha256=repository.EXPECTED_T205_PROFILE_SHA256,
        t205_evidence_sha256=repository.EXPECTED_T205_EVIDENCE_SHA256,
        t205_runtime_subject_sha256=repository.EXPECTED_RUNTIME_SUBJECT_SHA256,
        adapter_profile_sha256=repository.EXPECTED_ADAPTER_PROFILE_SHA256,
        evidence_index_sha256=repository.EXPECTED_EVIDENCE_INDEX_SHA256,
        cosign_executable_sha256=repository.EXPECTED_COSIGN_EXECUTABLE_SHA256,
        github_executable_sha256=repository.EXPECTED_GITHUB_EXECUTABLE_SHA256,
    )
    return fixed, inputs, pins


def repin_input(
    fixed: dict[str, bytes],
    inputs: RawProviderInputs,
    pins: RuntimeAttestationProviderPins,
    field: str,
    value: bytes,
) -> tuple[dict[str, bytes], RawProviderInputs, RuntimeAttestationProviderPins]:
    inputs = replace(inputs, **{field: value})
    index = json.loads(fixed["evidence_index_raw"])
    name = field.replace("_", "-")
    index["assets"][name] = {"sha256": hashlib.sha256(value).hexdigest(), "size": len(value)}
    fixed = dict(fixed)
    fixed["evidence_index_raw"] = artifact(index)
    pins = replace(pins, evidence_index_sha256=hashlib.sha256(fixed["evidence_index_raw"]).hexdigest())
    return fixed, inputs, pins


def verify(fixed: dict[str, bytes], inputs: RawProviderInputs, pins: RuntimeAttestationProviderPins):
    return verify_runtime_attestation_provider_bytes(**fixed, raw_inputs=inputs, pins=pins)
