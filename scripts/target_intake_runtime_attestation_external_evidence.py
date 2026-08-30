"""Verify a caller-pinned T207 release evidence index and its exact raw files.

The verifier is intentionally offline.  It authenticates file bytes and release
subject bindings only; it does not turn CLI output, workflow metadata, or a
refreshed trusted-root file into provider authority or trusted currentness.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass
from datetime import datetime
import hashlib
import hmac
import json
from pathlib import Path
import re
import sys
from typing import Mapping

try:
    from scripts.external_json import (
        StableFileError,
        StableFileIdentity,
        parse_unique_json_bytes,
        read_stable_bytes_with_metadata,
        stable_file_identity,
    )
except ModuleNotFoundError:
    from external_json import (
        StableFileError,
        StableFileIdentity,
        parse_unique_json_bytes,
        read_stable_bytes_with_metadata,
        stable_file_identity,
    )


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "deploy" / "runtime-attestation-external-evidence-policy.json"
EXPECTED_POLICY_SHA256 = "3c52cacdf836ba3c63288adf053871e8943cbe8c21676ce7c4fe1381a4820bbd"
MAX_INDEX_BYTES = 131_072
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
INDEX_KIND = "runtime_attestation_external_evidence_index"
_SHA256 = re.compile(r"[0-9a-f]{64}")
_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
_IMAGE = re.compile(r"ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_DECIMAL = re.compile(r"[1-9][0-9]*")


ARTIFACT_SPECS: tuple[tuple[str, str, str], ...] = (
    ("oci_manifest", "oci-manifest.raw.json", "application/octet-stream"),
    ("cosign_bundle", "cosign.bundle.json", "application/vnd.dev.sigstore.bundle.v0.3+json"),
    ("cosign_payload", "cosign.payload.json", "application/vnd.dev.cosign.simplesigning.v1+json"),
    ("github_bundle", "github-provenance.bundle.jsonl", "application/vnd.dev.sigstore.bundle+jsonl"),
    ("github_sigstore_trusted_root", "github-sigstore.trusted-root.jsonl", "application/vnd.dev.sigstore.trustedroot+jsonl"),
    ("tuf_verify_result", "tuf.verify.txt", "text/plain"),
    ("cosign_executable_digest", "cosign.executable.sha256", "text/plain"),
    ("cosign_version", "cosign.version.json", "application/json"),
    ("cosign_bundle_verify_result", "cosign.bundle.verify.txt", "text/plain"),
    ("cosign_verify_result", "cosign.verify.json", "application/json"),
    ("cosign_verify_attestation_result", "cosign.verify-attestation.json", "application/json"),
    ("github_executable_digest", "github.executable.sha256", "text/plain"),
    ("github_version", "github.version.txt", "text/plain"),
    ("github_verify_result", "github.verify.json", "application/json"),
)

_INDEX_FIELDS = {
    "artifacts", "capture", "evidence_kind", "name", "production_acceptance",
    "release", "requirements", "schema_version", "synthetic",
}
_RELEASE_FIELDS = {
    "captured_at", "commit", "digest", "image", "owner_id", "repository",
    "repository_id", "run_attempt", "run_id", "tag", "workflow_ref",
}
_ARTIFACT_FIELDS = {"media_type", "name", "path", "sha256", "size_bytes"}
_CAPTURE = {
    "bundle_bytes_preserved": True,
    "cli_outputs_preserved": True,
    "host_clock_trusted": False,
    "oci_manifest_digest_verified": True,
    "provider_mutation_performed": False,
    "target_observation_performed": False,
    "trusted_root_method": "gh_attestation_trusted_root_tuf",
}
_REQUIREMENTS = {
    "cross_host_fork_rollback": "unverified",
    "original_execution": "unverified",
    "provider_custody": "unverified",
    "provider_native_cas": "unverified",
    "revocation_freshness": "unverified",
    "runtime_authority": "unverified",
    "target_observer": "unverified",
    "transparency_currentness": "unverified",
    "trust_root_currentness": "unverified",
    "trusted_time": "unverified",
}
_POLICY_INTEGRATION_FIELDS = {
    "authoring", "deployment", "recovery", "runtime_acceptance",
}
_POLICY_PROVIDER_FIELDS = {
    "allowed_provider_kinds", "required_evidence", "selected_provider_kind", "status",
}
_POLICY_RELEASE_FIELDS = {
    "artifact_names", "bundle_bytes_must_be_preserved", "caller_pinned_manifest_required",
    "external_absolute_root_required", "oci_manifest_digest_must_match_release",
    "stable_single_link_reads_required",
}
_POLICY_OBSERVER_FIELDS = {
    "allowed_execution_locations", "required_evidence", "signing_domain", "status",
    "workflow_signer_key_reuse_allowed",
}
_POLICY_TRUST_FIELDS = {
    "host_clock_is_trusted_time", "online_revocation_or_status_required",
    "rekor_and_ct_currentness_required", "signed_timestamp_replay_policy_required",
    "status", "trusted_root_refresh_per_release_required", "tuf_metadata_chain_required",
}
_PROVIDER_KINDS = [
    "aws_s3_object_lock", "azure_blob_immutable", "gcp_cloud_storage_generation",
]
_PROVIDER_EVIDENCE = [
    "authenticated_workload_identity", "caller_pinned_prior_head",
    "provider_native_cas_precondition", "stale_write_409_or_412_or_generation_failure",
    "no_automatic_retry", "immutable_version_identity", "retention_configuration",
    "delete_denial", "post_denial_readback", "cross_host_latest_head",
    "fork_and_rollback_review",
]
_OBSERVER_LOCATIONS = ["dedicated_management_host", "isolated_kubernetes_namespace"]
_OBSERVER_EVIDENCE = [
    "federated_workload_identity", "kms_or_hsm_key_reference",
    "observer_key_authorization_snapshot", "observer_key_validity_and_revocation",
    "release_challenge_nonce", "target_environment_and_host_identity",
    "image_object_id_and_repo_digest", "process_start_and_executable_digest",
    "loaded_module_and_native_evidence", "post_deploy_readback",
    "independent_trusted_time",
]


class RuntimeAttestationExternalEvidenceError(ValueError):
    pass


@dataclass(frozen=True)
class StableInput:
    path: Path
    raw: bytes
    identity: StableFileIdentity
    sha256: str
    maximum: int


@dataclass(frozen=True)
class VerifiedExternalEvidence:
    manifest_sha256: str
    policy_sha256: str
    name: str
    image: str
    digest: str
    commit: str
    repository: str
    repository_id: str
    owner_id: str
    tag: str
    workflow_ref: str
    run_id: str
    run_attempt: int
    artifact_sha256: tuple[tuple[str, str], ...]
    exact_subject_bindings_verified: bool
    original_execution_verified: bool = False
    runtime_authority_verified: bool = False
    production_acceptance: bool = False


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def _closed(value: object, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise RuntimeAttestationExternalEvidenceError(f"{label} is invalid")
    return dict(value)


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise RuntimeAttestationExternalEvidenceError(f"{label} is invalid")
    return value


def _safe_text(value: object, label: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or any(ord(ch) < 32 for ch in value):
        raise RuntimeAttestationExternalEvidenceError(f"{label} is invalid")
    return value


def _external_root(value: Path | str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise RuntimeAttestationExternalEvidenceError("external evidence root is invalid")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(ROOT.resolve(strict=True))
    except ValueError:
        return resolved
    except OSError as error:
        raise RuntimeAttestationExternalEvidenceError("external evidence root is invalid") from error
    raise RuntimeAttestationExternalEvidenceError("external evidence root is invalid")


def _stable(path: Path, maximum: int) -> StableInput:
    try:
        raw, metadata = read_stable_bytes_with_metadata(path, max_bytes=maximum)
    except (OSError, StableFileError, ValueError) as error:
        raise RuntimeAttestationExternalEvidenceError("external evidence cannot be read safely") from error
    if metadata.st_nlink != 1:
        raise RuntimeAttestationExternalEvidenceError("external evidence cannot be read safely")
    return StableInput(
        path=path,
        raw=raw,
        identity=stable_file_identity(metadata),
        sha256=hashlib.sha256(raw).hexdigest(),
        maximum=maximum,
    )


def _unchanged(blob: StableInput) -> None:
    try:
        raw, metadata = read_stable_bytes_with_metadata(
            blob.path, max_bytes=blob.maximum, expected_identity=blob.identity
        )
    except (OSError, StableFileError, ValueError) as error:
        raise RuntimeAttestationExternalEvidenceError("external evidence changed during verification") from error
    if metadata.st_nlink != 1 or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), blob.sha256):
        raise RuntimeAttestationExternalEvidenceError("external evidence changed during verification")


def _parse_canonical(raw: bytes, maximum: int, label: str) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        raise RuntimeAttestationExternalEvidenceError(f"{label} is invalid")
    try:
        value = parse_unique_json_bytes(raw)
    except (TypeError, ValueError) as error:
        raise RuntimeAttestationExternalEvidenceError(f"{label} is invalid") from error
    canonical = _canonical_bytes(value)
    if not isinstance(value, Mapping) or raw not in (canonical, canonical.removesuffix(b"\n")):
        raise RuntimeAttestationExternalEvidenceError(f"{label} is invalid")
    return dict(value)


def verify_policy_bytes(raw: bytes, *, expected_sha256: str) -> str:
    expected = _digest(expected_sha256, "policy pin")
    actual = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise RuntimeAttestationExternalEvidenceError("policy pin drifted")
    value = _parse_canonical(raw, MAX_INDEX_BYTES, "external evidence policy")
    expected_fields = {
        "integration", "policy_kind", "policy_status", "production_acceptance",
        "provider_custody", "release_evidence", "schema_version", "synthetic",
        "target_observer", "trust_currentness",
    }
    if set(value) != expected_fields or value.get("schema_version") != 1 or type(value.get("schema_version")) is not int:
        raise RuntimeAttestationExternalEvidenceError("external evidence policy is invalid")
    integration = _closed(value.get("integration"), _POLICY_INTEGRATION_FIELDS, "policy integration")
    provider = _closed(value.get("provider_custody"), _POLICY_PROVIDER_FIELDS, "policy provider custody")
    release_evidence = _closed(value.get("release_evidence"), _POLICY_RELEASE_FIELDS, "policy release evidence")
    observer = _closed(value.get("target_observer"), _POLICY_OBSERVER_FIELDS, "policy target observer")
    trust = _closed(value.get("trust_currentness"), _POLICY_TRUST_FIELDS, "policy trust currentness")
    if (
        value.get("policy_kind") != "runtime_attestation_external_evidence_policy"
        or value.get("policy_status") != "unconfigured"
        or value.get("synthetic") is not True
        or value.get("production_acceptance") is not False
        or any(item is not False for item in integration.values())
        or provider.get("allowed_provider_kinds") != _PROVIDER_KINDS
        or provider.get("required_evidence") != _PROVIDER_EVIDENCE
        or provider.get("selected_provider_kind") is not None
        or provider.get("status") != "unverified"
        or release_evidence.get("artifact_names") != [item[0] for item in ARTIFACT_SPECS]
        or any(
            release_evidence.get(field) is not True
            for field in _POLICY_RELEASE_FIELDS.difference({"artifact_names"})
        )
        or observer.get("allowed_execution_locations") != _OBSERVER_LOCATIONS
        or observer.get("required_evidence") != _OBSERVER_EVIDENCE
        or observer.get("signing_domain") != "email-platform/runtime-attestation-target-observer/v1"
        or observer.get("status") != "unconfigured"
        or observer.get("workflow_signer_key_reuse_allowed") is not False
        or trust.get("status") != "unverified"
        or trust.get("host_clock_is_trusted_time") is not False
        or any(
            trust.get(field) is not True
            for field in _POLICY_TRUST_FIELDS.difference({"status", "host_clock_is_trusted_time"})
        )
    ):
        raise RuntimeAttestationExternalEvidenceError("external evidence policy overstates authority")
    return actual


def _parse_index(raw: bytes) -> dict[str, object]:
    value = _closed(_parse_canonical(raw, MAX_INDEX_BYTES, "external evidence index"), _INDEX_FIELDS, "external evidence index")
    if (
        value["schema_version"] != 1
        or type(value["schema_version"]) is not int
        or value["evidence_kind"] != INDEX_KIND
        or value["synthetic"] is not False
        or value["production_acceptance"] is not False
        or not isinstance(value["name"], str)
        or _NAME.fullmatch(value["name"]) is None
        or value["capture"] != _CAPTURE
        or value["requirements"] != _REQUIREMENTS
    ):
        raise RuntimeAttestationExternalEvidenceError("external evidence index is invalid")
    release = _closed(value["release"], _RELEASE_FIELDS, "release binding")
    for field in ("repository_id", "owner_id", "run_id"):
        if not isinstance(release[field], str) or _DECIMAL.fullmatch(release[field]) is None:
            raise RuntimeAttestationExternalEvidenceError("release binding is invalid")
    if type(release["run_attempt"]) is not int or release["run_attempt"] < 1:
        raise RuntimeAttestationExternalEvidenceError("release binding is invalid")
    if (
        not isinstance(release["repository"], str) or _REPOSITORY.fullmatch(release["repository"]) is None
        or not isinstance(release["image"], str) or _IMAGE.fullmatch(release["image"]) is None
        or not isinstance(release["commit"], str) or _COMMIT.fullmatch(release["commit"]) is None
        or not isinstance(release["digest"], str) or _DIGEST.fullmatch(release["digest"]) is None
    ):
        raise RuntimeAttestationExternalEvidenceError("release binding is invalid")
    for field in ("tag", "workflow_ref"):
        _safe_text(release[field], "release binding")
    captured_at = _safe_text(release["captured_at"], "release binding", 64)
    try:
        parsed_time = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise RuntimeAttestationExternalEvidenceError("release binding is invalid") from error
    if parsed_time.utcoffset() is None or captured_at.endswith("Z") is False:
        raise RuntimeAttestationExternalEvidenceError("release binding is invalid")
    artifacts = value["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != len(ARTIFACT_SPECS):
        raise RuntimeAttestationExternalEvidenceError("external evidence artifact inventory is invalid")
    parsed_artifacts: list[dict[str, object]] = []
    for item, (expected_name, suffix, media_type) in zip(artifacts, ARTIFACT_SPECS, strict=True):
        record = _closed(item, _ARTIFACT_FIELDS, "external evidence artifact")
        expected_path = f"{value['name']}.{suffix}"
        if (
            record["name"] != expected_name
            or record["path"] != expected_path
            or record["media_type"] != media_type
            or type(record["size_bytes"]) is not int
            or record["size_bytes"] < 1
            or record["size_bytes"] > MAX_ARTIFACT_BYTES
        ):
            raise RuntimeAttestationExternalEvidenceError("external evidence artifact inventory is invalid")
        _digest(record["sha256"], "artifact digest")
        parsed_artifacts.append(record)
    value["release"] = release
    value["artifacts"] = parsed_artifacts
    return value


def _json_document(raw: bytes, label: str) -> object:
    try:
        return parse_unique_json_bytes(raw)
    except (TypeError, ValueError) as error:
        raise RuntimeAttestationExternalEvidenceError(f"{label} is invalid") from error


def _verify_cosign_payload(raw: bytes, *, image: str, digest: str) -> None:
    value = _json_document(raw, "Cosign payload")
    if not isinstance(value, Mapping):
        raise RuntimeAttestationExternalEvidenceError("Cosign payload is invalid")
    critical = value.get("critical")
    if not isinstance(critical, Mapping):
        raise RuntimeAttestationExternalEvidenceError("Cosign payload is invalid")
    identity = critical.get("identity")
    image_record = critical.get("image")
    if (
        not isinstance(identity, Mapping)
        or identity.get("docker-reference") != image
        or not isinstance(image_record, Mapping)
        or image_record.get("docker-manifest-digest") != digest
    ):
        raise RuntimeAttestationExternalEvidenceError("Cosign payload subject drifted")


def _verify_github_bundle(raw: bytes, *, image: str, digest: str) -> None:
    matched = False
    try:
        document = _json_document(raw, "GitHub bundle")
    except RuntimeAttestationExternalEvidenceError:
        lines = raw.splitlines()
        if not lines or any(not line for line in lines):
            raise RuntimeAttestationExternalEvidenceError("GitHub bundle is invalid")
        documents = [_json_document(line, "GitHub bundle") for line in lines]
    else:
        documents = [document]
    for bundle in documents:
        if not isinstance(bundle, Mapping):
            raise RuntimeAttestationExternalEvidenceError("GitHub bundle is invalid")
        envelope = bundle.get("dsseEnvelope")
        if not isinstance(envelope, Mapping) or not isinstance(envelope.get("payload"), str):
            continue
        try:
            statement_raw = base64.b64decode(envelope["payload"], validate=True)
        except (binascii.Error, ValueError) as error:
            raise RuntimeAttestationExternalEvidenceError("GitHub bundle is invalid") from error
        statement = _json_document(statement_raw, "GitHub statement")
        if not isinstance(statement, Mapping) or statement.get("_type") != "https://in-toto.io/Statement/v1":
            continue
        subjects = statement.get("subject")
        if not isinstance(subjects, list):
            continue
        for subject in subjects:
            if not isinstance(subject, Mapping) or subject.get("name") != image:
                continue
            digests = subject.get("digest")
            if isinstance(digests, Mapping) and digests.get("sha256") == digest.removeprefix("sha256:"):
                matched = True
    if not matched:
        raise RuntimeAttestationExternalEvidenceError("GitHub provenance subject drifted")


def _verify_trusted_root_jsonl(raw: bytes) -> None:
    lines = raw.splitlines()
    if not lines:
        raise RuntimeAttestationExternalEvidenceError("trusted root is invalid")
    for line in lines:
        if not line or not isinstance(_json_document(line, "trusted root"), Mapping):
            raise RuntimeAttestationExternalEvidenceError("trusted root is invalid")


def _verify_digest_record(raw: bytes, label: str) -> None:
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise RuntimeAttestationExternalEvidenceError(f"{label} is invalid") from error
    token = text.split(maxsplit=1)[0] if text else ""
    if _SHA256.fullmatch(token) is None:
        raise RuntimeAttestationExternalEvidenceError(f"{label} is invalid")


def verify_external_evidence(
    manifest_path: Path | str,
    evidence_root: Path | str,
    *,
    expected_manifest_sha256: str,
    expected_policy_sha256: str,
) -> VerifiedExternalEvidence:
    root = _external_root(evidence_root)
    manifest = Path(manifest_path)
    if not manifest.is_absolute() or manifest.parent.resolve(strict=True) != root:
        raise RuntimeAttestationExternalEvidenceError("external evidence manifest is invalid")
    policy_blob = _stable(POLICY, MAX_INDEX_BYTES)
    policy_sha = verify_policy_bytes(policy_blob.raw, expected_sha256=expected_policy_sha256)
    manifest_blob = _stable(manifest, MAX_INDEX_BYTES)
    expected_manifest = _digest(expected_manifest_sha256, "manifest pin")
    if not hmac.compare_digest(manifest_blob.sha256, expected_manifest):
        raise RuntimeAttestationExternalEvidenceError("manifest pin drifted")
    index = _parse_index(manifest_blob.raw)
    blobs: dict[str, StableInput] = {}
    identities = {(manifest_blob.identity.device, manifest_blob.identity.inode)}
    for record in index["artifacts"]:
        path = root / str(record["path"])
        if path.parent != root:
            raise RuntimeAttestationExternalEvidenceError("external evidence artifact path is invalid")
        blob = _stable(path, MAX_ARTIFACT_BYTES)
        identity = (blob.identity.device, blob.identity.inode)
        if identity in identities:
            raise RuntimeAttestationExternalEvidenceError("external evidence files alias each other")
        identities.add(identity)
        if blob.sha256 != record["sha256"] or len(blob.raw) != record["size_bytes"]:
            raise RuntimeAttestationExternalEvidenceError("external evidence artifact pin drifted")
        blobs[str(record["name"])] = blob
    release = index["release"]
    digest = str(release["digest"])
    image = str(release["image"])
    if hashlib.sha256(blobs["oci_manifest"].raw).hexdigest() != digest.removeprefix("sha256:"):
        raise RuntimeAttestationExternalEvidenceError("OCI manifest digest drifted")
    _verify_cosign_payload(blobs["cosign_payload"].raw, image=image, digest=digest)
    _verify_github_bundle(blobs["github_bundle"].raw, image=image, digest=digest)
    _verify_trusted_root_jsonl(blobs["github_sigstore_trusted_root"].raw)
    _verify_digest_record(blobs["cosign_executable_digest"].raw, "Cosign executable digest")
    _verify_digest_record(blobs["github_executable_digest"].raw, "GitHub executable digest")
    for name in (
        "cosign_bundle", "tuf_verify_result", "cosign_version", "cosign_bundle_verify_result", "cosign_verify_result",
        "cosign_verify_attestation_result", "github_version", "github_verify_result",
    ):
        if not blobs[name].raw.strip():
            raise RuntimeAttestationExternalEvidenceError("external evidence artifact is empty")
    for name in (
        "cosign_bundle", "cosign_version", "cosign_verify_result",
        "cosign_verify_attestation_result", "github_verify_result",
    ):
        _json_document(blobs[name].raw, name)
    for blob in [policy_blob, manifest_blob, *blobs.values()]:
        _unchanged(blob)
    return VerifiedExternalEvidence(
        manifest_sha256=manifest_blob.sha256,
        policy_sha256=policy_sha,
        name=str(index["name"]),
        image=image,
        digest=digest,
        commit=str(release["commit"]),
        repository=str(release["repository"]),
        repository_id=str(release["repository_id"]),
        owner_id=str(release["owner_id"]),
        tag=str(release["tag"]),
        workflow_ref=str(release["workflow_ref"]),
        run_id=str(release["run_id"]),
        run_attempt=int(release["run_attempt"]),
        artifact_sha256=tuple((name, blobs[name].sha256) for name, _, _ in ARTIFACT_SPECS),
        exact_subject_bindings_verified=True,
    )


def verify_repository_policy() -> str:
    raw = POLICY.read_bytes()
    digest = verify_policy_bytes(raw, expected_sha256=EXPECTED_POLICY_SHA256)
    return (
        "runtime-attestation-external-policy-ok status=unconfigured "
        "external-index=caller-pinned target-observer=unconfigured "
        "trust-currentness=unverified provider-native-cas=unverified "
        f"production_acceptance=false policy_sha256={digest}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify T207 external runtime-attestation evidence.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("verify-repository")
    verify = sub.add_parser("verify")
    verify.add_argument("--manifest", required=True)
    verify.add_argument("--evidence-root", required=True)
    verify.add_argument("--expected-manifest-sha256", required=True)
    verify.add_argument("--expected-policy-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-repository":
            print(verify_repository_policy())
        else:
            result = verify_external_evidence(
                args.manifest,
                args.evidence_root,
                expected_manifest_sha256=args.expected_manifest_sha256,
                expected_policy_sha256=args.expected_policy_sha256,
            )
            print(
                "runtime-attestation-external-evidence-ok "
                "raw-artifacts=caller-pinned subject-bindings=verified "
                "trust-currentness=unverified revocation-freshness=unverified "
                "target-observer=unverified trusted-time=unverified "
                "provider-native-cas=unverified original-execution=unverified "
                "runtime-authority=unverified production_acceptance=false "
                f"manifest_sha256={result.manifest_sha256}"
            )
    except (OSError, RuntimeAttestationExternalEvidenceError) as error:
        print(f"runtime-attestation-external-evidence-error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
