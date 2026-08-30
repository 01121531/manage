"""Verify one caller-pinned T208 handoff for all release container evidence.

The handoff is authored and pinned outside the repository.  This verifier is
offline and read-only: it proves three T207 indexes describe one release, but
does not create an independent pin or promote workflow evidence to runtime
authority.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
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
    from scripts.target_intake_runtime_attestation_external_evidence import (
        EXPECTED_POLICY_SHA256,
        ROOT,
        RuntimeAttestationExternalEvidenceError,
        VerifiedExternalEvidence,
        verify_external_evidence,
    )
except ModuleNotFoundError:
    from external_json import (
        StableFileError,
        StableFileIdentity,
        parse_unique_json_bytes,
        read_stable_bytes_with_metadata,
        stable_file_identity,
    )
    from target_intake_runtime_attestation_external_evidence import (
        EXPECTED_POLICY_SHA256,
        ROOT,
        RuntimeAttestationExternalEvidenceError,
        VerifiedExternalEvidence,
        verify_external_evidence,
    )


HANDOFF_KIND = "runtime_attestation_release_handoff_v1"
MAX_HANDOFF_BYTES = 131_072
EXPECTED_NAMES = ("api", "web", "edge")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_DECIMAL = re.compile(r"[1-9][0-9]*")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?")
_TOP_FIELDS = {
    "evidence", "evidence_kind", "production_acceptance", "release",
    "requirements", "schema_version", "synthetic",
}
_RELEASE_FIELDS = {
    "commit", "owner_id", "repository", "repository_id", "run_attempt",
    "run_id", "tag", "workflow_ref",
}
_EVIDENCE_FIELDS = {"manifest_path", "manifest_sha256", "name"}
_REQUIREMENTS = {
    "handoff_manifest_pin": "caller_supplied",
    "index_pins": "independently_retained",
    "original_execution": "unverified",
    "provider_custody": "unverified",
    "provider_native_cas": "unverified",
    "runtime_authority": "unverified",
    "target_observer": "unverified",
    "trust_currentness": "unverified",
    "trusted_time": "unverified",
}


class RuntimeAttestationReleaseHandoffError(ValueError):
    pass


@dataclass(frozen=True)
class StableHandoffInput:
    path: Path
    raw: bytes
    identity: StableFileIdentity
    sha256: str


@dataclass(frozen=True)
class VerifiedReleaseHandoff:
    handoff_sha256: str
    policy_sha256: str
    repository: str
    tag: str
    commit: str
    run_id: str
    run_attempt: int
    images: tuple[tuple[str, str, str, str], ...]
    cross_image_release_binding_verified: bool = True
    original_execution_verified: bool = False
    runtime_authority_verified: bool = False
    production_acceptance: bool = False


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def _closed(value: object, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise RuntimeAttestationReleaseHandoffError(f"{label} is invalid")
    return dict(value)


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise RuntimeAttestationReleaseHandoffError(f"{label} is invalid")
    return value


def _external_root(value: Path | str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise RuntimeAttestationReleaseHandoffError("external evidence root is invalid")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(ROOT.resolve(strict=True))
    except ValueError:
        return resolved
    except OSError as error:
        raise RuntimeAttestationReleaseHandoffError("external evidence root is invalid") from error
    raise RuntimeAttestationReleaseHandoffError("external evidence root is invalid")


def _stable(path: Path, *, expected_identity: StableFileIdentity | None = None) -> StableHandoffInput:
    try:
        raw, metadata = read_stable_bytes_with_metadata(
            path,
            max_bytes=MAX_HANDOFF_BYTES,
            expected_identity=expected_identity,
        )
    except (OSError, StableFileError, ValueError) as error:
        raise RuntimeAttestationReleaseHandoffError("release handoff cannot be read safely") from error
    if metadata.st_nlink != 1:
        raise RuntimeAttestationReleaseHandoffError("release handoff cannot be read safely")
    return StableHandoffInput(
        path=path,
        raw=raw,
        identity=stable_file_identity(metadata),
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _parse_handoff(raw: bytes) -> tuple[dict[str, object], list[dict[str, object]]]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_HANDOFF_BYTES:
        raise RuntimeAttestationReleaseHandoffError("release handoff is invalid")
    try:
        document = parse_unique_json_bytes(raw)
    except (TypeError, ValueError) as error:
        raise RuntimeAttestationReleaseHandoffError("release handoff is invalid") from error
    if not isinstance(document, Mapping) or raw not in (
        _canonical_bytes(document),
        _canonical_bytes(document).removesuffix(b"\n"),
    ):
        raise RuntimeAttestationReleaseHandoffError("release handoff is invalid")
    value = _closed(document, _TOP_FIELDS, "release handoff")
    if (
        value["schema_version"] != 1
        or type(value["schema_version"]) is not int
        or value["evidence_kind"] != HANDOFF_KIND
        or value["synthetic"] is not False
        or value["production_acceptance"] is not False
        or value["requirements"] != _REQUIREMENTS
    ):
        raise RuntimeAttestationReleaseHandoffError("release handoff overstates authority")
    release = _closed(value["release"], _RELEASE_FIELDS, "release binding")
    if (
        not isinstance(release["repository"], str)
        or _REPOSITORY.fullmatch(release["repository"]) is None
        or not isinstance(release["commit"], str)
        or _COMMIT.fullmatch(release["commit"]) is None
        or not isinstance(release["tag"], str)
        or _TAG.fullmatch(release["tag"]) is None
        or type(release["run_attempt"]) is not int
        or release["run_attempt"] < 1
    ):
        raise RuntimeAttestationReleaseHandoffError("release binding is invalid")
    for field in ("repository_id", "owner_id", "run_id"):
        if not isinstance(release[field], str) or _DECIMAL.fullmatch(release[field]) is None:
            raise RuntimeAttestationReleaseHandoffError("release binding is invalid")
    expected_workflow = (
        f"{release['repository']}/.github/workflows/release.yml@refs/tags/{release['tag']}"
    )
    if release["workflow_ref"] != expected_workflow:
        raise RuntimeAttestationReleaseHandoffError("release binding is invalid")
    evidence = value["evidence"]
    if not isinstance(evidence, list) or len(evidence) != len(EXPECTED_NAMES):
        raise RuntimeAttestationReleaseHandoffError("release evidence inventory is invalid")
    records: list[dict[str, object]] = []
    for item, name in zip(evidence, EXPECTED_NAMES, strict=True):
        record = _closed(item, _EVIDENCE_FIELDS, "release evidence record")
        if (
            record["name"] != name
            or record["manifest_path"]
            != f"{name}.runtime-attestation.external-evidence-index.json"
        ):
            raise RuntimeAttestationReleaseHandoffError("release evidence inventory is invalid")
        _digest(record["manifest_sha256"], "release evidence index pin")
        records.append(record)
    return release, records


def _matches_release(
    result: VerifiedExternalEvidence,
    release: Mapping[str, object],
    name: str,
) -> bool:
    expected_image = f"ghcr.io/{str(release['repository']).lower()}-{name}"
    return (
        result.name == name
        and result.image == expected_image
        and result.repository == release["repository"]
        and result.repository_id == release["repository_id"]
        and result.owner_id == release["owner_id"]
        and result.tag == release["tag"]
        and result.commit == release["commit"]
        and result.workflow_ref == release["workflow_ref"]
        and result.run_id == release["run_id"]
        and result.run_attempt == release["run_attempt"]
    )


def verify_release_handoff(
    handoff_path: Path | str,
    evidence_root: Path | str,
    *,
    expected_handoff_sha256: str,
    expected_policy_sha256: str,
) -> VerifiedReleaseHandoff:
    expected_handoff = _digest(expected_handoff_sha256, "release handoff pin")
    expected_policy = _digest(expected_policy_sha256, "policy pin")
    root = _external_root(evidence_root)
    path = Path(handoff_path)
    if not path.is_absolute() or path.parent.resolve(strict=True) != root:
        raise RuntimeAttestationReleaseHandoffError("release handoff path is invalid")
    handoff = _stable(path)
    if not hmac.compare_digest(handoff.sha256, expected_handoff):
        raise RuntimeAttestationReleaseHandoffError("release handoff pin drifted")
    release, records = _parse_handoff(handoff.raw)
    handoff_identity = (handoff.identity.device, handoff.identity.inode)
    results: list[VerifiedExternalEvidence] = []
    for record in records:
        manifest = root / str(record["manifest_path"])
        manifest_input = _stable(manifest)
        if (manifest_input.identity.device, manifest_input.identity.inode) == handoff_identity:
            raise RuntimeAttestationReleaseHandoffError("release handoff files alias each other")
        if not hmac.compare_digest(manifest_input.sha256, str(record["manifest_sha256"])):
            raise RuntimeAttestationReleaseHandoffError("release evidence index pin drifted")
        try:
            result = verify_external_evidence(
                manifest,
                root,
                expected_manifest_sha256=str(record["manifest_sha256"]),
                expected_policy_sha256=expected_policy,
            )
        except RuntimeAttestationExternalEvidenceError as error:
            raise RuntimeAttestationReleaseHandoffError(
                "release evidence index verification failed"
            ) from error
        if not _matches_release(result, release, str(record["name"])):
            raise RuntimeAttestationReleaseHandoffError("cross-image release binding drifted")
        results.append(result)
    rechecked = _stable(path, expected_identity=handoff.identity)
    if not hmac.compare_digest(rechecked.sha256, handoff.sha256):
        raise RuntimeAttestationReleaseHandoffError("release handoff changed during verification")
    return VerifiedReleaseHandoff(
        handoff_sha256=handoff.sha256,
        policy_sha256=expected_policy,
        repository=str(release["repository"]),
        tag=str(release["tag"]),
        commit=str(release["commit"]),
        run_id=str(release["run_id"]),
        run_attempt=int(release["run_attempt"]),
        images=tuple(
            (result.name, result.image, result.digest, result.manifest_sha256)
            for result in results
        ),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a caller-pinned three-image runtime-attestation release handoff."
    )
    parser.add_argument("--handoff-manifest", required=True)
    parser.add_argument("--evidence-root", required=True)
    parser.add_argument("--expected-handoff-sha256", required=True)
    parser.add_argument("--expected-policy-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_release_handoff(
            args.handoff_manifest,
            args.evidence_root,
            expected_handoff_sha256=args.expected_handoff_sha256,
            expected_policy_sha256=args.expected_policy_sha256,
        )
    except (OSError, RuntimeAttestationReleaseHandoffError) as error:
        print(f"runtime-attestation-release-handoff-error: {error}", file=sys.stderr)
        return 1
    print(
        "runtime-attestation-release-handoff-ok images=api,web,edge "
        "index-pins=independently-retained cross-image-release-binding=verified "
        "target-observer=unverified trusted-time=unverified provider-native-cas=unverified "
        "original-execution=unverified runtime-authority=unverified "
        "production_acceptance=false "
        f"handoff_sha256={result.handoff_sha256}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
