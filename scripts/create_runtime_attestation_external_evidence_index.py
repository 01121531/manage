"""Create the T207 release evidence index from already captured raw files."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys

try:
    from scripts.target_intake_runtime_attestation_external_evidence import (
        ARTIFACT_SPECS,
        INDEX_KIND,
        MAX_ARTIFACT_BYTES,
    )
except ModuleNotFoundError:
    from target_intake_runtime_attestation_external_evidence import (
        ARTIFACT_SPECS,
        INDEX_KIND,
        MAX_ARTIFACT_BYTES,
    )


_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")


class ExternalEvidenceIndexError(ValueError):
    pass


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def _text(value: str, label: str, maximum: int = 512) -> str:
    if not value or len(value) > maximum or any(ord(ch) < 32 for ch in value):
        raise ExternalEvidenceIndexError(f"{label} is invalid")
    return value


def create_index(args: argparse.Namespace) -> bytes:
    evidence_dir = Path(args.evidence_dir).resolve(strict=True)
    output = Path(args.output).resolve(strict=False)
    if output.parent != evidence_dir or output.exists():
        raise ExternalEvidenceIndexError("output must be a new direct child of the evidence directory")
    if _NAME.fullmatch(args.name) is None or _SHA256.fullmatch(args.digest) is None or _COMMIT.fullmatch(args.commit) is None:
        raise ExternalEvidenceIndexError("release identity is invalid")
    try:
        captured = datetime.fromisoformat(args.captured_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise ExternalEvidenceIndexError("captured-at is invalid") from error
    if captured.utcoffset() is None or not args.captured_at.endswith("Z"):
        raise ExternalEvidenceIndexError("captured-at is invalid")
    artifacts: list[dict[str, object]] = []
    for name, suffix, media_type in ARTIFACT_SPECS:
        filename = f"{args.name}.{suffix}"
        path = evidence_dir / filename
        raw = path.read_bytes()
        if not raw or len(raw) > MAX_ARTIFACT_BYTES or path.is_symlink():
            raise ExternalEvidenceIndexError(f"captured artifact {name} is invalid")
        artifacts.append({
            "media_type": media_type,
            "name": name,
            "path": filename,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
        })
    value = {
        "artifacts": artifacts,
        "capture": {
            "bundle_bytes_preserved": True,
            "cli_outputs_preserved": True,
            "host_clock_trusted": False,
            "oci_manifest_digest_verified": True,
            "provider_mutation_performed": False,
            "target_observation_performed": False,
            "trusted_root_method": "gh_attestation_trusted_root_tuf",
        },
        "evidence_kind": INDEX_KIND,
        "name": args.name,
        "production_acceptance": False,
        "release": {
            "captured_at": args.captured_at,
            "commit": args.commit,
            "digest": args.digest,
            "image": _text(args.image, "image"),
            "owner_id": _text(args.owner_id, "owner-id", 32),
            "repository": _text(args.repository, "repository"),
            "repository_id": _text(args.repository_id, "repository-id", 32),
            "run_attempt": args.run_attempt,
            "run_id": _text(args.run_id, "run-id", 32),
            "tag": _text(args.tag, "tag"),
            "workflow_ref": _text(args.workflow_ref, "workflow-ref"),
        },
        "requirements": {
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
        },
        "schema_version": 1,
        "synthetic": False,
    }
    return _canonical_bytes(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create a T207 external release evidence index.")
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--owner-id", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True, type=int)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--captured-at", required=True)
    args = parser.parse_args(argv)
    try:
        raw = create_index(args)
        with Path(args.output).open("xb") as stream:
            stream.write(raw)
    except (OSError, ExternalEvidenceIndexError) as error:
        print(f"runtime-attestation-external-index-error: {error}", file=sys.stderr)
        return 1
    print(f"runtime-attestation-external-index-created sha256={hashlib.sha256(raw).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
