"""Merge and verify immutable container release evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Sequence

try:
    from scripts.external_json import (
        load_unique_json,
        load_unique_json_with_bytes,
        read_stable_bytes,
        write_atomic_bytes,
    )
except ModuleNotFoundError:  # pragma: no cover - standalone script execution
    from external_json import (
        load_unique_json,
        load_unique_json_with_bytes,
        read_stable_bytes,
        write_atomic_bytes,
    )


EXPECTED_IMAGES = ("api", "web", "edge")
MAX_CONTAINER_METADATA_BYTES = 64 * 1024
MAX_CONTAINER_EVIDENCE_BYTES = 32 * 1024 * 1024
ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "platform" / "migrations" / "versions"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_IMAGE = re.compile(
    r"^ghcr\.io/[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?/"
    r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?-(?:api|web|edge)$"
)
_MIGRATION_HEAD = re.compile(r"^[0-9]{4}_[a-z0-9_]+$")
_ATTESTATIONS = ["cosign-spdxjson", "github-build-provenance"]


def _load_mapping(path: Path) -> dict[str, Any]:
    value = load_unique_json(path, max_bytes=MAX_CONTAINER_METADATA_BYTES)
    if not isinstance(value, dict):
        raise ValueError(f"metadata must contain an object: {path.name}")
    return value


def _current_migration_head() -> str:
    candidates = sorted(
        path.stem for path in MIGRATIONS.glob("[0-9][0-9][0-9][0-9]_*.py")
    )
    if not candidates:
        raise ValueError("no migration head was found")
    return candidates[-1]


def _require_exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    if set(value) != expected:
        raise ValueError(f"invalid {context} fields")


def verify_manifest(
    manifest: dict[str, Any],
    *,
    expected_tag: str | None = None,
    expected_commit: str | None = None,
    expected_migration_head: str | None = None,
) -> dict[str, Any]:
    """Validate claimed release metadata; this is not cryptographic verification."""

    if not isinstance(manifest, dict):
        raise ValueError("container release manifest must contain an object")
    _require_exact_keys(
        manifest,
        {"schema_version", "tag", "commit", "migration_head", "images"},
        "manifest",
    )
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise ValueError("unsupported container release manifest schema")

    tag = manifest["tag"]
    commit = manifest["commit"]
    migration_head = manifest["migration_head"]
    if not isinstance(tag, str) or not _TAG.fullmatch(tag):
        raise ValueError("invalid release tag")
    if not isinstance(commit, str) or not _COMMIT.fullmatch(commit):
        raise ValueError("invalid release commit")
    if not isinstance(migration_head, str) or not _MIGRATION_HEAD.fullmatch(migration_head):
        raise ValueError("invalid migration head")
    if expected_tag is not None and tag != expected_tag:
        raise ValueError("release tag does not match expected tag")
    if expected_commit is not None and commit != expected_commit:
        raise ValueError("release commit does not match expected commit")
    if expected_migration_head is not None and migration_head != expected_migration_head:
        raise ValueError("migration head does not match expected head")

    images = manifest["images"]
    if not isinstance(images, dict) or set(images) != set(EXPECTED_IMAGES):
        raise ValueError("manifest must contain exactly api, web, and edge images")
    expected_identity_suffix = f"/.github/workflows/release.yml@refs/tags/{tag}"
    identity_pattern = re.compile(
        r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
        + re.escape(expected_identity_suffix)
        + r"$"
    )
    for name in EXPECTED_IMAGES:
        image_metadata = images[name]
        if not isinstance(image_metadata, dict):
            raise ValueError(f"invalid image metadata: {name}")
        _require_exact_keys(
            image_metadata,
            {"image", "digest", "sbom", "scan", "signature", "attestations"},
            f"image metadata: {name}",
        )
        image = image_metadata["image"]
        digest = image_metadata["digest"]
        if (
            not isinstance(image, str)
            or not _IMAGE.fullmatch(image)
            or not image.endswith(f"-{name}")
        ):
            raise ValueError(f"invalid GHCR image name: {name}")
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise ValueError(f"invalid OCI digest: {name}")

        sbom = image_metadata["sbom"]
        if not isinstance(sbom, dict):
            raise ValueError(f"invalid SBOM metadata: {name}")
        _require_exact_keys(sbom, {"file", "sha256"}, f"SBOM metadata: {name}")
        if (
            sbom["file"] != f"{name}.spdx.json"
            or not isinstance(sbom["sha256"], str)
            or not _SHA256.fullmatch(sbom["sha256"])
        ):
            raise ValueError(f"invalid SBOM metadata: {name}")

        scan = image_metadata["scan"]
        if not isinstance(scan, dict):
            raise ValueError(f"invalid Trivy scan metadata: {name}")
        _require_exact_keys(
            scan,
            {"tool", "severities", "result", "file", "sha256"},
            f"Trivy scan metadata: {name}",
        )
        if (
            scan["tool"] != "trivy"
            or scan["severities"] != ["HIGH", "CRITICAL"]
            or scan["result"] != "passed"
            or scan["file"] != f"{name}.trivy.sarif"
            or not isinstance(scan["sha256"], str)
            or not _SHA256.fullmatch(scan["sha256"])
        ):
            raise ValueError(f"invalid Trivy scan metadata: {name}")

        signature = image_metadata["signature"]
        if not isinstance(signature, dict):
            raise ValueError(f"invalid signature identity: {name}")
        _require_exact_keys(signature, {"issuer", "identity"}, f"signature metadata: {name}")
        identity = signature["identity"]
        if signature["issuer"] != "https://token.actions.githubusercontent.com":
            raise ValueError(f"invalid signature issuer: {name}")
        if not isinstance(identity, str) or not identity_pattern.fullmatch(identity):
            raise ValueError(f"invalid signature identity: {name}")
        if image_metadata["attestations"] != _ATTESTATIONS:
            raise ValueError(f"required attestations are missing: {name}")
    return manifest


def load_manifest(
    path: Path,
    *,
    expected_tag: str | None = None,
    expected_commit: str | None = None,
    expected_migration_head: str | None = None,
    _include_manifest_sha256: bool = False,
) -> dict[str, Any] | tuple[dict[str, Any], str]:
    """Load and strictly pre-validate a container release manifest."""

    value, raw = load_unique_json_with_bytes(
        path,
        max_bytes=MAX_CONTAINER_METADATA_BYTES,
    )
    if not isinstance(value, dict):
        raise ValueError(f"metadata must contain an object: {path.name}")
    manifest = verify_manifest(
        value,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
        expected_migration_head=expected_migration_head,
    )
    if _include_manifest_sha256:
        return manifest, hashlib.sha256(raw).hexdigest()
    return manifest


def build_manifest(input_dir: Path, *, tag: str, commit: str) -> dict[str, Any]:
    if not _TAG.fullmatch(tag):
        raise ValueError("release tag must be vMAJOR.MINOR.PATCH")
    if not _COMMIT.fullmatch(commit):
        raise ValueError("release commit must be a lowercase 40-character SHA")
    metadata_paths = sorted(input_dir.glob("*.metadata.json"))
    expected_files = {f"{name}.metadata.json" for name in EXPECTED_IMAGES}
    if {path.name for path in metadata_paths} != expected_files:
        raise ValueError("container evidence must contain exactly api, web, and edge metadata")

    images: dict[str, Any] = {}
    for name in EXPECTED_IMAGES:
        metadata = _load_mapping(input_dir / f"{name}.metadata.json")
        if metadata.get("schema_version") != 1 or metadata.get("name") != name:
            raise ValueError(f"invalid metadata identity: {name}")
        if metadata.get("tag") != tag or metadata.get("commit") != commit:
            raise ValueError(f"release tag or commit mismatch: {name}")
        image = metadata.get("image")
        digest = metadata.get("digest")
        if not isinstance(image, str) or not _IMAGE.fullmatch(image) or not image.endswith(f"-{name}"):
            raise ValueError(f"invalid GHCR image name: {name}")
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise ValueError(f"invalid OCI digest: {name}")

        sbom = metadata.get("sbom")
        if not isinstance(sbom, dict):
            raise ValueError(f"missing SBOM metadata: {name}")
        sbom_file = sbom.get("file")
        sbom_sha256 = sbom.get("sha256")
        if sbom_file != f"{name}.spdx.json" or not isinstance(sbom_sha256, str) or not _SHA256.fullmatch(sbom_sha256):
            raise ValueError(f"invalid SBOM metadata: {name}")
        sbom_path = input_dir / sbom_file
        try:
            sbom_bytes = read_stable_bytes(
                sbom_path,
                max_bytes=MAX_CONTAINER_EVIDENCE_BYTES,
            )
        except OSError as error:
            raise ValueError(f"missing SBOM artifact: {name}") from error
        if hashlib.sha256(sbom_bytes).hexdigest() != sbom_sha256:
            raise ValueError(f"SBOM hash mismatch: {name}")

        scan = metadata.get("scan")
        if not isinstance(scan, dict):
            raise ValueError(f"missing Trivy scan metadata: {name}")
        scan_file = scan.get("file")
        scan_sha256 = scan.get("sha256")
        if (
            scan.get("tool") != "trivy"
            or set(scan.get("severities", [])) != {"HIGH", "CRITICAL"}
            or scan.get("result") != "passed"
            or scan_file != f"{name}.trivy.sarif"
            or not isinstance(scan_sha256, str)
            or not _SHA256.fullmatch(scan_sha256)
        ):
            raise ValueError(f"invalid Trivy scan metadata: {name}")
        scan_path = input_dir / scan_file
        try:
            scan_bytes = read_stable_bytes(
                scan_path,
                max_bytes=MAX_CONTAINER_EVIDENCE_BYTES,
            )
        except OSError as error:
            raise ValueError(f"missing Trivy scan artifact: {name}") from error
        if hashlib.sha256(scan_bytes).hexdigest() != scan_sha256:
            raise ValueError(f"Trivy scan hash mismatch: {name}")

        signature = metadata.get("signature")
        if not isinstance(signature, dict):
            raise ValueError(f"missing signature identity: {name}")
        if signature.get("issuer") != "https://token.actions.githubusercontent.com":
            raise ValueError(f"invalid signature issuer: {name}")
        identity = signature.get("identity")
        expected_suffix = f"/.github/workflows/release.yml@refs/tags/{tag}"
        if not isinstance(identity, str) or not identity.startswith("https://github.com/") or not identity.endswith(expected_suffix):
            raise ValueError(f"invalid signature identity: {name}")
        if set(metadata.get("attestations", [])) != {
            "cosign-spdxjson",
            "github-build-provenance",
        }:
            raise ValueError(f"required attestations are missing: {name}")

        images[name] = {
            "image": image,
            "digest": digest,
            "sbom": {"file": sbom_file, "sha256": sbom_sha256},
            "scan": dict(scan),
            "signature": dict(signature),
            "attestations": sorted(metadata["attestations"]),
        }
    return verify_manifest(
        {
            "schema_version": 1,
            "tag": tag,
            "commit": commit,
            "migration_head": _current_migration_head(),
            "images": images,
        },
        expected_tag=tag,
        expected_commit=commit,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create a verified container release manifest.")
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest = build_manifest(Path(args.input_dir), tag=args.tag, commit=args.commit)
    output = Path(args.output)
    write_atomic_bytes(
        output,
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
