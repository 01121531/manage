"""Merge and verify immutable container release evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Sequence


EXPECTED_IMAGES = ("api", "web", "edge")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_IMAGE = re.compile(r"^ghcr\.io/[a-z0-9._/-]+$")


def _load_mapping(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"metadata must contain an object: {path.name}")
    return value


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
            sbom_bytes = sbom_path.read_bytes()
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
            scan_bytes = scan_path.read_bytes()
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
    return {"schema_version": 1, "tag": tag, "commit": commit, "images": images}


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
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
