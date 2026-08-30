"""Structurally verify fail-closed container build, scan, and release gates."""

from __future__ import annotations

from pathlib import Path
import re
import sys
from typing import Any

import yaml

try:
    from scripts.external_text import load_stable_text
    from scripts.external_yaml import load_unique_yaml
except ModuleNotFoundError:  # Direct `python scripts/...` execution.
    from external_text import load_stable_text  # type: ignore[no-redef]
    from external_yaml import load_unique_yaml  # type: ignore[no-redef]


ROOT = Path(__file__).resolve().parents[1]
SECURITY = ROOT / ".github" / "workflows" / "security.yml"
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
DOCKERFILES = (
    ROOT / "infra" / "Dockerfile",
    ROOT / "infra" / "frontend.Dockerfile",
    ROOT / "infra" / "edge.Dockerfile",
)
EXPECTED_MATRIX = {
    ("api", "infra/Dockerfile"),
    ("web", "infra/frontend.Dockerfile"),
    ("edge", "infra/edge.Dockerfile"),
}
_PINNED_ACTION = re.compile(r"^[^\s/@]+/[^\s@]+@[0-9a-f]{40}$")
_PINNED_BASE = re.compile(r"^FROM\s+\S+@sha256:[0-9a-f]{64}(?:\s+AS\s+\S+)?$", re.IGNORECASE)


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _load(path: Path) -> dict[str, Any]:
    value = load_unique_yaml(path)
    if not isinstance(value, dict):
        raise ValueError(f"workflow must contain a mapping: {path.name}")
    return value


def load_workflows() -> tuple[dict[str, Any], dict[str, Any]]:
    return _load(SECURITY), _load(RELEASE)


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    return [step for raw in _list(job.get("steps")) if (step := _mapping(raw))]


def _step(job: dict[str, Any], name: str) -> dict[str, Any]:
    return next((step for step in _steps(job) if step.get("name") == name), {})


def _step_index(job: dict[str, Any], name: str) -> int:
    return next((index for index, step in enumerate(_steps(job)) if step.get("name") == name), -1)


def _matrix(job: dict[str, Any]) -> set[tuple[str, str]]:
    include = _list(_mapping(_mapping(job.get("strategy")).get("matrix")).get("include"))
    return {
        (str(entry.get("name")), str(entry.get("dockerfile")))
        for raw in include
        if (entry := _mapping(raw))
    }


def _trivy_errors(step: dict[str, Any], *, label: str) -> list[str]:
    errors: list[str] = []
    settings = _mapping(step.get("with"))
    if str(settings.get("exit-code")) != "1":
        errors.append(f"{label} Trivy must fail with exit-code 1")
    severities = {item.strip() for item in str(settings.get("severity", "")).split(",")}
    if severities != {"HIGH", "CRITICAL"}:
        errors.append(f"{label} Trivy must gate exactly HIGH and CRITICAL")
    if settings.get("ignore-unfixed") not in (False, "false"):
        errors.append(f"{label} Trivy must not ignore unfixed vulnerabilities")
    if "continue-on-error" in step and step["continue-on-error"] is not False:
        errors.append(f"{label} Trivy must not continue on error")
    return errors


def validate_supply_chain(
    security: dict[str, Any],
    release: dict[str, Any],
    dockerfile_texts: tuple[str, ...],
) -> list[str]:
    errors: list[str] = []
    for label, workflow in (("security", security), ("release", release)):
        for job_name, raw_job in _mapping(workflow.get("jobs")).items():
            for step in _steps(_mapping(raw_job)):
                uses = step.get("uses")
                if isinstance(uses, str) and not _PINNED_ACTION.fullmatch(uses):
                    errors.append(f"{label}/{job_name} action is not commit-pinned: {uses}")

    security_jobs = _mapping(security.get("jobs"))
    security_container = _mapping(security_jobs.get("container-supply-chain"))
    if _matrix(security_container) != EXPECTED_MATRIX:
        errors.append("security container matrix must build api, web, and edge")
    security_build = _step(security_container, "Build local scan candidate")
    security_build_with = _mapping(security_build.get("with"))
    if security_build_with.get("load") is not True or security_build_with.get("push") is not False:
        errors.append("security build must load locally and never push")
    security_sbom = _mapping(_step(security_container, "Generate Syft SPDX SBOM").get("with"))
    if security_sbom.get("format") != "spdx-json" or security_sbom.get("upload-artifact") is not True:
        errors.append("security Syft step must generate and upload SPDX JSON")
    security_trivy = _step(security_container, "Trivy HIGH/CRITICAL image gate")
    if not security_trivy:
        errors.append("security workflow is missing the Trivy image gate")
    else:
        errors.extend(_trivy_errors(security_trivy, label="security"))
    security_summary = _step(security_container, "Summarize Trivy findings")
    if security_summary.get("if") != "always()" or "report_trivy_sarif.py" not in str(
        security_summary.get("run", "")
    ):
        errors.append("security Trivy findings must be safely summarized on failure")

    release_jobs = _mapping(release.get("jobs"))
    if _mapping(release.get("concurrency")) != {
        "group": "release-${{ github.ref }}",
        "cancel-in-progress": False,
    }:
        errors.append("release workflow must serialize the same tag without cancellation")
    quality = _mapping(release_jobs.get("release-quality-gate"))
    container = _mapping(release_jobs.get("verified-container-release"))
    promoter = _mapping(release_jobs.get("promote-verified-container-release"))
    windows = _mapping(release_jobs.get("verified-windows-release"))
    if not quality or not container or not promoter or not windows:
        errors.append(
            "release workflow must contain quality, container evidence, "
            "coordinated promotion, and Windows jobs"
        )
        return errors
    if "if" in container:
        errors.append("container publication must not override dependency success")
    container_needs = set(_list(container.get("needs")))
    if container_needs != {
        "release-quality-gate",
        "release-browser-e2e",
        "release-codeql",
        "release-security-gate",
    }:
        errors.append(
            "container release must wait for quality, browser E2E, SAST, and dependency gates"
        )
    permissions = _mapping(container.get("permissions"))
    for permission in ("packages", "id-token", "attestations"):
        if permissions.get(permission) != "write":
            errors.append(f"container release requires {permission}: write")
    if _matrix(container) != EXPECTED_MATRIX:
        errors.append("release container matrix must publish api, web, and edge")

    release_build = _step(container, "Build local release candidate")
    release_build_with = _mapping(release_build.get("with"))
    if release_build_with.get("load") is not True or release_build_with.get("push") is not False:
        errors.append("release candidate must be loaded locally and not pushed before scanning")
    release_sbom = _mapping(_step(container, "Generate Syft SPDX SBOM").get("with"))
    if release_sbom.get("format") != "spdx-json" or not str(release_sbom.get("output-file", "")).endswith(".spdx.json"):
        errors.append("release Syft step must write an SPDX JSON predicate")
    release_trivy = _step(container, "Trivy HIGH/CRITICAL release gate")
    if not release_trivy:
        errors.append("release workflow is missing the Trivy gate")
    else:
        errors.extend(_trivy_errors(release_trivy, label="release"))
    release_summary = _step(container, "Summarize Trivy findings")
    if release_summary.get("if") != "always()" or "report_trivy_sarif.py" not in str(
        release_summary.get("run", "")
    ):
        errors.append("release Trivy findings must be safely summarized on failure")

    ordered_steps = (
        "Build local release candidate",
        "Generate Syft SPDX SBOM",
        "Trivy HIGH/CRITICAL release gate",
        "Summarize Trivy findings",
        "Login to GitHub Container Registry after scan",
        "Push scanned staging digest",
        "Keyless-sign image and attach Syft SBOM",
        "Attach GitHub build provenance",
        "Capture raw provider evidence before promotion",
        "Verify keyless image signature and SBOM attestation",
        "Build caller-pinnable external evidence index",
        "Record immutable container evidence",
        "Upload signed container release evidence",
    )
    indexes = [_step_index(container, name) for name in ordered_steps]
    if -1 in indexes or indexes != sorted(indexes) or len(set(indexes)) != len(indexes):
        errors.append(
            "release must build, scan, stage, sign, attest, verify, and publish evidence in order"
        )
    matrix_scripts = "\n".join(str(step.get("run", "")) for step in _steps(container))
    if (
        _step(container, "Publish verified release tag")
        or _step(container, "Publish all verified release tags after aggregate preflight")
        or "imagetools create --tag" in matrix_scripts
    ):
        errors.append("release matrix must not promote a public version tag")

    push_script = str(_step(container, "Push scanned staging digest").get("run", ""))
    for marker in (
        'staging_ref="$IMAGE:sha-${GITHUB_SHA}"',
        'docker tag "$CANDIDATE" "$staging_ref"',
        'docker push "$staging_ref"',
        'digest_ref="$(docker image inspect',
        "^sha256:[0-9a-f]{64}$",
    ):
        if marker not in push_script:
            errors.append(f"release staging step is missing exact-image control: {marker}")
    if "GITHUB_REF_NAME" in push_script:
        errors.append("release version tag must not be pushed before evidence verification")
    cosign_script = str(_step(container, "Keyless-sign image and attach Syft SBOM").get("run", ""))
    installer = _step(container, "Install Cosign")
    if _mapping(installer.get("with")).get("cosign-release") != "v3.1.3":
        errors.append("release Cosign version must be pinned to the patched v3.1.3 baseline")
    for marker in ("cosign sign --yes", "--bundle", "--output-payload", "cosign attest --yes --type spdxjson", '"${IMAGE}@${DIGEST}"'):
        if marker not in cosign_script:
            errors.append(f"release Cosign step is missing: {marker}")
    provenance = _step(container, "Attach GitHub build provenance")
    provenance_with = _mapping(provenance.get("with"))
    if (
        provenance.get("id") != "github_provenance"
        or
        provenance_with.get("push-to-registry") is not True
        or provenance_with.get("create-storage-record") is not False
        or "subject-digest" not in provenance_with
    ):
        errors.append("release provenance must bind and attach the pushed OCI digest")
    capture_script = str(_step(container, "Capture raw provider evidence before promotion").get("run", ""))
    for marker in (
        "GITHUB_PROVENANCE_BUNDLE", "cp --", "github-provenance.bundle.jsonl",
        "docker buildx imagetools inspect --raw", "oci-manifest.raw.json",
        '"sha256:${manifest_sha}" != "$DIGEST"', "sha256sum", "cosign version --json",
        "gh attestation trusted-root", "--verify-only", "github.executable.sha256",
        "github.version.txt", "github-sigstore.trusted-root.jsonl", "tuf.verify.txt",
    ):
        if marker not in capture_script:
            errors.append(f"release raw provider evidence capture is missing: {marker}")
    if "jq" in capture_script:
        errors.append("raw provider bundle capture must not parse or reserialize JSON")
    verify_script = str(_step(container, "Verify keyless image signature and SBOM attestation").get("run", ""))
    for marker in (
        "cosign verify-blob", "cosign.bundle.json", "cosign.payload.json",
        "cosign.bundle.verify.txt", "cosign verify --output json",
        "cosign verify-attestation --output json", "--certificate-identity",
        "--certificate-oidc-issuer", "cosign.verify.json",
        "cosign.verify-attestation.json", "gh attestation verify", "--bundle",
        "--custom-trusted-root", "--source-digest", "--source-ref", "--format json",
        "github.verify.json",
    ):
        if marker not in verify_script:
            errors.append(f"release must verify keyless evidence: {marker}")

    index_script = str(_step(container, "Build caller-pinnable external evidence index").get("run", ""))
    for marker in (
        "create_runtime_attestation_external_evidence_index.py", "--evidence-dir supply-chain",
        "runtime-attestation.external-evidence-index.json", "--repository-id",
        "--owner-id", "--workflow-ref", "--run-id", "--run-attempt",
        "--captured-at",
    ):
        if marker not in index_script:
            errors.append(f"release external evidence index is missing: {marker}")

    if "if" in promoter:
        errors.append("coordinated container promotion must not override dependency success")
    if set(_list(promoter.get("needs"))) != {"verified-container-release"}:
        errors.append("coordinated promotion must wait for every container matrix branch")
    promoter_permissions = _mapping(promoter.get("permissions"))
    if promoter_permissions != {"contents": "read", "packages": "write"}:
        errors.append("coordinated promotion permissions must be exactly contents:read and packages:write")
    promotion_steps = (
        "Download all verified container evidence",
        "Set up Docker Buildx for coordinated promotion",
        "Login to GitHub Container Registry for coordinated promotion",
        "Preflight every release tag before any promotion",
        "Publish all verified release tags after aggregate preflight",
    )
    promotion_indexes = [_step_index(promoter, name) for name in promotion_steps]
    if (
        -1 in promotion_indexes
        or promotion_indexes != sorted(promotion_indexes)
        or len(set(promotion_indexes)) != len(promotion_indexes)
    ):
        errors.append("coordinated promotion must download, preflight, then publish in order")
    download = _step(promoter, "Download all verified container evidence")
    download_with = _mapping(download.get("with"))
    if (
        download_with.get("pattern") != "container-release-*"
        or download_with.get("merge-multiple") is not True
    ):
        errors.append("coordinated promotion must merge all verified matrix evidence")
    preflight_script = str(
        _step(promoter, "Preflight every release tag before any promotion").get("run", "")
    )
    for marker in (
        "for name in api web edge",
        'metadata="supply-chain/${name}.metadata.json"',
        'image="$(jq -er \'.image\' "$metadata")"',
        'digest="$(jq -er \'.digest\' "$metadata")"',
        'tag="$(jq -er \'.tag\' "$metadata")"',
        'commit="$(jq -er \'.commit\' "$metadata")"',
        '"$tag" != "$GITHUB_REF_NAME"',
        '"$commit" != "$GITHUB_SHA"',
        'release_ref="${image}:${GITHUB_REF_NAME}"',
        'docker buildx imagetools inspect "$release_ref"',
        "manifest unknown|not found",
        '[[ -z "$existing_digest" || "$existing_digest" != "$digest" ]]',
        "Cannot safely determine whether the release tag already exists",
    ):
        if marker not in preflight_script:
            errors.append(f"aggregate release-tag preflight is missing: {marker}")
    if "imagetools create" in preflight_script or "docker push" in preflight_script:
        errors.append("aggregate release-tag preflight must not mutate registry tags")
    promote_script = str(
        _step(promoter, "Publish all verified release tags after aggregate preflight").get(
            "run", ""
        )
    )
    for marker in (
        "for name in api web edge",
        'metadata="supply-chain/${name}.metadata.json"',
        'release_ref="${image}:${GITHUB_REF_NAME}"',
        'docker buildx imagetools create --tag "$release_ref" "${image}@${digest}"',
        'docker buildx imagetools inspect "$release_ref"',
        'published_digest=',
        '[[ "$published_digest" != "$digest" ]]',
    ):
        if marker not in promote_script:
            errors.append(f"verified release-tag promotion is missing: {marker}")

    if "if" in windows:
        errors.append("Windows publication must not override dependency success")
    windows_needs = set(_list(windows.get("needs")))
    if windows_needs != {
        "release-quality-gate",
        "release-browser-e2e",
        "release-codeql",
        "release-security-gate",
        "promote-verified-container-release",
    }:
        errors.append(
            "Windows release must wait for quality, browser E2E, SAST, dependency, and verified container publication"
        )
    publish_script = str(_step(windows, "Publish GitHub Release after container verification").get("run", ""))
    for marker in (
        "container-release-manifest.json",
        "api.spdx.json",
        "web.spdx.json",
        "edge.spdx.json",
        "api.trivy.sarif",
        "web.trivy.sarif",
        "edge.trivy.sarif",
    ):
        if marker not in publish_script:
            errors.append(f"GitHub Release is missing container evidence: {marker}")

    for path, text in zip(DOCKERFILES, dockerfile_texts):
        from_lines = [line.strip() for line in text.splitlines() if line.strip().upper().startswith("FROM ")]
        if not from_lines or any(not _PINNED_BASE.fullmatch(line) for line in from_lines):
            errors.append(f"{path.name} base images must be pinned by sha256 digest")
    return errors


def main() -> int:
    try:
        security, release = load_workflows()
        try:
            texts = tuple(load_stable_text(path) for path in DOCKERFILES)
        except (OSError, UnicodeError):
            print(
                "container-supply-chain-error: "
                "Cannot inspect container supply-chain assets",
                file=sys.stderr,
            )
            return 1
        errors = validate_supply_chain(security, release, texts)
    except (OSError, ValueError, yaml.YAMLError) as error:
        print(f"container-supply-chain-error: {error}", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"container-supply-chain-error: {error}", file=sys.stderr)
        return 1
    print("container-supply-chain-ok build-scan-sbom-sign-attest-release-order-validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
