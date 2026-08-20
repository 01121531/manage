"""Structurally verify fail-closed container build, scan, and release gates."""

from __future__ import annotations

from pathlib import Path
import re
import sys
from typing import Any

import yaml


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
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
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
    if step.get("continue-on-error") not in (None, False):
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
    quality = _mapping(release_jobs.get("release-quality-gate"))
    container = _mapping(release_jobs.get("verified-container-release"))
    windows = _mapping(release_jobs.get("verified-windows-release"))
    if not quality or not container or not windows:
        errors.append("release workflow must contain quality, container, and Windows jobs")
        return errors
    if container.get("needs") != "release-quality-gate":
        errors.append("container release must wait for the release quality gate")
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
        "Push the exact scanned image",
        "Keyless-sign image and attach Syft SBOM",
        "Attach GitHub build provenance",
        "Verify keyless image signature and SBOM attestation",
    )
    indexes = [_step_index(container, name) for name in ordered_steps]
    if -1 in indexes or indexes != sorted(indexes) or len(set(indexes)) != len(indexes):
        errors.append("release must build, SBOM, scan, push, sign, attest, then verify in order")

    push_script = str(_step(container, "Push the exact scanned image").get("run", ""))
    for marker in ('docker tag "$CANDIDATE"', 'docker push "$IMAGE:', "^sha256:[0-9a-f]{64}$"):
        if marker not in push_script:
            errors.append(f"release push step is missing exact-image control: {marker}")
    cosign_script = str(_step(container, "Keyless-sign image and attach Syft SBOM").get("run", ""))
    for marker in ("cosign sign --yes", "cosign attest --yes --type spdxjson", '"${IMAGE}@${DIGEST}"'):
        if marker not in cosign_script:
            errors.append(f"release Cosign step is missing: {marker}")
    provenance = _step(container, "Attach GitHub build provenance")
    provenance_with = _mapping(provenance.get("with"))
    if (
        provenance_with.get("push-to-registry") is not True
        or provenance_with.get("create-storage-record") is not False
        or "subject-digest" not in provenance_with
    ):
        errors.append("release provenance must bind and attach the pushed OCI digest")
    verify_script = str(_step(container, "Verify keyless image signature and SBOM attestation").get("run", ""))
    for marker in ("cosign verify ", "cosign verify-attestation", "--certificate-identity", "--certificate-oidc-issuer"):
        if marker not in verify_script:
            errors.append(f"release must verify keyless evidence: {marker}")

    windows_needs = set(_list(windows.get("needs")))
    if windows_needs != {"release-quality-gate", "verified-container-release"}:
        errors.append("Windows release must wait for quality and verified container publication")
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
        texts = tuple(path.read_text(encoding="utf-8") for path in DOCKERFILES)
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
