"""Structured checks for the gated desktop and container release workflow."""

from pathlib import Path
import re

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def workflow_errors(text: str) -> list[str]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as error:
        return [f"release workflow invalid YAML: {error}"]
    if not isinstance(data, dict):
        return ["release workflow must contain a mapping"]
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return ["release workflow must contain jobs"]
    errors: list[str] = []
    required_jobs = {
        "release-quality-gate",
        "verified-container-release",
        "verified-windows-release",
    }
    if not required_jobs.issubset(jobs):
        errors.append("release workflow is missing gated quality/container/Windows jobs")
        return errors

    def named_steps(job_name: str) -> dict[str, dict[str, object]]:
        job = jobs[job_name]
        steps = job.get("steps", []) if isinstance(job, dict) else []
        return {
            step["name"]: step
            for step in steps
            if isinstance(step, dict) and isinstance(step.get("name"), str)
        }

    quality_steps = named_steps("release-quality-gate")
    if "Run full quality gate" not in quality_steps:
        errors.append("release quality job must run the full quality gate")
    phase6_upload = quality_steps.get("Upload Phase 6 CI rehearsal evidence", {})
    if not phase6_upload:
        errors.append("release quality job must upload Phase 6 evidence")
    else:
        upload_action = str(phase6_upload.get("uses", ""))
        upload_with = phase6_upload.get("with", {})
        upload_name = (
            str(upload_with.get("name", ""))
            if isinstance(upload_with, dict)
            else ""
        )
        upload_path = (
            str(upload_with.get("path", ""))
            if isinstance(upload_with, dict)
            else ""
        )
        if upload_name != "phase6-ci-rehearsal-${{ github.sha }}":
            errors.append("Phase 6 evidence artifact must be commit-bound")
        if upload_path != "release/evidence/phase6-ci-rehearsal.json":
            errors.append("Phase 6 evidence upload path is invalid")
        if (
            re.fullmatch(r"actions/upload-artifact@[0-9a-f]{40}", upload_action)
            is None
        ):
            errors.append("Phase 6 evidence must use a pinned upload action")
        if (
            not isinstance(upload_with, dict)
            or upload_with.get("if-no-files-found") != "error"
        ):
            errors.append("missing Phase 6 evidence must fail the release")
    container_steps = named_steps("verified-container-release")
    if "Upload signed container release evidence" not in container_steps:
        errors.append("container release must upload signed evidence")
    windows = jobs["verified-windows-release"]
    needs = set(windows.get("needs", [])) if isinstance(windows, dict) else set()
    if needs != {"release-quality-gate", "verified-container-release"}:
        errors.append("Windows publication must depend on quality and container release")
    windows_steps = named_steps("verified-windows-release")
    for name in (
        "Download Phase 6 CI rehearsal evidence",
        "Verify Phase 6 evidence commit and integrity",
        "Create immutable container release manifest",
        "Build and inspect platform-only Windows EXE",
        "Create verified update assets",
        "Publish GitHub Release after container verification",
    ):
        if name not in windows_steps:
            errors.append(f"Windows release is missing step: {name}")
    publish = windows_steps.get("Publish GitHub Release after container verification", {})
    publish_run = str(publish.get("run", ""))
    for marker in (
        "gh release create",
        "email-platform-windows.exe",
        "update-manifest.json",
        "container-release-manifest.json",
        "phase6-ci-rehearsal.json",
        "phase6-ci-rehearsal.json.sha256",
        "--verify-tag",
    ):
        if marker not in publish_run:
            errors.append(f"release publication is missing: {marker}")
    download_phase6 = windows_steps.get("Download Phase 6 CI rehearsal evidence", {})
    download_with = (
        download_phase6.get("with", {})
        if isinstance(download_phase6, dict)
        else {}
    )
    if (
        not isinstance(download_with, dict)
        or download_with.get("name")
        != "phase6-ci-rehearsal-${{ github.sha }}"
    ):
        errors.append(
            "release publication must download the matching Phase 6 artifact"
        )
    download_action = (
        str(download_phase6.get("uses", ""))
        if isinstance(download_phase6, dict)
        else ""
    )
    if (
        re.fullmatch(r"actions/download-artifact@[0-9a-f]{40}", download_action)
        is None
    ):
        errors.append("Phase 6 evidence must use a pinned download action")
    verify_phase6 = windows_steps.get(
        "Verify Phase 6 evidence commit and integrity", {}
    )
    verify_run = (
        str(verify_phase6.get("run", ""))
        if isinstance(verify_phase6, dict)
        else ""
    )
    for marker in (
        "phase6_rehearsal.py verify",
        "--expected-commit",
        "${{ github.sha }}",
        "Get-FileHash",
        "phase6-ci-rehearsal.json.sha256",
    ):
        if marker not in verify_run:
            errors.append(f"Phase 6 release verification is missing: {marker}")
    if '"v*.*.*"' not in text:
        errors.append("release workflow must use semantic version tags")
    if "client_secret" in text.lower():
        errors.append("release workflow must not contain a client secret")
    return errors


def main() -> int:
    if not WORKFLOW.is_file():
        print("release-workflow-error: workflow does not exist")
        return 1
    errors = workflow_errors(WORKFLOW.read_text(encoding="utf-8"))
    if errors:
        for error in errors:
            print(f"release-workflow-error: {error}")
        return 1
    print("release-workflow-ok quality-container-signing-before-windows-publication")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
