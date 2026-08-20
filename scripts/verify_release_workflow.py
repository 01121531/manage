"""Structured checks for the gated desktop and container release workflow."""

from pathlib import Path

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
    container_steps = named_steps("verified-container-release")
    if "Upload signed container release evidence" not in container_steps:
        errors.append("container release must upload signed evidence")
    windows = jobs["verified-windows-release"]
    needs = set(windows.get("needs", [])) if isinstance(windows, dict) else set()
    if needs != {"release-quality-gate", "verified-container-release"}:
        errors.append("Windows publication must depend on quality and container release")
    windows_steps = named_steps("verified-windows-release")
    for name in (
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
        "--verify-tag",
    ):
        if marker not in publish_run:
            errors.append(f"release publication is missing: {marker}")
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
