"""Verify CI contains executable gates for platform and Windows artifacts."""

from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"
QUALITY_GATE_PATH = ROOT / "scripts" / "quality_gate.ps1"


def verification_errors() -> list[str]:
    workflow = yaml.safe_load(CI_PATH.read_text(encoding="utf-8"))
    jobs = workflow.get("jobs", {}) if isinstance(workflow, dict) else {}
    errors: list[str] = []
    required_jobs = {"quality-gate", "browser-e2e", "windows-desktop-release"}
    missing = required_jobs.difference(jobs)
    if missing:
        errors.append("missing CI jobs: " + ", ".join(sorted(missing)))
        return errors

    quality_steps = jobs["quality-gate"].get("steps", [])
    quality_serialized = "\n".join(str(step) for step in quality_steps)
    for required in (
        "phase6-ci-rehearsal-${{ github.sha }}",
        "release/evidence/phase6-ci-rehearsal.json",
        "if-no-files-found",
        "error",
    ):
        if required not in quality_serialized:
            errors.append(f"quality gate is missing Phase 6 evidence control: {required}")
    quality_gate = QUALITY_GATE_PATH.read_text(encoding="utf-8")
    for required in (
        "phase6_rehearsal.py run",
        "phase6_rehearsal.py verify",
        "release/evidence/phase6-ci-rehearsal.json",
    ):
        if required not in quality_gate:
            errors.append(f"quality gate is missing Phase 6 rehearsal command: {required}")

    release = jobs["windows-desktop-release"]
    if release.get("runs-on") != "windows-latest":
        errors.append("Windows release job must run on windows-latest")
    if release.get("needs") != "quality-gate":
        errors.append("Windows release job must depend on quality-gate")
    steps = release.get("steps", [])
    serialized = "\n".join(str(step) for step in steps)
    for required in (
        "platform/requirements-test.txt",
        "requirements-desktop-build.txt",
        "./build.ps1",
        "verify_desktop_package.py --exe",
        "Get-FileHash",
        "actions/upload-artifact@v4",
        "release/windows/*",
    ):
        if required not in serialized:
            errors.append(f"Windows release job is missing {required}")
    if "if-no-files-found" not in serialized or "error" not in serialized:
        errors.append("artifact upload must fail when release files are absent")
    return errors


def main() -> int:
    errors = verification_errors()
    if errors:
        for error in errors:
            print(f"ci-workflow-error: {error}")
        return 1
    print("ci-workflow-ok quality-e2e-phase6-windows-artifact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
