"""Verify the CI security workflow includes the expected supply-chain gates."""

from __future__ import annotations

from pathlib import Path
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"
CODEQL_ACTION_SHA = "24ea975727876cf496b1eb0c5b36e96e01600b51"


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def main() -> int:
    if not WORKFLOW.exists():
        return _fail("Missing security workflow")
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return _fail("Security workflow is invalid")
    jobs = data.get("jobs")
    required_jobs = {"codeql", "security-gate", "container-supply-chain"}
    if not isinstance(jobs, dict) or not required_jobs.issubset(jobs):
        return _fail("Security workflow missing SAST, dependency, or container gate job")
    codeql_job = jobs["codeql"]
    if not isinstance(codeql_job, dict):
        return _fail("CodeQL job is invalid")
    permissions = codeql_job.get("permissions")
    if not isinstance(permissions, dict) or permissions.get("security-events") != "write":
        return _fail("CodeQL job must have security-events: write")
    matrix = codeql_job.get("strategy", {}).get("matrix", {})
    languages = matrix.get("language") if isinstance(matrix, dict) else None
    if not isinstance(languages, list) or set(languages) != {"javascript-typescript", "python"}:
        return _fail("CodeQL must analyze Python and JavaScript/TypeScript")
    codeql_steps = codeql_job.get("steps")
    if not isinstance(codeql_steps, list):
        return _fail("CodeQL steps are invalid")
    expected_actions = [
        f"github/codeql-action/init@{CODEQL_ACTION_SHA}",
        f"github/codeql-action/analyze@{CODEQL_ACTION_SHA}",
    ]
    actual_actions = [
        step.get("uses")
        for step in codeql_steps
        if isinstance(step, dict) and isinstance(step.get("uses"), str)
    ]
    for expected in expected_actions:
        if expected not in actual_actions:
            return _fail(f"CodeQL action is missing or not pinned: {expected}")
    init_index = actual_actions.index(expected_actions[0])
    analyze_index = actual_actions.index(expected_actions[1])
    if init_index >= analyze_index:
        return _fail("CodeQL analyze must run after initialization")
    init_step = next(
        step for step in codeql_steps
        if isinstance(step, dict) and step.get("uses") == expected_actions[0]
    )
    if init_step.get("continue-on-error") is True:
        return _fail("CodeQL initialization cannot continue on error")
    init_with = init_step.get("with")
    if not isinstance(init_with, dict) or init_with.get("languages") != "${{ matrix.language }}":
        return _fail("CodeQL initialization must use the language matrix")
    if init_with.get("queries") != "security-extended":
        return _fail("CodeQL must run the security-extended query suite")
    analyze_step = next(
        step for step in codeql_steps
        if isinstance(step, dict) and step.get("uses") == expected_actions[1]
    )
    if analyze_step.get("continue-on-error") is True:
        return _fail("CodeQL analysis cannot continue on error")
    job = jobs["security-gate"]
    if not isinstance(job, dict):
        return _fail("Security workflow job is invalid")
    steps = job.get("steps")
    if not isinstance(steps, list):
        return _fail("Security workflow steps are invalid")
    rendered = "\n".join(
        str(step.get("name", "")) if isinstance(step, dict) else str(step)
        for step in steps
    )
    required = [
        "Secret scan",
        "Verify release manifest",
        "Verify signoff template",
        "Python dependency audit",
        "Frontend dependency audit",
    ]
    missing = [item for item in required if item not in rendered]
    if missing:
        return _fail("Security workflow missing steps: " + ", ".join(missing))
    container_job = jobs["container-supply-chain"]
    if not isinstance(container_job, dict):
        return _fail("Security container gate job is invalid")
    container_step_names = {
        step.get("name")
        for step in container_job.get("steps", [])
        if isinstance(step, dict)
    }
    for required_name in (
        "Build local scan candidate",
        "Generate Syft SPDX SBOM",
        "Trivy HIGH/CRITICAL image gate",
        "Upload Trivy report",
    ):
        if required_name not in container_step_names:
            return _fail(f"Security container gate is missing: {required_name}")
    print("security-workflow-ok sast-dependency-secret-container-gates-present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
