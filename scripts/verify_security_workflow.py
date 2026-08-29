"""Verify the CI security workflow includes the expected supply-chain gates."""

from __future__ import annotations

from pathlib import Path
import sys

import yaml

try:
    from scripts.external_yaml import load_unique_yaml
    from scripts.verify_ci_workflow import (
        checkout_credential_errors,
        continue_on_error_errors,
        has_unsafe_continue_on_error,
    )
except ModuleNotFoundError:  # Direct `python scripts/...` execution.
    from external_yaml import load_unique_yaml  # type: ignore[no-redef]
    from verify_ci_workflow import (  # type: ignore[no-redef]
        checkout_credential_errors,
        continue_on_error_errors,
        has_unsafe_continue_on_error,
    )


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "security.yml"
CODEQL_ACTION_SHA = "24ea975727876cf496b1eb0c5b36e96e01600b51"


def _fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def dependency_gate_step_errors(
    job: object, *, require_repository_checks: bool
) -> list[str]:
    """Validate commands, not labels, so a renamed no-op cannot satisfy the gate."""

    if not isinstance(job, dict):
        return ["dependency security job is invalid"]
    if has_unsafe_continue_on_error(job):
        return ["dependency security job must fail closed"]
    steps = job.get("steps")
    if not isinstance(steps, list):
        return ["dependency security steps are invalid"]
    named = {
        step.get("name"): step
        for step in steps
        if isinstance(step, dict) and isinstance(step.get("name"), str)
    }
    expected: dict[str, tuple[str, str | None]] = {
        "Secret scan": ("python scripts/secret_scan.py", None),
        "Python dependency audit": (
            "pip-audit -r platform/requirements.txt",
            None,
        ),
        "Python test dependency audit": (
            "pip-audit -r platform/requirements-test.txt",
            None,
        ),
        "Python desktop build dependency audit": (
            "pip-audit -r requirements-desktop-build.txt",
            None,
        ),
        "Frontend dependency audit": (
            "npm audit --audit-level=high "
            "--include=prod --include=dev --include=optional --include=peer",
            "frontend",
        ),
    }
    if require_repository_checks:
        expected.update(
            {
                "Verify release manifest": (
                    "python scripts/verify_release_manifest.py",
                    None,
                ),
                "Verify signoff template": (
                    "python scripts/verify_signoff_template.py",
                    None,
                ),
            }
        )
    errors: list[str] = []
    for name, (command, working_directory) in expected.items():
        step = named.get(name)
        if not isinstance(step, dict):
            errors.append(f"dependency security gate is missing: {name}")
            continue
        if has_unsafe_continue_on_error(step):
            errors.append(f"dependency security step must fail closed: {name}")
        if str(step.get("run", "")).strip() != command:
            errors.append(f"dependency security step has unsafe command: {name}")
        if working_directory is not None and step.get("working-directory") != working_directory:
            errors.append(f"dependency security step has wrong working directory: {name}")
    return errors


def main() -> int:
    if not WORKFLOW.exists():
        return _fail("Missing security workflow")
    try:
        data = load_unique_yaml(WORKFLOW)
    except (OSError, UnicodeError, yaml.YAMLError):
        return _fail("Security workflow is invalid")
    if not isinstance(data, dict):
        return _fail("Security workflow is invalid")
    jobs = data.get("jobs")
    required_jobs = {"codeql", "security-gate", "container-supply-chain"}
    if not isinstance(jobs, dict) or not required_jobs.issubset(jobs):
        return _fail("Security workflow missing SAST, dependency, or container gate job")
    checkout_errors = checkout_credential_errors(jobs, label="Security")
    if checkout_errors:
        return _fail("; ".join(checkout_errors))
    fail_open_errors = continue_on_error_errors(jobs, label="Security")
    if fail_open_errors:
        return _fail("; ".join(fail_open_errors))
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
    if has_unsafe_continue_on_error(init_step):
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
    if has_unsafe_continue_on_error(analyze_step):
        return _fail("CodeQL analysis cannot continue on error")
    if has_unsafe_continue_on_error(codeql_job):
        return _fail("CodeQL job must fail closed")
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
        "Python test dependency audit",
        "Python desktop build dependency audit",
        "Frontend dependency audit",
    ]
    missing = [item for item in required if item not in rendered]
    if missing:
        return _fail("Security workflow missing steps: " + ", ".join(missing))
    command_errors = dependency_gate_step_errors(
        job, require_repository_checks=True
    )
    if command_errors:
        return _fail("; ".join(command_errors))
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
