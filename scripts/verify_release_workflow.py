"""Structured checks for the gated desktop and container release workflow."""

from pathlib import Path
import re

import yaml

try:
    from scripts.external_yaml import load_unique_yaml_with_text, parse_unique_yaml
    from scripts.verify_ci_workflow import (
        checkout_credential_errors,
        continue_on_error_errors,
        has_unsafe_continue_on_error,
        postgres_migration_gate_errors,
    )
except ModuleNotFoundError:  # Direct `python scripts/...` execution.
    from external_yaml import (  # type: ignore[no-redef]
        load_unique_yaml_with_text,
        parse_unique_yaml,
    )
    from verify_ci_workflow import (  # type: ignore[no-redef]
        checkout_credential_errors,
        continue_on_error_errors,
        has_unsafe_continue_on_error,
        postgres_migration_gate_errors,
    )

try:
    from scripts.verify_security_workflow import (
        CODEQL_ACTION_SHA,
        dependency_gate_step_errors,
    )
except ModuleNotFoundError:  # Direct `python scripts/...` execution.
    from verify_security_workflow import (  # type: ignore[no-redef]
        CODEQL_ACTION_SHA,
        dependency_gate_step_errors,
    )


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def workflow_errors(text: str) -> list[str]:
    try:
        data = parse_unique_yaml(text)
    except yaml.YAMLError as error:
        return [f"release workflow invalid YAML: {error}"]
    if not isinstance(data, dict):
        return ["release workflow must contain a mapping"]
    jobs = data.get("jobs")
    if not isinstance(jobs, dict):
        return ["release workflow must contain jobs"]
    errors = checkout_credential_errors(jobs, label="Release")
    errors.extend(continue_on_error_errors(jobs, label="Release"))
    required_jobs = {
        "release-quality-gate",
        "release-postgres-migration-gate",
        "release-browser-e2e",
        "release-codeql",
        "release-security-gate",
        "verified-container-release",
        "verified-windows-release",
    }
    if not required_jobs.issubset(jobs):
        errors.append("release workflow is missing gated quality/container/Windows jobs")
        return errors
    linux_jobs = required_jobs.difference(
        {"release-quality-gate", "verified-windows-release"}
    )
    for job_name in sorted(linux_jobs):
        job = jobs[job_name]
        if not isinstance(job, dict) or job.get("runs-on") != "ubuntu-24.04":
            errors.append(f"{job_name} must run on ubuntu-24.04")

    def named_steps(job_name: str) -> dict[str, dict[str, object]]:
        job = jobs[job_name]
        steps = job.get("steps", []) if isinstance(job, dict) else []
        return {
            step["name"]: step
            for step in steps
            if isinstance(step, dict) and isinstance(step.get("name"), str)
        }

    quality_steps = named_steps("release-quality-gate")
    release_quality = jobs["release-quality-gate"]
    quality_needs = (
        release_quality.get("needs", [])
        if isinstance(release_quality, dict)
        else []
    )
    if isinstance(quality_needs, str):
        quality_needs = [quality_needs]
    if set(quality_needs) != {"release-postgres-migration-gate"}:
        errors.append(
            "release quality gate must depend on the PostgreSQL migration gate"
        )
    if "Run full quality gate" not in quality_steps:
        errors.append("release quality job must run the full quality gate")
    phase6_output = "${{ runner.temp }}/phase6-ci-rehearsal-${{ github.sha }}.json"
    quality_environment = release_quality.get("env", {})
    if (
        not isinstance(quality_environment, dict)
        or quality_environment.get("PHASE6_EVIDENCE_OUTPUT") != phase6_output
    ):
        errors.append("release quality job must bind Phase 6 evidence to the external runner temp path")
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
        if upload_path != phase6_output:
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

    release_codeql = jobs["release-codeql"]
    if not isinstance(release_codeql, dict):
        errors.append("release CodeQL job must be a mapping")
    else:
        if has_unsafe_continue_on_error(release_codeql):
            errors.append("release CodeQL job must fail closed")
        permissions = release_codeql.get("permissions")
        if not isinstance(permissions, dict) or permissions.get("security-events") != "write":
            errors.append("release CodeQL must publish security events")
        strategy = release_codeql.get("strategy")
        matrix = strategy.get("matrix", {}) if isinstance(strategy, dict) else {}
        languages = matrix.get("language") if isinstance(matrix, dict) else None
        if not isinstance(languages, list) or set(languages) != {"python", "javascript-typescript"}:
            errors.append("release CodeQL must analyze Python and JavaScript/TypeScript")
        codeql_steps = release_codeql.get("steps", [])
        uses = [
            step.get("uses")
            for step in codeql_steps
            if isinstance(step, dict) and isinstance(step.get("uses"), str)
        ] if isinstance(codeql_steps, list) else []
        expected_codeql = [
            f"github/codeql-action/init@{CODEQL_ACTION_SHA}",
            f"github/codeql-action/analyze@{CODEQL_ACTION_SHA}",
        ]
        if any(action not in uses for action in expected_codeql):
            errors.append("release CodeQL actions must be present and commit-pinned")
        else:
            init_step = next(
                step for step in codeql_steps
                if isinstance(step, dict) and step.get("uses") == expected_codeql[0]
            )
            analyze_step = next(
                step for step in codeql_steps
                if isinstance(step, dict) and step.get("uses") == expected_codeql[1]
            )
            init_with = init_step.get("with")
            if not isinstance(init_with, dict) or init_with.get("languages") != "${{ matrix.language }}" or init_with.get("queries") != "security-extended":
                errors.append("release CodeQL initialization is not security-extended matrix analysis")
            if has_unsafe_continue_on_error(init_step) or has_unsafe_continue_on_error(analyze_step):
                errors.append("release CodeQL steps must fail closed")

    errors.extend(
        dependency_gate_step_errors(
            jobs["release-security-gate"], require_repository_checks=False
        )
    )
    errors.extend(
        postgres_migration_gate_errors(
            jobs["release-postgres-migration-gate"],
            label="Release PostgreSQL migration gate",
        )
    )

    browser = jobs["release-browser-e2e"]
    if not isinstance(browser, dict):
        errors.append("release browser E2E job must be a mapping")
        return errors
    if browser.get("runs-on") != "ubuntu-24.04":
        errors.append("release browser E2E must run on ubuntu-24.04")
    if has_unsafe_continue_on_error(browser):
        errors.append("release browser E2E must fail closed")
    browser_steps = browser.get("steps", [])
    browser_serialized = "\n".join(str(step) for step in browser_steps)
    for required in (
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
        "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
        "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020",
        "platform/requirements.txt",
        "npm ci",
        "playwright install --with-deps chromium",
        "npm run test:e2e",
    ):
        if required not in browser_serialized:
            errors.append(f"release browser E2E is missing: {required}")
    if any(
        has_unsafe_continue_on_error(step)
        for step in browser_steps
    ):
        errors.append("release browser E2E steps must fail closed")

    container = jobs["verified-container-release"]
    if isinstance(container, dict) and "if" in container:
        errors.append("container publication must not override dependency success")
    container_needs = set(container.get("needs", [])) if isinstance(container, dict) else set()
    if container_needs != {
        "release-quality-gate",
        "release-browser-e2e",
        "release-codeql",
        "release-security-gate",
    }:
        errors.append(
            "container publication must depend on quality, browser E2E, SAST, "
            "dependency security, and the migration-blocked quality gate"
        )
    container_steps = named_steps("verified-container-release")
    if "Upload signed container release evidence" not in container_steps:
        errors.append("container release must upload signed evidence")
    windows = jobs["verified-windows-release"]
    if isinstance(windows, dict) and "if" in windows:
        errors.append("Windows publication must not override dependency success")
    needs = set(windows.get("needs", [])) if isinstance(windows, dict) else set()
    if needs != {
        "release-quality-gate",
        "release-browser-e2e",
        "release-codeql",
        "release-security-gate",
        "verified-container-release",
    }:
        errors.append(
            "Windows publication must depend on quality, browser E2E, SAST, "
            "dependency security, the migration-blocked quality gate, and container release"
        )
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
    try:
        _, text = load_unique_yaml_with_text(WORKFLOW)
    except (OSError, UnicodeError, yaml.YAMLError):
        print("release-workflow-error: release workflow invalid YAML")
        return 1
    errors = workflow_errors(text)
    if errors:
        for error in errors:
            print(f"release-workflow-error: {error}")
        return 1
    print(
        "release-workflow-ok "
        "quality-e2e-postgres-migrations-container-before-windows-publication"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
