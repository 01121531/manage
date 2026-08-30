"""Verify CI contains executable gates for platform and Windows artifacts."""

from __future__ import annotations

from pathlib import Path

import yaml

try:
    from scripts.external_text import load_stable_text
    from scripts.external_yaml import load_unique_yaml, parse_unique_yaml
except ModuleNotFoundError:  # Direct `python scripts/...` execution.
    from external_text import load_stable_text  # type: ignore[no-redef]
    from external_yaml import load_unique_yaml, parse_unique_yaml  # type: ignore[no-redef]


ROOT = Path(__file__).resolve().parents[1]
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"
QUALITY_GATE_PATH = ROOT / "scripts" / "quality_gate.ps1"
POSTGRES_DATABASE_URL = (
    "postgresql+psycopg://migration_gate:migration_gate@localhost:5432/"
    "email_platform_migration_gate"
)
POSTGRES_SERVICE_ENV = {
    "POSTGRES_DB": "email_platform_migration_gate",
    "POSTGRES_USER": "migration_gate",
    "POSTGRES_PASSWORD": "migration_gate",
}
APPROVED_EXTERNAL_ACTIONS = {
    "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262",
    "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
    "actions/setup-node": "49933ea5288caeca8642d1e84afbd3f7d6820020",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
}
CI_READ_ONLY_PERMISSIONS = {"contents": "read"}
POSTGRES_GATE_ACTIONS = [
    f"actions/checkout@{APPROVED_EXTERNAL_ACTIONS['actions/checkout']}",
    f"actions/setup-python@{APPROVED_EXTERNAL_ACTIONS['actions/setup-python']}",
]
POSIX_TLS_BOUNDARY_STEP = (
    "Verify private materialization and Kubernetes TLS boundaries on Linux"
)
POSIX_TLS_BOUNDARY_COMMAND = (
    "python -m unittest tests.test_private_secret_materialization "
    "tests.test_private_secret_residue "
    "tests.test_kubernetes_kubeconfig_intake "
    "tests.test_kubernetes_tls_rotation_backend "
    "tests.test_tls_rotation_profile_live "
    "tests.test_verify_tls_rotation_executor "
    "tests.test_verify_tls_rotation_artifacts "
    "tests.test_private_secret_crash_evidence "
    "tests.test_verify_private_secret_crash_evidence "
    "tests.test_private_secret_github_attestation "
    "tests.test_private_secret_target_provenance "
    "tests.test_verify_private_secret_provenance "
    "tests.test_private_secret_github_rest_collection "
    "tests.test_private_secret_worm_collection "
    "tests.test_verify_private_secret_collection "
    "tests.test_private_secret_collection_review_decision "
    "tests.test_verify_private_secret_collection_review "
    "tests.test_private_secret_collection_archive_receipt "
    "tests.test_verify_private_secret_collection_archive "
    "tests.test_private_secret_collector_deployment "
    "tests.test_verify_private_secret_collector_deployment"
)


def has_unsafe_continue_on_error(node: object) -> bool:
    """Only an omitted key or the strict boolean false preserves fail-closed behavior."""

    return (
        isinstance(node, dict)
        and "continue-on-error" in node
        and node["continue-on-error"] is not False
    )


def continue_on_error_errors(jobs: object, *, label: str) -> list[str]:
    """Reject fail-open or type-confused continue-on-error on every job and step."""

    if not isinstance(jobs, dict):
        return [f"{label} jobs must be a mapping"]
    errors: list[str] = []
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        if has_unsafe_continue_on_error(job):
            errors.append(
                f"{label} {job_name} continue-on-error must be boolean false when present"
            )
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue
        for index, step in enumerate(steps):
            if has_unsafe_continue_on_error(step):
                errors.append(
                    f"{label} {job_name} step {index + 1} continue-on-error "
                    "must be boolean false when present"
                )
    return errors


def checkout_credential_errors(jobs: object, *, label: str) -> list[str]:
    """Reject checkout steps that leave the job token available to later scripts."""

    if not isinstance(jobs, dict):
        return [f"{label} jobs must be a mapping"]
    errors: list[str] = []
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            uses = step.get("uses")
            if not isinstance(uses, str) or not uses.startswith("actions/checkout@"):
                continue
            inputs = step.get("with")
            if (
                not isinstance(inputs, dict)
                or inputs.get("persist-credentials") is not False
            ):
                errors.append(
                    f"{label} {job_name} checkout step {index + 1} must set "
                    "persist-credentials to boolean false"
                )
    return errors


def external_action_pin_errors(jobs: object) -> list[str]:
    """Require every third-party CI action to match the reviewed commit exactly."""

    if not isinstance(jobs, dict):
        return ["CI jobs must be a mapping"]
    errors: list[str] = []

    def check_reference(uses: object, *, label: str) -> None:
        if not isinstance(uses, str):
            errors.append(f"{label} action reference must be a string")
            return
        if uses.startswith("./"):
            return
        action_name, separator, revision = uses.rpartition("@")
        approved_revision = APPROVED_EXTERNAL_ACTIONS.get(action_name)
        if not separator or approved_revision is None:
            errors.append(f"{label} uses an unapproved external action: {uses}")
            return
        if revision != approved_revision:
            errors.append(f"{label} action must use the approved commit: {action_name}")

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        if "uses" in job:
            check_reference(job.get("uses"), label=f"{job_name} reusable workflow")
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            continue
        for index, step in enumerate(steps):
            if not isinstance(step, dict) or "uses" not in step:
                continue
            check_reference(step.get("uses"), label=f"{job_name} step {index + 1}")
    return errors


def ci_permission_errors(workflow: object, jobs: object) -> list[str]:
    """Prevent workflow or job overrides from broadening the CI token."""

    if not isinstance(workflow, dict):
        return ["CI workflow must be a mapping"]
    errors: list[str] = []
    if workflow.get("permissions") != CI_READ_ONLY_PERMISSIONS:
        errors.append("CI workflow permissions must be exactly contents: read")
    if not isinstance(jobs, dict):
        return errors
    for job_name, job in jobs.items():
        if not isinstance(job, dict) or "permissions" not in job:
            continue
        if job.get("permissions") != CI_READ_ONLY_PERMISSIONS:
            errors.append(
                f"{job_name} permissions must inherit or be exactly contents: read"
            )
    return errors


def postgres_migration_gate_errors(job: object, *, label: str) -> list[str]:
    """Validate a fail-closed online migration against an ephemeral PostgreSQL 16."""

    if not isinstance(job, dict):
        return [f"{label} must be a mapping"]
    errors: list[str] = []
    if job.get("runs-on") != "ubuntu-24.04":
        errors.append(f"{label} must run on ubuntu-24.04")
    if has_unsafe_continue_on_error(job):
        errors.append(f"{label} must fail closed")
    environment = job.get("env")
    if not isinstance(environment, dict) or environment.get(
        "ALEMBIC_DATABASE_URL"
    ) != POSTGRES_DATABASE_URL:
        errors.append(f"{label} must use the reviewed PostgreSQL psycopg URL")

    services = job.get("services")
    postgres = services.get("postgres") if isinstance(services, dict) else None
    if not isinstance(postgres, dict):
        errors.append(f"{label} must define a PostgreSQL service")
    else:
        if postgres.get("image") != "postgres:16-alpine":
            errors.append(f"{label} must test PostgreSQL 16")
        if postgres.get("env") != POSTGRES_SERVICE_ENV:
            errors.append(f"{label} PostgreSQL service environment is invalid")
        ports = postgres.get("ports")
        if not isinstance(ports, list) or {str(port) for port in ports} != {"5432:5432"}:
            errors.append(f"{label} PostgreSQL service must expose localhost port 5432")
        options = " ".join(str(postgres.get("options", "")).split())
        for marker in (
            "--health-cmd",
            'pg_isready -U migration_gate -d email_platform_migration_gate',
            "--health-interval 5s",
            "--health-timeout 5s",
            "--health-retries 12",
        ):
            if marker not in options:
                errors.append(f"{label} PostgreSQL health check is missing: {marker}")

    steps = job.get("steps")
    if not isinstance(steps, list):
        errors.append(f"{label} steps must be a list")
        return errors
    if any(
        has_unsafe_continue_on_error(step)
        for step in steps
    ):
        errors.append(f"{label} steps must fail closed")
    actions = [
        step.get("uses")
        for step in steps
        if isinstance(step, dict) and isinstance(step.get("uses"), str)
    ]
    if actions != POSTGRES_GATE_ACTIONS:
        errors.append(f"{label} checkout and Python setup actions must be commit-pinned")
    named_steps = {
        step["name"]: step
        for step in steps
        if isinstance(step, dict) and isinstance(step.get("name"), str)
    }
    install = named_steps.get("Install platform dependencies")
    if not isinstance(install, dict) or " ".join(
        str(install.get("run", "")).split()
    ) != "python -m pip install -r platform/requirements.txt":
        errors.append(f"{label} must install platform runtime dependencies")
    vault_safety = named_steps.get("Verify Vault token file safety on Linux")
    if not isinstance(vault_safety, dict) or " ".join(
        str(vault_safety.get("run", "")).split()
    ) != (
        "python -m unittest platform.tests.test_secret_resolvers "
        "tests.test_vault_token_sinks tests.test_vault_approle_bootstrap "
        "tests.test_vault_broker_policy_bootstrap"
    ):
        errors.append(
            f"{label} must run resolver, host token sink, AppRole, and broker policy behavior tests on Linux"
        )
    posix_tls_boundary = named_steps.get(POSIX_TLS_BOUNDARY_STEP)
    if not isinstance(posix_tls_boundary, dict) or " ".join(
        str(posix_tls_boundary.get("run", "")).split()
    ) != POSIX_TLS_BOUNDARY_COMMAND:
        errors.append(
            f"{label} must run the complete private materialization and Kubernetes TLS boundary tests on Linux"
        )
    migrate = named_steps.get("Apply PostgreSQL migrations online")
    if not isinstance(migrate, dict) or " ".join(
        str(migrate.get("run", "")).split()
    ) != "alembic -c alembic.ini upgrade head":
        errors.append(f"{label} must execute an online Alembic upgrade to head")
    verify = named_steps.get("Verify unique repository head matches database")
    verify_run = str(verify.get("run", "")) if isinstance(verify, dict) else ""
    for marker in (
        'os.environ["ALEMBIC_DATABASE_URL"]',
        'ScriptDirectory.from_config(Config("alembic.ini")).get_heads()',
        "len(heads) != 1",
        'text("SELECT version_num FROM alembic_version")',
        "database_head != heads[0]",
    ):
        if marker not in verify_run:
            errors.append(f"{label} head verification is missing: {marker}")
    serialized = "\n".join(str(step) for step in steps).lower()
    if "--sql" in serialized:
        errors.append(f"{label} must not use offline Alembic SQL generation")
    if "sqlite" in serialized:
        errors.append(f"{label} must not substitute SQLite for PostgreSQL")
    return errors


def verification_errors(
    workflow_text: str | None = None,
    quality_gate_text: str | None = None,
) -> list[str]:
    try:
        workflow = (
            load_unique_yaml(CI_PATH)
            if workflow_text is None
            else parse_unique_yaml(workflow_text)
        )
    except (OSError, UnicodeError, yaml.YAMLError):
        return ["CI workflow is invalid"]
    jobs = workflow.get("jobs", {}) if isinstance(workflow, dict) else {}
    errors = ci_permission_errors(workflow, jobs)
    errors.extend(checkout_credential_errors(jobs, label="CI"))
    errors.extend(continue_on_error_errors(jobs, label="CI"))
    required_jobs = {
        "quality-gate",
        "postgres-migration-gate",
        "browser-e2e",
        "windows-desktop-release",
    }
    missing = required_jobs.difference(jobs)
    if missing:
        errors.append("missing CI jobs: " + ", ".join(sorted(missing)))
        return errors
    errors.extend(external_action_pin_errors(jobs))

    quality_job = jobs["quality-gate"]
    quality_needs = quality_job.get("needs", [])
    if isinstance(quality_needs, str):
        quality_needs = [quality_needs]
    if set(quality_needs) != {"postgres-migration-gate"}:
        errors.append("quality gate must depend on the PostgreSQL migration gate")
    quality_steps = quality_job.get("steps", [])
    quality_serialized = "\n".join(str(step) for step in quality_steps)
    phase6_output = "${{ runner.temp }}/phase6-ci-rehearsal-${{ github.sha }}.json"
    quality_step = next(
        (
            step
            for step in quality_steps
            if isinstance(step, dict) and step.get("name") == "Run quality gate"
        ),
        {},
    )
    quality_environment = quality_step.get("env", {})
    if (
        not isinstance(quality_environment, dict)
        or quality_environment.get("PHASE6_EVIDENCE_OUTPUT") != phase6_output
    ):
        errors.append("quality gate step must bind Phase 6 evidence to the external runner temp path")
    for required in (
        "phase6-ci-rehearsal-${{ github.sha }}",
        phase6_output,
        "if-no-files-found",
        "error",
    ):
        if required not in quality_serialized:
            errors.append(f"quality gate is missing Phase 6 evidence control: {required}")
    try:
        quality_gate = (
            load_stable_text(QUALITY_GATE_PATH)
            if quality_gate_text is None
            else quality_gate_text
        )
    except (OSError, UnicodeError):
        return ["CI workflow is invalid"]
    for required in (
        "phase6_rehearsal.py run",
        "phase6_rehearsal.py verify",
        "$env:PHASE6_EVIDENCE_OUTPUT",
        "[System.IO.Path]::GetTempPath()",
        "verify_phase6_evidence_outputs.py",
        "verify_migration_compatibility.py",
    ):
        if required not in quality_gate:
            errors.append(f"quality gate is missing Phase 6 rehearsal command: {required}")

    errors.extend(
        postgres_migration_gate_errors(
            jobs["postgres-migration-gate"], label="PostgreSQL migration gate"
        )
    )

    browser = jobs["browser-e2e"]
    if not isinstance(browser, dict):
        errors.append("browser E2E job must be a mapping")
        return errors
    if browser.get("runs-on") != "ubuntu-24.04":
        errors.append("browser E2E job must run on ubuntu-24.04")
    if has_unsafe_continue_on_error(browser):
        errors.append("browser E2E job must fail closed")
    browser_steps = browser.get("steps", [])
    browser_serialized = "\n".join(str(step) for step in browser_steps)
    for required in (
        "platform/requirements.txt",
        "npm ci",
        "playwright install --with-deps chromium",
        "npm run test:e2e",
    ):
        if required not in browser_serialized:
            errors.append(f"browser E2E job is missing {required}")
    if any(
        has_unsafe_continue_on_error(step)
        for step in browser_steps
    ):
        errors.append("browser E2E steps must fail closed")

    release = jobs["windows-desktop-release"]
    if release.get("runs-on") != "windows-latest":
        errors.append("Windows release job must run on windows-latest")
    release_needs = release.get("needs", [])
    if isinstance(release_needs, str):
        release_needs = [release_needs]
    if set(release_needs) != {
        "quality-gate",
        "browser-e2e",
    }:
        errors.append(
            "Windows release job must depend on browser E2E and the quality gate "
            "that is transitively blocked by PostgreSQL migrations"
        )
    steps = release.get("steps", [])
    serialized = "\n".join(str(step) for step in steps)
    for required in (
        "platform/requirements-test.txt",
        "requirements-desktop-build.txt",
        "./build.ps1",
        "verify_desktop_package.py --exe",
        "Get-FileHash",
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
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
    print("ci-workflow-ok quality-e2e-postgres-migrations-phase6-windows-artifact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
