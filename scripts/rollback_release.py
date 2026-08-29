"""Execute a release-bound, fail-closed platform rollback."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import wraps
import hmac
from inspect import signature
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Mapping, Protocol, Sequence

from scripts.create_container_release_manifest import EXPECTED_IMAGES, load_manifest
from scripts.postgres_maintenance import (
    BACKUP_MANIFEST_NAME,
    verify_bundle_release_binding,
)
from scripts.redis_maintenance import MANIFEST_NAME as REDIS_MANIFEST_NAME
from scripts.redis_maintenance import verify_release_backup
from scripts.restore_readiness import (
    PROBE_CONTAINER,
    PROBES,
    restore_contract_errors,
)
from scripts.tls_runtime_identity import (
    EXTERNAL_ENDPOINTS,
    INTERNAL_ENDPOINT_SERVICES,
    TLS_HTTP_PROBE_PROGRAM,
    TlsRuntimeIdentityError,
    expected_internal_fingerprints,
    parse_tls_probe_observation,
    probe_arguments,
    tls_probe_contract_errors,
)
from scripts.validate_edge_tls import EdgeTlsError, validate_edge_tls
from scripts.vault_token_sinks import VaultTokenSinkError, validate_vault_token_sinks
from scripts.external_yaml import load_unique_yaml_with_text
from scripts.release_control_lock import ReleaseControlLocked, release_control_lock
from scripts.rollback_release_evidence import (
    RollbackReleaseEvidenceError,
    RollbackReleaseEvidenceRecorder,
    TERMINAL_EDGE_CLOSED_FAILURE,
    TERMINAL_EDGE_UNCONFIRMED,
    TERMINAL_PREFLIGHT_FAILED,
    TERMINAL_SUCCEEDED,
    execution_fingerprint as rollback_execution_fingerprint,
    prepare_evidence_output,
    sha256_bytes,
    utc_timestamp,
)


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_COMPOSE = ROOT / "docker-compose.yml"
PRODUCTION_ENV_FILE = ROOT / ".env"
PRODUCTION_PROJECT_NAME = "email-platform"
DEFAULT_COMPOSE_OVERRIDES = tuple(
    ROOT / name
    for name in (
        "compose.override.yaml",
        "compose.override.yml",
        "docker-compose.override.yaml",
        "docker-compose.override.yml",
    )
)
STOP_SERVICES = (
    "edge",
    "api",
    "worker-mail",
    "worker-sub2",
    "web",
    "keycloak",
    "redis",
)
BACKEND_SERVICES = ("keycloak", "migrate", "api", "worker-mail", "worker-sub2", "web")
RUNNING_BACKEND_SERVICES = ("keycloak", "api", "worker-mail", "worker-sub2", "web")
REQUIRED_OPERATIONAL_SERVICES = (
    "postgres",
    "redis",
    "keycloak",
    "api",
    "worker-mail",
    "worker-sub2",
    "web",
    "edge",
    "prometheus",
    "alertmanager",
)
MAX_RECOVERY_POINT_SKEW = timedelta(minutes=5)
RUNTIME_IMAGE_SERVICES = {
    "api": "api",
    "worker-mail": "api",
    "worker-sub2": "api",
    "web": "web",
    "edge": "edge",
}
THIRD_PARTY_IMAGE_DIGEST_VARIABLES = (
    "POSTGRES_IMAGE_SHA256",
    "REDIS_IMAGE_SHA256",
    "KEYCLOAK_IMAGE_SHA256",
    "ALERTMANAGER_IMAGE_SHA256",
    "PROMETHEUS_IMAGE_SHA256",
)
FORBIDDEN_COMPOSE_CONTROL_VARIABLES = (
    "COMPOSE_FILE",
    "COMPOSE_PROJECT_NAME",
    "COMPOSE_PROFILES",
    "COMPOSE_ENV_FILES",
)
FORBIDDEN_DOCKER_TARGET_VARIABLES = (
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
)
FORBIDDEN_DOCKER_TLS_VARIABLES = (
    "DOCKER_TLS",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
)
FORBIDDEN_PRODUCTION_CREDENTIAL_VARIABLES = (
    "VAULT_TOKEN",
    "PLATFORM_VAULT_TOKEN",
    "PLATFORM_VAULT_API_TOKEN",
    "PLATFORM_VAULT_MAIL_TOKEN",
    "PLATFORM_VAULT_SUB2_TOKEN",
    "PLATFORM_VAULT_API_SECRET_ID",
    "PLATFORM_VAULT_MAIL_SECRET_ID",
    "PLATFORM_VAULT_SUB2_SECRET_ID",
    "VAULT_DEV_ROOT_TOKEN_ID",
    "ALEMBIC_DATABASE_URL",
    "PLATFORM_MIGRATION_DATABASE_URL",
    "PLATFORM_DATABASE_URL",
    "PLATFORM_REDIS_URL",
    "POSTGRES_PASSWORD",
    "POSTGRES_APP_PASSWORD",
    "POSTGRES_BOOTSTRAP_PASSWORD",
    "KEYCLOAK_DB_PASSWORD",
    "KEYCLOAK_ADMIN_PASSWORD",
    "KC_DB_PASSWORD",
    "KC_BOOTSTRAP_ADMIN_PASSWORD",
    "REDIS_PASSWORD",
    "REDIS_HEALTHCHECK_PASSWORD",
    "REDISCLI_AUTH",
    "PGPASSWORD",
)
SUBPROCESS_BASE_ENVIRONMENT_VARIABLES = (
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "PROGRAMDATA",
)
_COMPOSE_INPUT_VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)")


def _load_compose_input_variables(path: Path) -> frozenset[str]:
    _, source = load_unique_yaml_with_text(path)
    return frozenset(_COMPOSE_INPUT_VARIABLE.findall(source))


COMPOSE_INPUT_VARIABLES = _load_compose_input_variables(PRODUCTION_COMPOSE)
_DATABASE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class RollbackError(RuntimeError):
    """A safe rollback invariant was not satisfied."""


def _serialized_release_control(function):
    function_signature = signature(function)

    @wraps(function)
    def serialized(*args, **kwargs):
        bound = function_signature.bind(*args, **kwargs)
        evidence_output = bound.arguments["evidence_output"]
        plan = bound.arguments["plan"]
        try:
            prepare_evidence_output(evidence_output)
        except (OSError, RollbackReleaseEvidenceError, TypeError) as error:
            raise RollbackError("rollback evidence preflight failed") from error
        try:
            with release_control_lock():
                return function(*args, **kwargs)
        except ReleaseControlLocked as error:
            evidence = _new_evidence(plan)
            evidence.outcome(TERMINAL_PREFLIGHT_FAILED)
            _publish_evidence(evidence, evidence_output)
            raise RollbackError("another release control operation is active") from error

    return serialized


class ComposeEnvironmentError(RollbackError):
    """The caller tried to override production Compose inputs through its shell."""


class Runner(Protocol):
    def run(
        self,
        command: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        capture_output: bool = False,
    ) -> str: ...


class SubprocessRunner:
    def run(
        self,
        command: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        capture_output: bool = False,
    ) -> str:
        if env is None:
            raise RollbackError("explicit subprocess environment is required")
        result = subprocess.run(
            list(command),
            check=True,
            capture_output=capture_output,
            text=True,
            env=dict(env),
        )
        return result.stdout if capture_output else ""


def _validated_third_party_image_environment(
    environment: Mapping[str, str],
) -> dict[str, str]:
    """Require reviewed digest fragments before any production Compose call."""

    if any(
        name in environment for name in FORBIDDEN_PRODUCTION_CREDENTIAL_VARIABLES
    ):
        raise ComposeEnvironmentError("production Compose environment preflight failed")
    if any(name in environment for name in FORBIDDEN_DOCKER_TARGET_VARIABLES):
        raise ComposeEnvironmentError("production Compose environment preflight failed")
    if any(name in environment for name in FORBIDDEN_DOCKER_TLS_VARIABLES):
        raise ComposeEnvironmentError("production Compose environment preflight failed")
    inherited_compose_inputs = (
        COMPOSE_INPUT_VARIABLES.intersection(environment)
        .difference(THIRD_PARTY_IMAGE_DIGEST_VARIABLES)
    )
    if inherited_compose_inputs:
        raise ComposeEnvironmentError("production Compose environment preflight failed")

    for name in THIRD_PARTY_IMAGE_DIGEST_VARIABLES:
        value = environment.get(name, "")
        if re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise RollbackError(
                f"{name} must be an explicitly supplied 64-character lowercase sha256 fragment"
            )
    validated = {
        name: environment[name]
        for name in (
            *SUBPROCESS_BASE_ENVIRONMENT_VARIABLES,
            *THIRD_PARTY_IMAGE_DIGEST_VARIABLES,
        )
        if name in environment
    }
    return validated


@dataclass(frozen=True)
class RollbackPlan:
    tag: str
    commit: str
    migration_head: str
    container_manifest_sha256: str
    backup_created_at: datetime
    backup_dir: Path
    postgres_manifest_path: Path
    postgres_manifest_sha256: str
    redis_backup_created_at: datetime
    redis_backup_dir: Path
    redis_manifest_sha256: str
    recovery_set: str
    key_file: Path
    images: dict[str, str]
    signature_identities: dict[str, str]
    signature_issuer: str
    repository: str

    def execution_fingerprint(self) -> str:
        return rollback_execution_fingerprint(
            {
                "tag": self.tag,
                "commit": self.commit,
                "migration_head": self.migration_head,
                "container_manifest_sha256": self.container_manifest_sha256,
            },
            {
                "postgres_manifest_sha256": self.postgres_manifest_sha256,
                "redis_manifest_sha256": self.redis_manifest_sha256,
                "recovery_set": self.recovery_set,
            },
        )

    def compose_environment(self) -> dict[str, str]:
        environment = _validated_third_party_image_environment(os.environ)
        environment.update(
            {
                "PLATFORM_API_IMAGE": self.images["api"],
                "PLATFORM_WEB_IMAGE": self.images["web"],
                "PLATFORM_EDGE_IMAGE": self.images["edge"],
                "PLATFORM_RELEASE_TAG": self.tag,
                "PLATFORM_RELEASE_COMMIT": self.commit,
                "PLATFORM_RELEASE_MIGRATION_HEAD": self.migration_head,
            }
        )
        return environment


def _repository_from_image(image: str, image_name: str) -> str:
    prefix = "ghcr.io/"
    suffix = f"-{image_name}"
    if not image.startswith(prefix) or not image.endswith(suffix):
        raise RollbackError("container image repository is invalid")
    repository = image[len(prefix) : -len(suffix)]
    if repository.count("/") != 1:
        raise RollbackError("container image repository is invalid")
    return repository


def load_rollback_plan(
    container_manifest_path: Path,
    backup_dir: Path,
    key_file: Path,
    *,
    redis_backup_dir: Path,
    recovery_set: str,
) -> RollbackPlan:
    manifest, manifest_sha256 = load_manifest(
        container_manifest_path,
        _include_manifest_sha256=True,
    )
    images: dict[str, str] = {}
    identities: dict[str, str] = {}
    repositories: set[str] = set()
    for name in EXPECTED_IMAGES:
        metadata = manifest["images"][name]
        images[name] = f"{metadata['image']}@{metadata['digest']}"
        identities[name] = metadata["signature"]["identity"]
        repositories.add(_repository_from_image(metadata["image"], name))
    if len(repositories) != 1:
        raise RollbackError("container images do not belong to one repository")
    repository = repositories.pop()
    expected_identity_prefix = f"https://github.com/{repository}/"
    if any(not identity.startswith(expected_identity_prefix) for identity in identities.values()):
        raise RollbackError("signature identity does not match image repository")

    binding_result = verify_bundle_release_binding(
        backup_dir,
        key_file=key_file,
        release_tag=manifest["tag"],
        release_commit=manifest["commit"],
        migration_head=manifest["migration_head"],
        container_manifest_sha256=manifest_sha256,
        _include_created_at=True,
        _include_manifest_sha256=True,
    )
    _, backup_created_at, postgres_manifest_sha256 = binding_result
    postgres_manifest_path = backup_dir / BACKUP_MANIFEST_NAME
    _, redis_backup_created_at, redis_manifest_sha256 = verify_release_backup(
        redis_backup_dir,
        key_file=key_file,
        release_tag=manifest["tag"],
        release_commit=manifest["commit"],
        migration_head=manifest["migration_head"],
        container_manifest_sha256=manifest_sha256,
        postgres_manifest_sha256=postgres_manifest_sha256,
        recovery_set=recovery_set,
        _include_created_at=True,
        _include_manifest_sha256=True,
    )
    redis_manifest_path = redis_backup_dir / REDIS_MANIFEST_NAME
    if backup_created_at.tzinfo is None or redis_backup_created_at.tzinfo is None:
        raise RollbackError("recovery point creation times must be timezone-aware")
    postgres_created_at = backup_created_at.astimezone(timezone.utc)
    redis_created_at = redis_backup_created_at.astimezone(timezone.utc)
    if abs(redis_created_at - postgres_created_at) > MAX_RECOVERY_POINT_SKEW:
        raise RollbackError("PostgreSQL and Redis recovery points are too far apart")
    return RollbackPlan(
        tag=manifest["tag"],
        commit=manifest["commit"],
        migration_head=manifest["migration_head"],
        container_manifest_sha256=manifest_sha256,
        backup_created_at=postgres_created_at,
        backup_dir=backup_dir,
        postgres_manifest_path=postgres_manifest_path,
        postgres_manifest_sha256=postgres_manifest_sha256,
        redis_backup_created_at=redis_created_at,
        redis_backup_dir=redis_backup_dir,
        redis_manifest_sha256=redis_manifest_sha256,
        recovery_set=recovery_set,
        key_file=key_file,
        images=images,
        signature_identities=identities,
        signature_issuer="https://token.actions.githubusercontent.com",
        repository=repository,
    )


def plan_summary(plan: RollbackPlan) -> dict[str, object]:
    return {
        "schema_version": 2,
        "production_acceptance": False,
        "release_tag": plan.tag,
        "release_commit": plan.commit,
        "migration_head": plan.migration_head,
        "container_manifest_sha256": plan.container_manifest_sha256,
        "backup_created_at": plan.backup_created_at.isoformat(),
        "redis_backup_created_at": plan.redis_backup_created_at.isoformat(),
        "postgres_manifest_sha256": plan.postgres_manifest_sha256,
        "redis_manifest_sha256": plan.redis_manifest_sha256,
        "recovery_set": plan.recovery_set,
        "max_recovery_point_skew_seconds": int(
            MAX_RECOVERY_POINT_SKEW.total_seconds()
        ),
        "images": dict(plan.images),
        "database_bundle": "platform+keycloak+redis",
        "execution_order": [
            "verify-signatures-and-attestations",
            "pull-digests",
            "stop-edge-writers-and-redis",
            "restore-release-bound-dual-database-bundle",
            "restore-release-bound-redis-backup",
            "start-and-verify-redis",
            "start-and-verify-internal-services",
            "start-and-verify-edge",
        ],
    }


def _compose(command: str, *arguments: str) -> list[str]:
    return [
        "docker",
        "compose",
        "--project-directory",
        str(ROOT),
        "--env-file",
        str(PRODUCTION_ENV_FILE),
        "--project-name",
        PRODUCTION_PROJECT_NAME,
        "-f",
        str(PRODUCTION_COMPOSE),
        command,
        *arguments,
    ]


def _assert_release_checkout(
    expected_commit: str,
    *,
    runner: Runner,
    environment: Mapping[str, str],
    shell_environment: Mapping[str, str],
) -> None:
    if any(
        name in shell_environment for name in FORBIDDEN_COMPOSE_CONTROL_VARIABLES
    ) or any(
        path.exists() for path in DEFAULT_COMPOSE_OVERRIDES
    ):
        raise RollbackError("release checkout preflight failed")
    try:
        head = runner.run(
            ["git", "-C", str(ROOT), "rev-parse", "--verify", "HEAD"],
            env=environment,
            capture_output=True,
        ).strip()
        if not hmac.compare_digest(head, expected_commit):
            raise RollbackError("release checkout preflight failed")
        runner.run(
            ["git", "-C", str(ROOT), "diff", "--quiet", "--no-ext-diff", "--"],
            env=environment,
        )
        runner.run(
            [
                "git",
                "-C",
                str(ROOT),
                "diff",
                "--cached",
                "--quiet",
                "--no-ext-diff",
                "--",
            ],
            env=environment,
        )
    except RollbackError:
        raise
    except (OSError, subprocess.SubprocessError) as error:
        raise RollbackError("release checkout preflight failed") from error


def _verify_supply_chain(
    plan: RollbackPlan,
    runner: Runner,
    environment: Mapping[str, str],
) -> None:
    gh_environment = dict(environment)
    if "GH_TOKEN" in os.environ:
        gh_environment["GH_TOKEN"] = os.environ["GH_TOKEN"]
    for name in EXPECTED_IMAGES:
        image = plan.images[name]
        identity = plan.signature_identities[name]
        common = [
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            plan.signature_issuer,
        ]
        runner.run(["cosign", "verify", *common, image], env=environment)
        runner.run(
            [
                "cosign",
                "verify-attestation",
                "--type",
                "spdxjson",
                *common,
                image,
            ],
            env=environment,
        )
        runner.run(
            [
                "gh",
                "attestation",
                "verify",
                f"oci://{image}",
                "--repo",
                plan.repository,
            ],
            env=gh_environment,
        )


def _pull_images(
    plan: RollbackPlan,
    runner: Runner,
    environment: Mapping[str, str],
) -> None:
    for name in EXPECTED_IMAGES:
        runner.run(["docker", "pull", plan.images[name]], env=environment)


def _restore_command(
    plan: RollbackPlan,
    *,
    platform_target_db: str,
    keycloak_target_db: str,
) -> list[str]:
    return [
        sys.executable,
        "-m",
        "scripts.postgres_maintenance",
        "restore-bundle",
        "--input-dir",
        str(plan.backup_dir),
        "--key-file",
        str(plan.key_file),
        "--platform-target-db",
        platform_target_db,
        "--keycloak-target-db",
        keycloak_target_db,
        "--release-tag",
        plan.tag,
        "--release-commit",
        plan.commit,
        "--migration-head",
        plan.migration_head,
        "--container-manifest-sha256",
        plan.container_manifest_sha256,
    ]


def _redis_restore_command(plan: RollbackPlan) -> list[str]:
    return [
        sys.executable,
        "-m",
        "scripts.redis_maintenance",
        "restore-release",
        "--input-dir",
        str(plan.redis_backup_dir),
        "--key-file",
        str(plan.key_file),
        "--recovery-set",
        plan.recovery_set,
        "--postgres-manifest",
        str(plan.postgres_manifest_path),
        "--release-tag",
        plan.tag,
        "--release-commit",
        plan.commit,
        "--migration-head",
        plan.migration_head,
        "--container-manifest-sha256",
        plan.container_manifest_sha256,
        "--confirm-release-tag",
        plan.tag,
    ]


def _start_and_verify_redis(
    runner: Runner,
    environment: Mapping[str, str],
) -> None:
    runner.run(
        _compose("up", "-d", "--no-build", "--pull", "never", "redis"),
        env=environment,
    )
    _assert_running_services(runner, environment, required_services=("redis",))
    runner.run(
        _compose("exec", "-T", "redis", "/usr/local/bin/redis-healthcheck"),
        env=environment,
    )


def _assert_runtime_image(
    service: str,
    expected_image: str,
    *,
    runner: Runner,
    environment: Mapping[str, str],
) -> str:
    container_id = runner.run(
        _compose("ps", "-q", service),
        env=environment,
        capture_output=True,
    ).strip()
    if not container_id or "\n" in container_id:
        raise RollbackError("runtime container identity is invalid")
    actual_image = runner.run(
        ["docker", "inspect", "--format", "{{.Config.Image}}", container_id],
        env=environment,
        capture_output=True,
    ).strip()
    if actual_image != expected_image:
        raise RollbackError("runtime image does not match release digest")
    return actual_image


def _assert_running_services(
    runner: Runner,
    environment: Mapping[str, str],
    required_services: Sequence[str] = RUNNING_BACKEND_SERVICES,
) -> None:
    output = runner.run(
        _compose("ps", "--status", "running", "--services"),
        env=environment,
        capture_output=True,
    )
    running = {line.strip() for line in output.splitlines() if line.strip()}
    missing = set(required_services) - running
    if missing:
        raise RollbackError("required backend services are not running")


def _assert_operational_services(
    runner: Runner,
    environment: Mapping[str, str],
) -> None:
    try:
        _assert_running_services(
            runner,
            environment,
            required_services=REQUIRED_OPERATIONAL_SERVICES,
        )
    except RollbackError as error:
        raise RollbackError("required operational services are not running") from error


def _internal_smoke(
    runner: Runner,
    environment: Mapping[str, str],
    expected_fingerprints: Mapping[str, str],
    evidence: RollbackReleaseEvidenceRecorder | None = None,
) -> None:
    contract_errors = restore_contract_errors() + tls_probe_contract_errors()
    if contract_errors:
        raise RollbackError("internal smoke contract is invalid")
    endpoints = tuple(INTERNAL_ENDPOINT_SERVICES)
    if len(endpoints) != len(PROBES):
        raise RollbackError("internal TLS identity contract is invalid")
    for endpoint, url in zip(endpoints, PROBES, strict=True):
        service = INTERNAL_ENDPOINT_SERVICES[endpoint]
        expected = expected_fingerprints.get(service)
        if expected is None:
            raise RollbackError("internal TLS identity preflight is incomplete")
        output = runner.run(
            _compose(
                "exec",
                "-T",
                PROBE_CONTAINER,
                "python",
                "-c",
                TLS_HTTP_PROBE_PROGRAM,
                *probe_arguments(
                    url,
                    ca_file="/run/secrets/internal-tls/ca.crt",
                    max_body_bytes=1024 * 1024,
                ),
            ),
            env=environment,
            capture_output=True,
        )
        try:
            observation = parse_tls_probe_observation(
                output,
                expected_sha256=expected,
            )
        except TlsRuntimeIdentityError as error:
            raise RollbackError("internal TLS peer identity is invalid") from error
        if evidence is not None:
            evidence.tls_observation("internal", endpoint, observation)
            evidence.check(
                "internal_probes_passed",
                evidence.payload["checks"]["internal_probes_passed"] + 1,
            )


def _external_smoke(
    domain: str,
    runner: Runner,
    environment: Mapping[str, str],
    expected_fingerprint: str,
    evidence: RollbackReleaseEvidenceRecorder | None = None,
) -> None:
    urls = (
        f"https://{domain}/readyz",
        f"https://identity.{domain}/realms/email-platform/.well-known/openid-configuration",
    )
    for count, (endpoint, url) in enumerate(
        zip(EXTERNAL_ENDPOINTS, urls, strict=True),
        start=1,
    ):
        output = runner.run(
            [
                sys.executable,
                "-c",
                TLS_HTTP_PROBE_PROGRAM,
                *probe_arguments(
                    url,
                    ca_file=None,
                    max_body_bytes=1024 * 1024,
                ),
            ],
            env=environment,
            capture_output=True,
        )
        try:
            observation = parse_tls_probe_observation(
                output,
                expected_sha256=expected_fingerprint,
            )
        except TlsRuntimeIdentityError as error:
            raise RollbackError("external TLS peer identity is invalid") from error
        if evidence is not None:
            evidence.tls_observation("external", endpoint, observation)
            evidence.check("external_probes_passed", count)


def _validate_execution_inputs(
    *,
    platform_target_db: str,
    keycloak_target_db: str,
    domain: str,
) -> None:
    for database in (platform_target_db, keycloak_target_db):
        if _DATABASE_NAME.fullmatch(database) is None:
            raise RollbackError("target database name is invalid")
    normalized_domain = domain.lower()
    labels = normalized_domain.split(".")
    if (
        not normalized_domain
        or len(normalized_domain) > 253
        or len(labels) < 2
        or any(_DOMAIN_LABEL.fullmatch(label) is None for label in labels)
    ):
        raise RollbackError("platform domain is invalid")


def _evidence_images(plan: RollbackPlan) -> dict[str, str]:
    return {
        "api": plan.images["api"],
        "worker_mail": plan.images["api"],
        "worker_sub2": plan.images["api"],
        "web": plan.images["web"],
        "edge": plan.images["edge"],
    }


def _new_evidence(plan: RollbackPlan) -> RollbackReleaseEvidenceRecorder:
    evidence = RollbackReleaseEvidenceRecorder(
        execution_fingerprint=plan.execution_fingerprint(),
        release={
            "tag": plan.tag,
            "commit": plan.commit,
            "migration_head": plan.migration_head,
            "container_manifest_sha256": plan.container_manifest_sha256,
        },
        recovery={
            "recovery_set": plan.recovery_set,
            "postgres_manifest_sha256": plan.postgres_manifest_sha256,
            "redis_manifest_sha256": plan.redis_manifest_sha256,
            "postgres_created_at": utc_timestamp(plan.backup_created_at),
            "redis_created_at": utc_timestamp(plan.redis_backup_created_at),
        },
        images=_evidence_images(plan),
    )
    evidence.validate_initial()
    return evidence


def _publish_evidence(
    evidence: RollbackReleaseEvidenceRecorder,
    evidence_output: Path,
) -> None:
    try:
        evidence.write(evidence_output)
    except (OSError, RollbackReleaseEvidenceError) as error:
        raise RollbackError("rollback evidence publication failed") from error


def _stop_edge_for_failure(
    runner: Runner,
    environment: Mapping[str, str],
    evidence: RollbackReleaseEvidenceRecorder,
) -> bool:
    try:
        runner.run(_compose("stop", "edge"), env=environment)
    except Exception:
        return False
    evidence.edge_stop_confirmed()
    return True


@_serialized_release_control
def execute_rollback(
    plan: RollbackPlan,
    *,
    confirm_release_tag: str,
    platform_target_db: str,
    keycloak_target_db: str,
    domain: str,
    evidence_output: Path,
    runner: Runner | None = None,
) -> None:
    try:
        prepare_evidence_output(evidence_output)
        evidence = _new_evidence(plan)
    except (OSError, RollbackReleaseEvidenceError) as error:
        raise RollbackError("rollback evidence preflight failed") from error

    command_runner: Runner | None = None
    environment: Mapping[str, str] | None = None
    mutation_attempted = False
    edge_may_be_open = False
    try:
        if confirm_release_tag != plan.tag:
            raise RollbackError("release confirmation does not match rollback plan")
        _validate_execution_inputs(
            platform_target_db=platform_target_db,
            keycloak_target_db=keycloak_target_db,
            domain=domain,
        )
        try:
            edge_fingerprint = validate_edge_tls(PRODUCTION_ENV_FILE, domain)
        except EdgeTlsError as error:
            raise RollbackError("public edge TLS preflight failed") from error
        try:
            internal_fingerprints = expected_internal_fingerprints(
                PRODUCTION_ENV_FILE,
                now=datetime.now(timezone.utc),
            )
        except TlsRuntimeIdentityError as error:
            raise RollbackError("internal TLS identity preflight failed") from error
        try:
            validate_vault_token_sinks(PRODUCTION_ENV_FILE, PRODUCTION_COMPOSE)
        except VaultTokenSinkError:
            raise RollbackError(
                "production Vault token sink preflight failed"
            ) from None
        evidence.check("vault_sink_checks_passed", 1)
        environment = plan.compose_environment()
        command_runner = runner or SubprocessRunner()

        _assert_release_checkout(
            plan.commit,
            runner=command_runner,
            environment=environment,
            shell_environment=os.environ,
        )
        _assert_operational_services(command_runner, environment)
        evidence.check("operational_checks_passed", 1)
        _verify_supply_chain(plan, command_runner, environment)
        evidence.check("supply_chain_verified", True)
        _pull_images(plan, command_runner, environment)
        evidence.check("images_pulled", True)
        evidence.phase("PREFLIGHTED")

        mutation_attempted = True
        command_runner.run(_compose("stop", *STOP_SERVICES), env=environment)
        evidence.edge_stop_confirmed()
        evidence.phase("WRITERS_STOPPED")
        command_runner.run(
            _restore_command(
                plan,
                platform_target_db=platform_target_db,
                keycloak_target_db=keycloak_target_db,
            ),
            env=environment,
        )
        evidence.phase("POSTGRES_RESTORED")
        command_runner.run(_redis_restore_command(plan), env=environment)
        evidence.phase("REDIS_RESTORED")
        _start_and_verify_redis(command_runner, environment)
        evidence.phase("REDIS_VERIFIED")
        command_runner.run(
            _compose("up", "-d", "--no-build", "--pull", "never", "--force-recreate", *BACKEND_SERVICES),
            env=environment,
        )
        _assert_running_services(command_runner, environment)
        evidence_services = {
            "api": "api",
            "worker-mail": "worker_mail",
            "worker-sub2": "worker_sub2",
            "web": "web",
        }
        for service, evidence_service in evidence_services.items():
            observed = _assert_runtime_image(
                service,
                plan.images[RUNTIME_IMAGE_SERVICES[service]],
                runner=command_runner,
                environment=environment,
            )
            evidence.observed_image(evidence_service, observed)
        _internal_smoke(
            command_runner,
            environment,
            internal_fingerprints,
            evidence,
        )
        evidence.phase("INTERNAL_VERIFIED")
        try:
            validate_vault_token_sinks(PRODUCTION_ENV_FILE, PRODUCTION_COMPOSE)
        except VaultTokenSinkError:
            raise RollbackError(
                "Vault token sink recheck failed with public edge closed"
            ) from None
        evidence.check("vault_sink_checks_passed", 2)

        evidence.edge_start_attempted()
        edge_may_be_open = True
        command_runner.run(
            _compose("up", "-d", "--no-build", "--pull", "never", "--force-recreate", "edge"),
            env=environment,
        )
        evidence.phase("EDGE_STARTED")
        observed_edge = _assert_runtime_image(
            "edge",
            plan.images["edge"],
            runner=command_runner,
            environment=environment,
        )
        evidence.observed_image("edge", observed_edge)
        _external_smoke(
            domain,
            command_runner,
            environment,
            edge_fingerprint,
            evidence,
        )
        evidence.phase("EXTERNAL_VERIFIED")
        _assert_operational_services(command_runner, environment)
        evidence.check("operational_checks_passed", 2)
        evidence.outcome(TERMINAL_SUCCEEDED)
    except BaseException as execution_error:
        closure_unconfirmed = False
        if mutation_attempted:
            if evidence.payload["edge"]["stop_confirmations"] == 0 or edge_may_be_open:
                if command_runner is None or environment is None or not _stop_edge_for_failure(
                    command_runner, environment, evidence
                ):
                    closure_unconfirmed = True
            evidence.outcome(
                TERMINAL_EDGE_UNCONFIRMED
                if closure_unconfirmed
                else TERMINAL_EDGE_CLOSED_FAILURE
            )
        else:
            evidence.outcome(TERMINAL_PREFLIGHT_FAILED)
        publication_error: RollbackError | None = None
        try:
            _publish_evidence(evidence, evidence_output)
        except RollbackError as error:
            publication_error = error
        if not isinstance(execution_error, Exception):
            raise
        if closure_unconfirmed:
            raise RollbackError(
                "rollback failed and public edge closure could not be confirmed"
            ) from execution_error
        if publication_error is not None:
            raise publication_error from execution_error
        if isinstance(
            execution_error,
            (RollbackError, OSError, subprocess.SubprocessError),
        ):
            raise
        raise RollbackError("rollback execution failed") from None

    try:
        _publish_evidence(evidence, evidence_output)
    except RollbackError as publication_error:
        if command_runner is None or environment is None or not _stop_edge_for_failure(
            command_runner, environment, evidence
        ):
            raise RollbackError(
                "rollback evidence publication failed and public edge closure could not be confirmed"
            ) from publication_error
        raise RollbackError(
            "rollback evidence publication failed; public edge was closed"
        ) from publication_error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "execute"):
        command = subparsers.add_parser(name)
        command.add_argument("--container-manifest", type=Path, required=True)
        command.add_argument("--backup-dir", type=Path, required=True)
        command.add_argument("--redis-backup-dir", type=Path, required=True)
        command.add_argument("--recovery-set", required=True)
        command.add_argument("--key-file", type=Path, required=True)
        if name == "execute":
            command.add_argument("--confirm-release-tag", required=True)
            command.add_argument("--platform-target-db", default="email_platform")
            command.add_argument("--keycloak-target-db", default="keycloak")
            command.add_argument("--domain", required=True)
            command.add_argument("--evidence-output", type=Path, required=True)
    return parser


def main(arguments: list[str] | None = None) -> int:
    options = _parser().parse_args(arguments)
    try:
        plan = load_rollback_plan(
            options.container_manifest,
            options.backup_dir,
            options.key_file,
            redis_backup_dir=options.redis_backup_dir,
            recovery_set=options.recovery_set,
        )
        if options.command == "plan":
            print(json.dumps(plan_summary(plan), sort_keys=True))
        else:
            execute_rollback(
                plan,
                confirm_release_tag=options.confirm_release_tag,
                platform_target_db=options.platform_target_db,
                keycloak_target_db=options.keycloak_target_db,
                domain=options.domain,
                evidence_output=options.evidence_output,
            )
            print("rollback-release-ok")
        return 0
    except (RollbackError, ValueError, OSError, subprocess.SubprocessError):
        print("rollback-release-failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
