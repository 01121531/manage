"""Deploy one verified application release while keeping the public edge fail closed."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hmac
from functools import wraps
from inspect import signature
import os
from pathlib import Path
import subprocess
import sys
from typing import Mapping, Sequence

from scripts.create_container_release_manifest import EXPECTED_IMAGES, load_manifest
from scripts.rollback_release import (
    ComposeEnvironmentError,
    PRODUCTION_COMPOSE,
    PRODUCTION_ENV_FILE,
    RUNTIME_IMAGE_SERVICES,
    MAX_RECOVERY_POINT_SKEW,
    RollbackError,
    RollbackPlan,
    Runner,
    SubprocessRunner,
    _assert_operational_services,
    _assert_running_services,
    _assert_release_checkout,
    _assert_runtime_image,
    _compose,
    _external_smoke,
    _internal_smoke,
    _pull_images,
    _repository_from_image,
    _validate_execution_inputs,
    _validated_third_party_image_environment,
    _verify_supply_chain,
    load_rollback_plan,
)
from scripts.scan_third_party_images import (
    ThirdPartyScanError,
    scan_third_party_images,
)
from scripts.target_intake_preflight import (
    PhaseCheckpointIdentity,
    load_phase_checkpoint,
)
from scripts.deploy_release_evidence import (
    DeploymentReleaseEvidenceError,
    DeploymentReleaseEvidenceRecorder,
    TERMINAL_EDGE_CLOSED_FAILURE,
    TERMINAL_EDGE_UNCONFIRMED,
    TERMINAL_PREFLIGHT_FAILED,
    TERMINAL_SUCCEEDED,
    prepare_evidence_output,
    utc_timestamp,
)
from scripts.release_control_lock import ReleaseControlLocked, release_control_lock
from scripts.validate_edge_tls import EdgeTlsError, validate_edge_tls
from scripts.vault_token_sinks import VaultTokenSinkError, validate_vault_token_sinks
from scripts.tls_runtime_identity import (
    TlsRuntimeIdentityError,
    expected_internal_fingerprints,
)


BACKEND_SERVICES = ("migrate", "api", "worker-mail", "worker-sub2", "web")
MAX_ROLLBACK_POINT_AGE = timedelta(hours=1)
MAX_FUTURE_CLOCK_SKEW = timedelta(minutes=5)


class DeploymentError(RuntimeError):
    """An immutable forward-deployment invariant was not satisfied."""


def _serialized_release_control(function):
    function_signature = signature(function)

    @wraps(function)
    def serialized(*args, **kwargs):
        bound = function_signature.bind(*args, **kwargs)
        evidence_output = bound.arguments["evidence_output"]
        plan = bound.arguments["plan"]
        release_started_at = datetime.now(timezone.utc)
        try:
            checkpoint = load_phase_checkpoint(
                bound.arguments["target_intake_manifest"],
                environment=bound.arguments["target_environment"],
                through_phase=0,
                evaluated_at=release_started_at,
            )
        except ValueError:
            raise DeploymentError("target intake Phase 0 preflight failed")
        bound.arguments["_target_intake_checkpoint"] = checkpoint
        try:
            prepare_evidence_output(evidence_output)
        except (OSError, DeploymentReleaseEvidenceError, TypeError) as error:
            raise DeploymentError("deployment evidence preflight failed") from error
        try:
            with release_control_lock():
                return function(*bound.args, **bound.kwargs)
        except ReleaseControlLocked as error:
            evidence = _new_evidence(plan, checkpoint)
            evidence.outcome(TERMINAL_PREFLIGHT_FAILED)
            _publish_evidence(evidence, evidence_output)
            raise DeploymentError(
                "another release control operation is active"
            ) from error

    return serialized


@dataclass(frozen=True)
class DeploymentPlan:
    tag: str
    commit: str
    migration_head: str
    container_manifest_sha256: str
    images: dict[str, str]
    signature_identities: dict[str, str]
    signature_issuer: str
    repository: str
    rollback: RollbackPlan

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


def load_deployment_plan(
    container_manifest_path: Path,
    *,
    rollback_container_manifest_path: Path,
    rollback_backup_dir: Path,
    rollback_redis_backup_dir: Path,
    rollback_recovery_set: str,
    rollback_key_file: Path,
    now: datetime | None = None,
) -> DeploymentPlan:
    try:
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
    except (OSError, ValueError, RollbackError) as error:
        raise DeploymentError("container release manifest is invalid") from error

    if len(repositories) != 1:
        raise DeploymentError("container images do not belong to one repository")
    repository = repositories.pop()
    expected_identity_prefix = f"https://github.com/{repository}/"
    if any(
        not identity.startswith(expected_identity_prefix)
        for identity in identities.values()
    ):
        raise DeploymentError("signature identity does not match image repository")
    try:
        rollback = load_rollback_plan(
            rollback_container_manifest_path,
            rollback_backup_dir,
            rollback_key_file,
            redis_backup_dir=rollback_redis_backup_dir,
            recovery_set=rollback_recovery_set,
        )
    except (OSError, ValueError, RollbackError) as error:
        raise DeploymentError("authenticated rollback point is invalid") from error
    checked_at = now or datetime.now(timezone.utc)
    if checked_at.tzinfo is None:
        raise DeploymentError("rollback freshness check requires an aware UTC time")
    checked_at = checked_at.astimezone(timezone.utc)
    for created_at in (
        rollback.backup_created_at,
        rollback.redis_backup_created_at,
    ):
        created_at = created_at.astimezone(timezone.utc)
        if created_at > checked_at + MAX_FUTURE_CLOCK_SKEW:
            raise DeploymentError("rollback point creation time is in the future")
        if checked_at - created_at > MAX_ROLLBACK_POINT_AGE:
            raise DeploymentError("rollback point is stale")
    if rollback.tag == manifest["tag"]:
        raise DeploymentError("rollback and target releases must be different")
    return DeploymentPlan(
        tag=manifest["tag"],
        commit=manifest["commit"],
        migration_head=manifest["migration_head"],
        container_manifest_sha256=manifest_sha256,
        images=images,
        signature_identities=identities,
        signature_issuer="https://token.actions.githubusercontent.com",
        repository=repository,
        rollback=rollback,
    )


def plan_summary(plan: DeploymentPlan) -> dict[str, object]:
    return {
        "release_tag": plan.tag,
        "release_commit": plan.commit,
        "migration_head": plan.migration_head,
        "container_manifest_sha256": plan.container_manifest_sha256,
        "images": dict(plan.images),
        "rollback_release_tag": plan.rollback.tag,
        "rollback_release_commit": plan.rollback.commit,
        "rollback_migration_head": plan.rollback.migration_head,
        "rollback_container_manifest_sha256": plan.rollback.container_manifest_sha256,
        "rollback_backup_created_at": plan.rollback.backup_created_at.isoformat(),
        "rollback_redis_backup_created_at": (
            plan.rollback.redis_backup_created_at.isoformat()
        ),
        "rollback_recovery_set": plan.rollback.recovery_set,
        "rollback_postgres_manifest_sha256": (
            plan.rollback.postgres_manifest_sha256
        ),
        "rollback_max_recovery_point_skew_seconds": int(
            MAX_RECOVERY_POINT_SKEW.total_seconds()
        ),
        "rollback_database_bundle": "platform+keycloak+redis",
        "production_acceptance": False,
        "rolling_release": False,
    }


def _evidence_images(plan: DeploymentPlan) -> dict[str, str]:
    return {
        "api": plan.images["api"],
        "worker_mail": plan.images["api"],
        "worker_sub2": plan.images["api"],
        "web": plan.images["web"],
        "edge": plan.images["edge"],
    }


def _new_evidence(
    plan: DeploymentPlan,
    checkpoint: PhaseCheckpointIdentity,
) -> DeploymentReleaseEvidenceRecorder:
    evidence = DeploymentReleaseEvidenceRecorder(
        target_release={
            "tag": plan.tag,
            "commit": plan.commit,
            "migration_head": plan.migration_head,
            "container_manifest_sha256": plan.container_manifest_sha256,
        },
        rollback={
            "release_tag": plan.rollback.tag,
            "release_commit": plan.rollback.commit,
            "migration_head": plan.rollback.migration_head,
            "container_manifest_sha256": plan.rollback.container_manifest_sha256,
            "postgres_manifest_sha256": plan.rollback.postgres_manifest_sha256,
            "redis_manifest_sha256": plan.rollback.redis_manifest_sha256,
            "recovery_set": plan.rollback.recovery_set,
            "postgres_created_at": utc_timestamp(plan.rollback.backup_created_at),
            "redis_created_at": utc_timestamp(
                plan.rollback.redis_backup_created_at
            ),
        },
        images=_evidence_images(plan),
        target_intake=checkpoint.as_evidence(),
        started_at=checkpoint.evaluated_at,
    )
    evidence.validate_initial()
    return evidence


def _record_third_party_images(
    evidence: DeploymentReleaseEvidenceRecorder,
    environment: Mapping[str, str],
) -> None:
    references = {
        "postgres": f"postgres@sha256:{environment['POSTGRES_IMAGE_SHA256']}",
        "redis": f"redis@sha256:{environment['REDIS_IMAGE_SHA256']}",
        "keycloak": (
            "quay.io/keycloak/keycloak@sha256:"
            f"{environment['KEYCLOAK_IMAGE_SHA256']}"
        ),
        "alertmanager": (
            "prom/alertmanager@sha256:"
            f"{environment['ALERTMANAGER_IMAGE_SHA256']}"
        ),
        "prometheus": (
            "prom/prometheus@sha256:"
            f"{environment['PROMETHEUS_IMAGE_SHA256']}"
        ),
    }
    for service, image in references.items():
        evidence.third_party_image(service, image)


def _publish_evidence(
    evidence: DeploymentReleaseEvidenceRecorder,
    evidence_output: Path,
) -> None:
    try:
        evidence.write(evidence_output)
    except (OSError, DeploymentReleaseEvidenceError) as error:
        raise DeploymentError("deployment evidence publication failed") from error


def _stop_edge_for_failure(
    runner: Runner,
    environment: Mapping[str, str],
    evidence: DeploymentReleaseEvidenceRecorder,
) -> bool:
    try:
        runner.run(_compose("stop", "edge"), env=environment)
    except Exception:
        return False
    evidence.edge_stop_confirmed()
    return True


@_serialized_release_control
def execute_deployment(
    plan: DeploymentPlan,
    *,
    confirm_release_tag: str,
    container_manifest_sha256: str,
    domain: str,
    evidence_output: Path,
    target_intake_manifest: Path,
    target_environment: str,
    _target_intake_checkpoint: PhaseCheckpointIdentity | None = None,
    runner: Runner | None = None,
) -> None:
    if _target_intake_checkpoint is None:
        raise DeploymentError("target intake Phase 0 preflight failed")
    try:
        prepare_evidence_output(evidence_output)
        evidence = _new_evidence(plan, _target_intake_checkpoint)
    except (OSError, DeploymentReleaseEvidenceError) as error:
        raise DeploymentError("deployment evidence preflight failed") from error

    command_runner: Runner | None = None
    environment: Mapping[str, str] | None = None
    mutation_attempted = False
    edge_may_be_open = False
    closure_unconfirmed = False
    try:
        if confirm_release_tag != plan.tag:
            raise DeploymentError("release confirmation does not match deployment plan")
        if not hmac.compare_digest(
            container_manifest_sha256.lower(), plan.container_manifest_sha256
        ):
            raise DeploymentError(
                "container manifest SHA-256 does not match deployment plan"
            )
        try:
            _validate_execution_inputs(
                platform_target_db="email_platform",
                keycloak_target_db="keycloak",
                domain=domain,
            )
        except RollbackError as error:
            raise DeploymentError(str(error)) from error

        try:
            edge_fingerprint = validate_edge_tls(PRODUCTION_ENV_FILE, domain)
        except EdgeTlsError as error:
            raise DeploymentError("public edge TLS preflight failed") from error
        try:
            internal_fingerprints = expected_internal_fingerprints(
                PRODUCTION_ENV_FILE,
                now=datetime.now(timezone.utc),
            )
        except TlsRuntimeIdentityError as error:
            raise DeploymentError("internal TLS identity preflight failed") from error

        try:
            validate_vault_token_sinks(PRODUCTION_ENV_FILE, PRODUCTION_COMPOSE)
        except VaultTokenSinkError:
            raise DeploymentError(
                "production Vault token sink preflight failed"
            ) from None
        evidence.check("vault_sink_checks_passed", 1)

        try:
            environment = plan.compose_environment()
        except ComposeEnvironmentError as error:
            raise DeploymentError(
                "production Compose environment preflight failed"
            ) from error
        except RollbackError as error:
            raise DeploymentError(
                "third-party image digest preflight failed"
            ) from error
        _record_third_party_images(evidence, environment)
        command_runner = runner or SubprocessRunner()

        try:
            _assert_release_checkout(
                plan.commit,
                runner=command_runner,
                environment=environment,
                shell_environment=os.environ,
            )
        except RollbackError as error:
            raise DeploymentError("release checkout preflight failed") from error

        try:
            rollback_environment = plan.rollback.compose_environment()
            _assert_operational_services(command_runner, rollback_environment)
            evidence.check("operational_checks_passed", 1)
            _verify_supply_chain(plan.rollback, command_runner, rollback_environment)
            for service, image_name in RUNTIME_IMAGE_SERVICES.items():
                _assert_runtime_image(
                    service,
                    plan.rollback.images[image_name],
                    runner=command_runner,
                    environment=rollback_environment,
                )
            evidence.check("rollback_readiness_verified", True)
        except (OSError, subprocess.SubprocessError, RollbackError) as error:
            raise DeploymentError("rollback readiness preflight failed") from error

        try:
            scan_third_party_images(environment, command_runner)
            evidence.check("upstream_images_scanned", True)
        except (OSError, subprocess.SubprocessError, ThirdPartyScanError) as error:
            raise DeploymentError("upstream image scan preflight failed") from error

        try:
            _verify_supply_chain(plan, command_runner, environment)
            evidence.check("target_supply_chain_verified", True)
            _pull_images(plan, command_runner, environment)
            evidence.check("images_pulled", True)
        except (OSError, subprocess.SubprocessError, RollbackError) as error:
            raise DeploymentError("deployment preflight failed") from error
        evidence.phase("PREFLIGHTED")

        mutation_attempted = True
        edge_may_be_open = True
        deployment_succeeded = False
        try:
            command_runner.run(_compose("stop", "edge"), env=environment)
            evidence.edge_stop_confirmed()
            edge_may_be_open = False
            evidence.phase("EDGE_STOPPED")
            command_runner.run(
                _compose(
                    "up",
                    "-d",
                    "--no-build",
                    "--pull",
                    "never",
                    "--force-recreate",
                    *BACKEND_SERVICES,
                ),
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
            evidence.phase("BACKENDS_STARTED")
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
                raise DeploymentError(
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
            deployment_succeeded = True
        finally:
            if not deployment_succeeded and (
                evidence.payload["edge"]["stop_confirmations"] == 0
                or edge_may_be_open
            ):
                closure_unconfirmed = not _stop_edge_for_failure(
                    command_runner, environment, evidence
                )
        evidence.outcome(TERMINAL_SUCCEEDED)
    except BaseException as execution_error:
        evidence.outcome(
            TERMINAL_EDGE_UNCONFIRMED
            if closure_unconfirmed
            else (
                TERMINAL_EDGE_CLOSED_FAILURE
                if mutation_attempted
                else TERMINAL_PREFLIGHT_FAILED
            )
        )
        publication_error: DeploymentError | None = None
        try:
            _publish_evidence(evidence, evidence_output)
        except DeploymentError as error:
            publication_error = error
        if not isinstance(execution_error, Exception):
            raise
        if closure_unconfirmed:
            raise DeploymentError(
                "deployment failed and public edge closure could not be confirmed"
            ) from execution_error
        if publication_error is not None:
            raise publication_error from execution_error
        if isinstance(execution_error, DeploymentError):
            raise
        if mutation_attempted:
            raise DeploymentError(
                "deployment failed with public edge closed"
            ) from None
        raise DeploymentError("deployment preflight failed") from None

    try:
        _publish_evidence(evidence, evidence_output)
    except DeploymentError as publication_error:
        if command_runner is None or environment is None or not _stop_edge_for_failure(
            command_runner, environment, evidence
        ):
            raise DeploymentError(
                "deployment evidence publication failed and public edge closure could not be confirmed"
            ) from publication_error
        raise DeploymentError(
            "deployment evidence publication failed; public edge was closed"
        ) from publication_error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan_parser = subparsers.add_parser("plan")
    execute_parser = subparsers.add_parser("execute")
    for command in (plan_parser, execute_parser):
        command.add_argument("--container-manifest", type=Path, required=True)
        command.add_argument(
            "--rollback-container-manifest", type=Path, required=True
        )
        command.add_argument("--rollback-backup-dir", type=Path, required=True)
        command.add_argument(
            "--rollback-redis-backup-dir", type=Path, required=True
        )
        command.add_argument("--rollback-recovery-set", required=True)
        command.add_argument("--rollback-key-file", type=Path, required=True)
    execute_parser.add_argument("--container-manifest-sha256", required=True)
    execute_parser.add_argument("--confirm-release-tag", required=True)
    execute_parser.add_argument("--domain", required=True)
    execute_parser.add_argument("--evidence-output", type=Path, required=True)
    execute_parser.add_argument("--target-intake-manifest", type=Path, required=True)
    execute_parser.add_argument("--target-environment", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        plan = load_deployment_plan(
            args.container_manifest,
            rollback_container_manifest_path=args.rollback_container_manifest,
            rollback_backup_dir=args.rollback_backup_dir,
            rollback_redis_backup_dir=args.rollback_redis_backup_dir,
            rollback_recovery_set=args.rollback_recovery_set,
            rollback_key_file=args.rollback_key_file,
        )
        if args.command == "plan":
            import json

            print(json.dumps(plan_summary(plan), indent=2, sort_keys=True))
            return 0
        execute_deployment(
            plan,
            confirm_release_tag=args.confirm_release_tag,
            container_manifest_sha256=args.container_manifest_sha256,
            domain=args.domain,
            evidence_output=args.evidence_output,
            target_intake_manifest=args.target_intake_manifest,
            target_environment=args.target_environment,
        )
        print("deploy-release-ok")
        return 0
    except (DeploymentError, ValueError, OSError, subprocess.SubprocessError):
        print("deploy-release-failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
