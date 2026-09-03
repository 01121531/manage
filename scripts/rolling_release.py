"""Switch Web/API releases between two digest-bound slots behind a stable edge."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Mapping, Sequence

from scripts.deploy_release import DeploymentPlan, load_deployment_plan
from scripts.external_json import read_stable_bytes_with_metadata
from scripts.release_control_lock import ReleaseControlLocked, release_control_lock
from scripts.rolling_release_evidence import (
    RollingReleaseEvidenceError,
    RollingReleaseEvidenceRecorder,
    TERMINAL_COMPLETE,
    TERMINAL_PRE_SWITCH_FAILED,
    TERMINAL_ROUTE_UNCONFIRMED,
    TERMINAL_SWITCHED_BACK,
    prepare_evidence_output,
    sha256_bytes,
)
from scripts.rollback_release import (
    PRODUCTION_COMPOSE,
    PRODUCTION_ENV_FILE,
    PRODUCTION_PROJECT_NAME,
    ROOT,
    ComposeEnvironmentError,
    RollbackError,
    Runner,
    SubprocessRunner,
    _assert_release_checkout,
    _pull_images,
    _validate_execution_inputs,
    _validated_third_party_image_environment,
    _verify_supply_chain,
)
from scripts.scan_third_party_images import ThirdPartyScanError, scan_third_party_images
from scripts.target_intake_preflight import PhaseCheckpointIdentity, load_phase_checkpoint
from scripts.tls_runtime_identity import (
    TLS_HTTP_PROBE_PROGRAM,
    TlsRuntimeIdentityError,
    expected_internal_fingerprints,
    parse_tls_probe_observation,
    probe_arguments,
    tls_probe_contract_errors,
)
from scripts.validate_edge_tls import EdgeTlsError, validate_edge_tls
from scripts.vault_token_sinks import VaultTokenSinkError, validate_vault_token_sinks
from scripts.sub2_egress_preflight import (
    Sub2EgressPreflightError,
    validate_sub2_egress_policy,
)


ROLLING_COMPOSE = ROOT / "docker-compose.rolling.yml"
SLOT_DIR = ROOT / "infra" / "nginx" / "slots"
STATE_NAME = "rolling-release-state.json"
ROUTE_NAME = "active-slot.conf"
MAX_ROUTE_BYTES = 16 * 1024
SLOTS = ("blue", "green")
FORBIDDEN_ROLLING_ENV = (
    "PLATFORM_ROLLING_MIGRATION_IMAGE",
    "PLATFORM_ROLLING_GREEN_API_IMAGE",
    "PLATFORM_ROLLING_GREEN_WEB_IMAGE",
    "PLATFORM_ROLLING_WORKER_MAIL_IMAGE",
    "PLATFORM_ROLLING_WORKER_SUB2_IMAGE",
    "PLATFORM_ROLLING_GREEN_RELEASE_TAG",
    "PLATFORM_ROLLING_GREEN_RELEASE_COMMIT",
    "PLATFORM_ROLLING_GREEN_MIGRATION_HEAD",
    "PLATFORM_ROLLING_ROUTE_DIR",
)


class RollingReleaseError(RuntimeError):
    """A rolling-release invariant or recovery operation failed."""


@dataclass(frozen=True)
class _RouteSnapshot:
    content: bytes
    mode: int


@dataclass(frozen=True)
class RollingPlan:
    deployment: DeploymentPlan
    active_slot: str
    route_dir: Path

    @property
    def target_slot(self) -> str:
        return "green" if self.active_slot == "blue" else "blue"

    @property
    def source(self):
        return self.deployment.rollback

    def fingerprint(self, domain: str) -> str:
        payload = "\n".join(
            (
                self.deployment.container_manifest_sha256,
                self.source.container_manifest_sha256,
                self.active_slot,
                domain.lower(),
            )
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def compose_environment(self) -> dict[str, str]:
        if any(name in os.environ for name in FORBIDDEN_ROLLING_ENV):
            raise ComposeEnvironmentError("rolling Compose environment preflight failed")
        environment = _validated_third_party_image_environment(os.environ)
        blue = self.source if self.active_slot == "blue" else self.deployment
        green = self.deployment if self.active_slot == "blue" else self.source
        environment.update(
            {
                "PLATFORM_API_IMAGE": blue.images["api"],
                "PLATFORM_WEB_IMAGE": blue.images["web"],
                "PLATFORM_EDGE_IMAGE": self.source.images["edge"],
                "PLATFORM_RELEASE_TAG": blue.tag,
                "PLATFORM_RELEASE_COMMIT": blue.commit,
                "PLATFORM_RELEASE_MIGRATION_HEAD": blue.migration_head,
                "PLATFORM_ROLLING_MIGRATION_IMAGE": self.deployment.images["api"],
                "PLATFORM_ROLLING_GREEN_API_IMAGE": green.images["api"],
                "PLATFORM_ROLLING_GREEN_WEB_IMAGE": green.images["web"],
                "PLATFORM_ROLLING_WORKER_MAIL_IMAGE": self.source.images["api"],
                "PLATFORM_ROLLING_WORKER_SUB2_IMAGE": self.source.images["api"],
                "PLATFORM_ROLLING_GREEN_RELEASE_TAG": green.tag,
                "PLATFORM_ROLLING_GREEN_RELEASE_COMMIT": green.commit,
                "PLATFORM_ROLLING_GREEN_MIGRATION_HEAD": green.migration_head,
                "PLATFORM_ROLLING_ROUTE_DIR": str(self.route_dir),
            }
        )
        return environment


def _read_route_snapshot(path: Path) -> _RouteSnapshot:
    try:
        content, metadata = read_stable_bytes_with_metadata(
            path,
            max_bytes=MAX_ROUTE_BYTES,
        )
    except OSError as error:
        raise RollingReleaseError("rolling route file cannot be read safely") from error
    mode = stat.S_IMODE(metadata.st_mode)
    if os.name != "nt" and mode & 0o022:
        raise RollingReleaseError("rolling route file must not be group/world writable")
    return _RouteSnapshot(content=content, mode=mode)


def _canonical_route(slot: str) -> bytes:
    if slot not in SLOTS:
        raise RollingReleaseError("release slot must be blue or green")
    return _read_route_snapshot(SLOT_DIR / f"{slot}.conf").content


def _route_matches(path: Path, slot: str) -> bool:
    try:
        return hmac.compare_digest(
            _read_route_snapshot(path).content,
            _canonical_route(slot),
        )
    except RollingReleaseError:
        return False


def _validate_route_dir(path: Path, active_slot: str) -> Path:
    if not path.is_absolute():
        raise RollingReleaseError("rolling route directory must be absolute")
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        pass
    else:
        raise RollingReleaseError("rolling route directory must be outside the repository")
    information = resolved.stat()
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(information, "st_file_attributes", 0)
    if not resolved.is_dir() or resolved.is_symlink() or attributes & reparse:
        raise RollingReleaseError("rolling route directory must be a real directory")
    if os.name != "nt" and stat.S_IMODE(information.st_mode) & 0o022:
        raise RollingReleaseError("rolling route directory must not be group/world writable")
    route = resolved / ROUTE_NAME
    route_snapshot = _read_route_snapshot(route)
    if not hmac.compare_digest(route_snapshot.content, _canonical_route(active_slot)):
        raise RollingReleaseError("active rolling route does not match the declared slot")
    return resolved


def load_rolling_plan(
    container_manifest_path: Path,
    *,
    current_container_manifest_path: Path,
    rollback_backup_dir: Path,
    rollback_redis_backup_dir: Path,
    rollback_recovery_set: str,
    rollback_key_file: Path,
    active_slot: str,
    route_dir: Path,
    now=None,
) -> RollingPlan:
    try:
        deployment = load_deployment_plan(
            container_manifest_path,
            rollback_container_manifest_path=current_container_manifest_path,
            rollback_backup_dir=rollback_backup_dir,
            rollback_redis_backup_dir=rollback_redis_backup_dir,
            rollback_recovery_set=rollback_recovery_set,
            rollback_key_file=rollback_key_file,
            now=now,
        )
    except Exception as error:
        raise RollingReleaseError("rolling release manifests or recovery set are invalid") from error
    if active_slot not in SLOTS:
        raise RollingReleaseError("release slot must be blue or green")
    if deployment.images["edge"] != deployment.rollback.images["edge"]:
        raise RollingReleaseError("rolling Web/API release requires an unchanged edge digest")
    if deployment.images["api"] != deployment.rollback.images["api"]:
        raise RollingReleaseError(
            "rolling release requires an unchanged API/worker digest; "
            "use the single-instance worker-drain release path"
        )
    resolved_route_dir = _validate_route_dir(route_dir, active_slot)
    return RollingPlan(deployment, active_slot, resolved_route_dir)


def plan_summary(plan: RollingPlan) -> dict[str, object]:
    return {
        "release_strategy": "web-api-blue-green",
        "rolling_release": True,
        "production_acceptance": False,
        "source_retained_after_switch": True,
        "source_slot": plan.active_slot,
        "target_slot": plan.target_slot,
        "source_release_tag": plan.source.tag,
        "target_release_tag": plan.deployment.tag,
        "target_release_commit": plan.deployment.commit,
        "target_migration_head": plan.deployment.migration_head,
        "target_container_manifest_sha256": plan.deployment.container_manifest_sha256,
        "edge_digest_unchanged": True,
        "worker_release_strategy": "unchanged-single-instance",
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
        "-f",
        str(ROLLING_COMPOSE),
        command,
        *arguments,
    ]


def _service_pair(slot: str) -> tuple[str, str]:
    return ("api", "web") if slot == "blue" else ("api-green", "web-green")


def _assert_running(runner: Runner, environment: Mapping[str, str], services: Sequence[str]) -> None:
    output = runner.run(
        _compose("ps", "--status", "running", "--services"),
        env=environment,
        capture_output=True,
    )
    running = set(output.splitlines())
    if any(service not in running for service in services):
        raise RollingReleaseError("required rolling services are not running")


def _assert_edge_route_mount(
    plan: RollingPlan,
    runner: Runner,
    environment: Mapping[str, str],
) -> None:
    container_id = runner.run(
        _compose("ps", "-q", "edge"), env=environment, capture_output=True
    ).strip()
    if not container_id or "\n" in container_id:
        raise RollingReleaseError("edge rolling route mount is invalid")
    try:
        raw_mounts = runner.run(
            ["docker", "inspect", "--format", "{{json .Mounts}}", container_id],
            env=environment,
            capture_output=True,
        )
        mounts = json.loads(raw_mounts)
        route_mounts = [
            mount
            for mount in mounts
            if isinstance(mount, dict)
            and mount.get("Destination") == "/etc/nginx/edge-routing"
        ]
        mount = route_mounts[0]
        source = mount.get("Source")
        if (
            not isinstance(mounts, list)
            or len(route_mounts) != 1
            or mount.get("Type") != "bind"
            or mount.get("RW") is not False
            or not isinstance(source, str)
            or Path(source).resolve(strict=True) != plan.route_dir.resolve(strict=True)
        ):
            raise ValueError("invalid route mount")
    except (IndexError, json.JSONDecodeError, OSError, TypeError, ValueError) as error:
        raise RollingReleaseError("edge rolling route mount is invalid") from error


def _assert_runtime_image(
    service: str,
    expected: str,
    runner: Runner,
    environment: Mapping[str, str],
) -> str:
    container_id = runner.run(
        _compose("ps", "-q", service), env=environment, capture_output=True
    ).strip()
    if not container_id or "\n" in container_id:
        raise RollingReleaseError("rolling service identity is ambiguous")
    observed = runner.run(
        ["docker", "inspect", "--format", "{{.Config.Image}}", container_id],
        env=environment,
        capture_output=True,
    ).strip()
    if not hmac.compare_digest(observed, expected):
        raise RollingReleaseError("rolling service image digest does not match the manifest")
    return observed


def _record_workers(
    plan: RollingPlan,
    moment: str,
    runner: Runner,
    environment: Mapping[str, str],
    evidence: RollingReleaseEvidenceRecorder,
) -> None:
    for service, evidence_name in (
        ("worker-mail", "worker_mail"),
        ("worker-sub2", "worker_sub2"),
    ):
        observed = _assert_runtime_image(
            service, plan.source.images["api"], runner, environment
        )
        evidence.worker(moment, evidence_name, observed)


def _probe_slot(
    plan: RollingPlan,
    slot: str,
    runner: Runner,
    environment: Mapping[str, str],
    expected_fingerprints: Mapping[str, str],
    evidence: RollingReleaseEvidenceRecorder,
) -> None:
    if tls_probe_contract_errors():
        raise RollingReleaseError("rolling TLS probe contract is invalid")
    release = plan.source if slot == plan.active_slot else plan.deployment
    api, web = _service_pair(slot)
    release_role = "source" if slot == plan.active_slot else "target"
    expected_body = {
        "service": "email-platform",
        "tag": release.tag,
        "commit": release.commit,
        "migration_head": release.migration_head,
        "slot": slot,
    }
    api_output = runner.run(
        _compose(
            "exec", "-T", api, "python", "-c", TLS_HTTP_PROBE_PROGRAM,
            *probe_arguments(
                f"https://{api}:8443/releasez",
                ca_file="/run/secrets/internal-tls/ca.crt",
                max_body_bytes=4096,
                content_type="application/json",
                expected_json=expected_body,
            ),
        ),
        env=environment,
        capture_output=True,
    )
    web_output = runner.run(
        _compose(
            "exec", "-T", api, "python", "-c", TLS_HTTP_PROBE_PROGRAM,
            *probe_arguments(
                f"https://{web}:8443/healthz",
                ca_file="/run/secrets/internal-tls/ca.crt",
                max_body_bytes=1024 * 1024,
                require_nonempty=True,
            ),
        ),
        env=environment,
        capture_output=True,
    )
    try:
        api_observation = parse_tls_probe_observation(
            api_output,
            expected_sha256=expected_fingerprints[api],
        )
        web_observation = parse_tls_probe_observation(
            web_output,
            expected_sha256=expected_fingerprints[web],
        )
    except (KeyError, TlsRuntimeIdentityError) as error:
        raise RollingReleaseError("rolling internal TLS peer identity is invalid") from error
    evidence.internal_tls(release_role, "api", slot, api_observation)
    evidence.internal_tls(release_role, "web", slot, web_observation)


def _external_probe(
    release,
    slot: str,
    domain: str,
    runner: Runner,
    environment: Mapping[str, str],
    evidence: RollingReleaseEvidenceRecorder,
    release_role: str,
    expected_fingerprint: str,
) -> None:
    identity = {
        "slot": slot,
        "tag": release.tag,
        "commit": release.commit,
        "migration_head": release.migration_head,
    }
    for attempt in range(1, 4):
        try:
            output = runner.run(
                [
                    sys.executable, "-c", TLS_HTTP_PROBE_PROGRAM,
                    *probe_arguments(
                        f"https://{domain}/releasez",
                        ca_file=None,
                        max_body_bytes=4096,
                        content_type="application/json",
                        expected_json={"service": "email-platform", **identity},
                    ),
                ],
                env=environment,
                capture_output=True,
            )
        except (OSError, subprocess.SubprocessError):
            evidence.public_releasez(
                release_role=release_role,
                attempt=attempt,
                release=identity,
                result="failed",
                expected_sha256=expected_fingerprint,
            )
            raise
        try:
            observation = parse_tls_probe_observation(
                output,
                expected_sha256=expected_fingerprint,
            )
        except TlsRuntimeIdentityError as error:
            evidence.public_releasez(
                release_role=release_role,
                attempt=attempt,
                release=identity,
                result="failed",
                expected_sha256=expected_fingerprint,
            )
            raise RollingReleaseError("public TLS peer identity is invalid") from error
        evidence.public_releasez(
            release_role=release_role,
            attempt=attempt,
            release=identity,
            result="passed",
            expected_sha256=expected_fingerprint,
            observation=observation,
        )


def _atomic_write(path: Path, content: bytes, *, mode: int = 0o600) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.fchmod(descriptor, mode)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        if os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _write_state(plan: RollingPlan, domain: str, phase: str, error_code: str | None = None) -> None:
    state = {
        "schema_version": 1,
        "plan_fingerprint": plan.fingerprint(domain),
        "source_slot": plan.active_slot,
        "target_slot": plan.target_slot,
        "source_release_tag": plan.source.tag,
        "target_release_tag": plan.deployment.tag,
        "phase": phase,
        "last_error_code": error_code,
        "production_acceptance": False,
    }
    _atomic_write(
        plan.route_dir / STATE_NAME,
        (json.dumps(state, sort_keys=True) + "\n").encode("utf-8"),
    )


def _evidence_release(release, slot: str) -> dict[str, str]:
    return {
        "slot": slot,
        "tag": release.tag,
        "commit": release.commit,
        "migration_head": release.migration_head,
        "container_manifest_sha256": release.container_manifest_sha256,
    }


def _new_evidence(
    plan: RollingPlan,
    domain: str,
    checkpoint: PhaseCheckpointIdentity,
) -> RollingReleaseEvidenceRecorder:
    route_before = _read_route_snapshot(plan.route_dir / ROUTE_NAME).content
    return RollingReleaseEvidenceRecorder(
        plan_fingerprint=plan.fingerprint(domain),
        source=_evidence_release(plan.source, plan.active_slot),
        target=_evidence_release(plan.deployment, plan.target_slot),
        source_images=plan.source.images,
        target_images=plan.deployment.images,
        expected_worker_digest=plan.source.images["api"],
        route_before_sha256=sha256_bytes(route_before),
        source_route_sha256=sha256_bytes(_canonical_route(plan.active_slot)),
        target_route_sha256=sha256_bytes(_canonical_route(plan.target_slot)),
        target_intake=checkpoint.as_evidence(),
        started_at=checkpoint.evaluated_at,
    )


def _publish_evidence(
    plan: RollingPlan,
    evidence: RollingReleaseEvidenceRecorder,
    evidence_output: Path,
) -> None:
    try:
        route_after = sha256_bytes(
            _read_route_snapshot(plan.route_dir / ROUTE_NAME).content
        )
    except RollingReleaseError:
        route_after = None
    try:
        evidence.write(evidence_output, route_after)
    except (OSError, RollingReleaseEvidenceError) as error:
        raise RollingReleaseError("rolling release evidence publication failed") from error


def _reload_edge(
    runner: Runner,
    environment: Mapping[str, str],
    evidence: RollingReleaseEvidenceRecorder,
    slot: str,
) -> None:
    try:
        runner.run(
            _compose("exec", "-T", "edge", "nginx", "-t", "-q"),
            env=environment,
        )
    except (OSError, subprocess.SubprocessError):
        evidence.nginx("test", slot, "failed")
        raise
    evidence.nginx("test", slot, "passed")
    try:
        runner.run(
            _compose("exec", "-T", "edge", "nginx", "-s", "reload"),
            env=environment,
        )
    except (OSError, subprocess.SubprocessError):
        evidence.nginx("reload", slot, "failed")
        raise
    evidence.nginx("reload", slot, "passed")


def _switch_route(
    plan: RollingPlan,
    slot: str,
    runner: Runner,
    environment: Mapping[str, str],
    evidence: RollingReleaseEvidenceRecorder,
) -> None:
    route_path = plan.route_dir / ROUTE_NAME
    previous = _read_route_snapshot(route_path)
    expected_previous_slot = (
        plan.active_slot if slot == plan.target_slot else plan.target_slot
    )
    if not hmac.compare_digest(
        previous.content,
        _canonical_route(expected_previous_slot),
    ):
        raise RollingReleaseError("active rolling route changed before switch")
    _atomic_write(route_path, _canonical_route(slot), mode=previous.mode)
    try:
        _reload_edge(runner, environment, evidence, slot)
    except (OSError, subprocess.SubprocessError):
        _atomic_write(route_path, previous.content, mode=previous.mode)
        try:
            _reload_edge(runner, environment, evidence, plan.active_slot)
        except (OSError, subprocess.SubprocessError) as recovery_error:
            evidence.outcome(TERMINAL_ROUTE_UNCONFIRMED)
            raise RollingReleaseError("route recovery could not be confirmed") from recovery_error
        raise RollingReleaseError("edge route switch failed and was restored") from None


def _execute_locked(
    plan: RollingPlan,
    *,
    confirm_release_tag: str,
    container_manifest_sha256: str,
    domain: str,
    runner: Runner | None,
    evidence: RollingReleaseEvidenceRecorder,
) -> None:
    _validate_route_dir(plan.route_dir, plan.active_slot)
    if confirm_release_tag != plan.deployment.tag:
        raise RollingReleaseError("release confirmation does not match rolling plan")
    if not hmac.compare_digest(
        container_manifest_sha256.lower(), plan.deployment.container_manifest_sha256
    ):
        raise RollingReleaseError("container manifest SHA-256 does not match rolling plan")
    try:
        _validate_execution_inputs(
            platform_target_db="email_platform", keycloak_target_db="keycloak", domain=domain
        )
        edge_fingerprint = validate_edge_tls(PRODUCTION_ENV_FILE, domain)
        internal_fingerprints = expected_internal_fingerprints(
            PRODUCTION_ENV_FILE,
            now=datetime.now(timezone.utc),
        )
        validate_vault_token_sinks(PRODUCTION_ENV_FILE, PRODUCTION_COMPOSE)
        validate_sub2_egress_policy(PRODUCTION_ENV_FILE)
        environment = plan.compose_environment()
    except (
        RollbackError,
        EdgeTlsError,
        VaultTokenSinkError,
        ComposeEnvironmentError,
        Sub2EgressPreflightError,
        TlsRuntimeIdentityError,
    ) as error:
        raise RollingReleaseError("rolling release preflight failed") from error
    command_runner = runner or SubprocessRunner()
    stable = ("postgres", "redis", "keycloak", "worker-mail", "worker-sub2", "edge")
    source_api, source_web = _service_pair(plan.active_slot)
    target_api, target_web = _service_pair(plan.target_slot)
    route_path = plan.route_dir / ROUTE_NAME
    candidate_started = False
    try:
        _assert_release_checkout(
            plan.deployment.commit,
            runner=command_runner,
            environment=environment,
            shell_environment=os.environ,
        )
        _assert_running(command_runner, environment, (*stable, source_api, source_web))
        _assert_edge_route_mount(plan, command_runner, environment)
        _assert_runtime_image(source_api, plan.source.images["api"], command_runner, environment)
        _assert_runtime_image(source_web, plan.source.images["web"], command_runner, environment)
        _record_workers(plan, "before", command_runner, environment, evidence)
        _assert_runtime_image("edge", plan.source.images["edge"], command_runner, environment)
        _probe_slot(
            plan,
            plan.active_slot,
            command_runner,
            environment,
            internal_fingerprints,
            evidence,
        )
        _verify_supply_chain(plan.source, command_runner, environment)
        scan_third_party_images(environment, command_runner)
        _verify_supply_chain(plan.deployment, command_runner, environment)
        _pull_images(plan.deployment, command_runner, environment)
        command_runner.run(
            [sys.executable, str(ROOT / "scripts" / "verify_migration_compatibility.py")],
            env=environment,
        )
        candidate_started = True
        _write_state(plan, domain, "PREFLIGHTED")
        evidence.phase("PREFLIGHTED")
        command_runner.run(
            _compose("run", "--rm", "--no-deps", "migrate"), env=environment
        )
        _write_state(plan, domain, "SCHEMA_EXPANDED")
        evidence.phase("SCHEMA_EXPANDED")
        command_runner.run(
            _compose(
                "up", "-d", "--no-deps", "--no-build", "--pull", "never", "--force-recreate",
                target_api, target_web,
            ),
            env=environment,
        )
        _assert_running(command_runner, environment, (target_api, target_web))
        _assert_runtime_image(target_api, plan.deployment.images["api"], command_runner, environment)
        _assert_runtime_image(target_web, plan.deployment.images["web"], command_runner, environment)
        _probe_slot(
            plan,
            plan.target_slot,
            command_runner,
            environment,
            internal_fingerprints,
            evidence,
        )
        _write_state(plan, domain, "INACTIVE_VERIFIED")
        evidence.phase("INACTIVE_VERIFIED")
        _switch_route(plan, plan.target_slot, command_runner, environment, evidence)
        _write_state(plan, domain, "TRAFFIC_SWITCHED")
        evidence.phase("TRAFFIC_SWITCHED")
        try:
            _external_probe(
                plan.deployment,
                plan.target_slot,
                domain,
                command_runner,
                environment,
                evidence,
                "target",
                edge_fingerprint,
            )
        except (OSError, subprocess.SubprocessError, RollingReleaseError):
            _switch_route(
                plan, plan.active_slot, command_runner, environment, evidence
            )
            try:
                _external_probe(
                    plan.source,
                    plan.active_slot,
                    domain,
                    command_runner,
                    environment,
                    evidence,
                    "source",
                    edge_fingerprint,
                )
            except (OSError, subprocess.SubprocessError, RollingReleaseError) as recovery_error:
                try:
                    _record_workers(plan, "after", command_runner, environment, evidence)
                except RollingReleaseError:
                    pass
                _write_state(plan, domain, "ROUTE_UNCONFIRMED", "route_unconfirmed")
                evidence.outcome(TERMINAL_ROUTE_UNCONFIRMED)
                raise RollingReleaseError("route recovery could not be confirmed") from recovery_error
            _record_workers(plan, "after", command_runner, environment, evidence)
            command_runner.run(
                _compose("stop", target_api, target_web), env=environment
            )
            candidate_started = False
            _write_state(plan, domain, "SWITCHED_BACK", "target_observation_failed")
            evidence.outcome(TERMINAL_SWITCHED_BACK)
            raise RollingReleaseError("target observation failed and source was restored") from None
        _record_workers(plan, "after", command_runner, environment, evidence)
        _write_state(plan, domain, "COMPLETE_SOURCE_RETAINED")
        evidence.outcome(TERMINAL_COMPLETE)
    except RollingReleaseError as error:
        if evidence.payload["workers"]["before"]["worker_mail"] is not None:
            try:
                _record_workers(plan, "after", command_runner, environment, evidence)
            except RollingReleaseError:
                pass
        if (
            candidate_started
            and "recovery could not be confirmed" not in str(error)
            and _route_matches(route_path, plan.active_slot)
        ):
            try:
                command_runner.run(
                    _compose("stop", target_api, target_web), env=environment
                )
            except (OSError, subprocess.SubprocessError):
                pass
            _write_state(plan, domain, "FAILED", "rolling_execution_failed")
        if evidence.payload["terminal_state"] == TERMINAL_PRE_SWITCH_FAILED:
            traffic_switched = any(
                item["phase"] == "TRAFFIC_SWITCHED"
                for item in evidence.payload["phases"]
            )
            if traffic_switched:
                _write_state(plan, domain, "ROUTE_UNCONFIRMED", "route_unconfirmed")
                evidence.outcome(TERMINAL_ROUTE_UNCONFIRMED)
            else:
                evidence.outcome(TERMINAL_PRE_SWITCH_FAILED)
        raise
    except (OSError, subprocess.SubprocessError, RollbackError, ThirdPartyScanError) as error:
        if evidence.payload["workers"]["before"]["worker_mail"] is not None:
            try:
                _record_workers(plan, "after", command_runner, environment, evidence)
            except RollingReleaseError:
                pass
        if candidate_started and _route_matches(route_path, plan.active_slot):
            try:
                command_runner.run(_compose("stop", target_api, target_web), env=environment)
            except (OSError, subprocess.SubprocessError):
                pass
        traffic_switched = any(
            item["phase"] == "TRAFFIC_SWITCHED" for item in evidence.payload["phases"]
        )
        if traffic_switched:
            _write_state(plan, domain, "ROUTE_UNCONFIRMED", "route_unconfirmed")
            evidence.outcome(TERMINAL_ROUTE_UNCONFIRMED)
        else:
            _write_state(plan, domain, "FAILED", "rolling_execution_failed")
            evidence.outcome(TERMINAL_PRE_SWITCH_FAILED)
        raise RollingReleaseError("rolling release execution failed") from error


def execute_rolling_release(
    plan: RollingPlan,
    *,
    confirm_release_tag: str,
    container_manifest_sha256: str,
    domain: str,
    evidence_output: Path,
    target_intake_manifest: Path,
    target_environment: str,
    runner: Runner | None = None,
) -> None:
    release_started_at = datetime.now(timezone.utc)
    try:
        checkpoint = load_phase_checkpoint(
            target_intake_manifest,
            environment=target_environment,
            through_phase=0,
            evaluated_at=release_started_at,
        )
    except ValueError:
        raise RollingReleaseError("target intake Phase 0 preflight failed")
    try:
        prepare_evidence_output(evidence_output)
        evidence = _new_evidence(plan, domain, checkpoint)
    except (OSError, RollingReleaseError, RollingReleaseEvidenceError) as error:
        raise RollingReleaseError("rolling release evidence preflight failed") from error
    try:
        with release_control_lock():
            _execute_locked(
                plan,
                confirm_release_tag=confirm_release_tag,
                container_manifest_sha256=container_manifest_sha256,
                domain=domain,
                runner=runner,
                evidence=evidence,
            )
    except ReleaseControlLocked as error:
        evidence.outcome(TERMINAL_PRE_SWITCH_FAILED)
        _publish_evidence(plan, evidence, evidence_output)
        raise RollingReleaseError("another release control operation is active") from error
    except RollingReleaseError:
        if evidence.payload["phases"][-1]["phase"] not in {
            "SWITCHED_BACK",
            "ROUTE_UNCONFIRMED",
            "PRE_SWITCH_FAILED",
        }:
            evidence.outcome(TERMINAL_PRE_SWITCH_FAILED)
        _publish_evidence(plan, evidence, evidence_output)
        raise
    _publish_evidence(plan, evidence, evidence_output)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "execute"):
        command = subparsers.add_parser(name)
        command.add_argument("--container-manifest", type=Path, required=True)
        command.add_argument("--current-container-manifest", type=Path, required=True)
        command.add_argument("--rollback-backup-dir", type=Path, required=True)
        command.add_argument("--rollback-redis-backup-dir", type=Path, required=True)
        command.add_argument("--rollback-recovery-set", required=True)
        command.add_argument("--rollback-key-file", type=Path, required=True)
        command.add_argument("--active-slot", choices=SLOTS, required=True)
        command.add_argument("--route-dir", type=Path, required=True)
        if name == "execute":
            command.add_argument("--confirm-release-tag", required=True)
            command.add_argument("--container-manifest-sha256", required=True)
            command.add_argument("--domain", required=True)
            command.add_argument("--evidence-output", type=Path, required=True)
            command.add_argument("--target-intake-manifest", type=Path, required=True)
            command.add_argument("--target-environment", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        plan = load_rolling_plan(
            args.container_manifest,
            current_container_manifest_path=args.current_container_manifest,
            rollback_backup_dir=args.rollback_backup_dir,
            rollback_redis_backup_dir=args.rollback_redis_backup_dir,
            rollback_recovery_set=args.rollback_recovery_set,
            rollback_key_file=args.rollback_key_file,
            active_slot=args.active_slot,
            route_dir=args.route_dir,
        )
        if args.command == "plan":
            print(json.dumps(plan_summary(plan), indent=2, sort_keys=True))
            return 0
        execute_rolling_release(
            plan,
            confirm_release_tag=args.confirm_release_tag,
            container_manifest_sha256=args.container_manifest_sha256,
            domain=args.domain,
            evidence_output=args.evidence_output,
            target_intake_manifest=args.target_intake_manifest,
            target_environment=args.target_environment,
        )
        print("rolling-release-ok source-slot-retained")
        return 0
    except (RollingReleaseError, OSError, ValueError, subprocess.SubprocessError):
        print("rolling-release-failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
