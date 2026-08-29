from __future__ import annotations

from contextlib import nullcontext
from dataclasses import replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import rolling_release as rolling_release_module
from scripts.deploy_release import DeploymentPlan
from scripts.rollback_release import RollbackPlan
from scripts.rolling_release import (
    RollingPlan,
    RollingReleaseError,
    _canonical_route,
    execute_rolling_release,
    plan_summary,
)
from scripts.rolling_release_evidence import (
    RollingReleaseEvidenceError,
    TERMINAL_COMPLETE,
    TERMINAL_PRE_SWITCH_FAILED,
    TERMINAL_ROUTE_UNCONFIRMED,
    TERMINAL_SWITCHED_BACK,
    assert_expected_releases,
    main as evidence_main,
    validate_evidence,
    verify_evidence,
)
from scripts.target_intake_preflight import PhaseCheckpointIdentity
from scripts.tls_runtime_identity import TLS_HTTP_PROBE_PROGRAM


DIGEST_ENV = {
    "POSTGRES_IMAGE_SHA256": "1" * 64,
    "REDIS_IMAGE_SHA256": "2" * 64,
    "KEYCLOAK_IMAGE_SHA256": "3" * 64,
    "ALERTMANAGER_IMAGE_SHA256": "4" * 64,
    "PROMETHEUS_IMAGE_SHA256": "5" * 64,
}
DOMAIN = "platform.example.com"
TLS_FINGERPRINT = "e" * 64
TLS_FINGERPRINTS = {
    service: TLS_FINGERPRINT
    for service in ("api", "web", "api-green", "web-green")
}
TARGET_INTAKE = PhaseCheckpointIdentity(
    environment="staging",
    manifest_payload_sha256="9" * 64,
    requirements_sha256="8" * 64,
    checkpoint_phase=0,
    evaluated_at="2026-08-26T12:00:00.000000Z",
    valid_from="2026-08-26T10:00:00.000000Z",
    valid_until="2099-08-26T12:00:00.000000Z",
)


def _images(seed: int) -> dict[str, str]:
    return {
        name: f"ghcr.io/example/manage-{name}@sha256:{str(seed + index) * 64}"
        for index, name in enumerate(("api", "web", "edge"))
    }


def _plan(route_dir: Path, active_slot: str = "blue") -> RollingPlan:
    identities = {
        name: "https://github.com/example/manage/.github/workflows/release.yml@refs/tags/v1"
        for name in ("api", "web", "edge")
    }
    current_images = _images(4)
    target_images = _images(1)
    target_images["edge"] = current_images["edge"]
    current = RollbackPlan(
        tag="v1.0.0",
        commit="a" * 40,
        migration_head="0025_oidc_session_revocations",
        container_manifest_sha256="a" * 64,
        backup_created_at=datetime.now(timezone.utc),
        backup_dir=route_dir,
        postgres_manifest_path=route_dir / "manifest.json",
        postgres_manifest_sha256="b" * 64,
        redis_backup_created_at=datetime.now(timezone.utc),
        redis_backup_dir=route_dir,
        redis_manifest_sha256="d" * 64,
        recovery_set="fixture",
        key_file=route_dir / "key",
        images=current_images,
        signature_identities=identities,
        signature_issuer="https://token.actions.githubusercontent.com",
        repository="example/manage",
    )
    target = DeploymentPlan(
        tag="v1.1.0",
        commit="b" * 40,
        migration_head="0026_future_expand",
        container_manifest_sha256="c" * 64,
        images=target_images,
        signature_identities=identities,
        signature_issuer="https://token.actions.githubusercontent.com",
        repository="example/manage",
        rollback=current,
    )
    return RollingPlan(target, active_slot, route_dir)


class FakeRunner:
    def __init__(
        self,
        plan: RollingPlan,
        *,
        fail_external: bool = False,
        external_failures: int = 0,
        fail_reload_once: bool = False,
        edge_route_mount: dict[str, object] | None = None,
    ):
        self.plan = plan
        self.external_failures = external_failures or int(fail_external)
        self.fail_reload_once = fail_reload_once
        self.edge_route_mount = (
            {
                "Type": "bind",
                "Source": str(plan.route_dir.resolve()),
                "Destination": "/etc/nginx/edge-routing",
                "RW": False,
            }
            if edge_route_mount is None
            else edge_route_mount
        )
        self.calls: list[tuple[list[str], dict[str, str] | None]] = []
        self.tls_fingerprint = TLS_FINGERPRINT
        self.external_tls_mismatches = 0

    def run(self, command, *, env=None, capture_output=False):
        command = list(command)
        copied = dict(env) if env is not None else None
        self.calls.append((command, copied))
        rendered = " ".join(command)
        if self.fail_reload_once and rendered.endswith("nginx -s reload"):
            self.fail_reload_once = False
            raise subprocess.CalledProcessError(1, command)
        if self.external_failures and f"https://{DOMAIN}/releasez" in rendered:
            self.external_failures -= 1
            raise subprocess.CalledProcessError(1, command)
        if " ps --status running --services" in rendered:
            return "\n".join(
                (
                    "postgres", "redis", "keycloak", "worker-mail", "worker-sub2",
                    "edge", "api", "web", "api-green", "web-green",
                )
            ) + "\n"
        if " ps -q " in rendered:
            return command[-1] + "-id\n"
        if command[:4] == ["docker", "inspect", "--format", "{{.Config.Image}}"]:
            service = command[-1].removesuffix("-id")
            assert copied is not None
            variable = {
                "api": "PLATFORM_API_IMAGE",
                "web": "PLATFORM_WEB_IMAGE",
                "api-green": "PLATFORM_ROLLING_GREEN_API_IMAGE",
                "web-green": "PLATFORM_ROLLING_GREEN_WEB_IMAGE",
                "worker-mail": "PLATFORM_ROLLING_WORKER_MAIL_IMAGE",
                "worker-sub2": "PLATFORM_ROLLING_WORKER_SUB2_IMAGE",
                "edge": "PLATFORM_EDGE_IMAGE",
            }[service]
            return copied[variable] + "\n"
        if command[:4] == ["docker", "inspect", "--format", "{{json .Mounts}}"]:
            return json.dumps([self.edge_route_mount]) + "\n"
        if TLS_HTTP_PROBE_PROGRAM in command:
            fingerprint = self.tls_fingerprint
            if self.external_tls_mismatches and f"https://{DOMAIN}/releasez" in rendered:
                self.external_tls_mismatches -= 1
                fingerprint = "f" * 64
            return json.dumps(
                {
                    "peer_sha256": fingerprint,
                    "tls_version": "TLSv1.3",
                }
            )
        return ""


class RollingReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.route_dir = Path(temporary.name)
        (self.route_dir / "active-slot.conf").write_bytes(_canonical_route("blue"))
        self.plan = _plan(self.route_dir)
        self.evidence_output = self.route_dir / "rolling-release-evidence.json"
        self.target_intake_manifest = self.route_dir / "target-intake.json"
        environment = mock.patch.dict(os.environ, DIGEST_ENV, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

        patches = (
            mock.patch("scripts.rolling_release.release_control_lock", return_value=nullcontext()),
            mock.patch(
                "scripts.rolling_release.validate_edge_tls",
                return_value=TLS_FINGERPRINT,
            ),
            mock.patch(
                "scripts.rolling_release.expected_internal_fingerprints",
                return_value=TLS_FINGERPRINTS,
            ),
            mock.patch("scripts.rolling_release.validate_vault_token_sinks"),
            mock.patch("scripts.rolling_release._assert_release_checkout"),
            mock.patch("scripts.rolling_release._verify_supply_chain"),
            mock.patch("scripts.rolling_release._pull_images"),
            mock.patch("scripts.rolling_release.scan_third_party_images"),
        )
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        intake_patch = mock.patch("scripts.rolling_release.load_phase_checkpoint")
        self.intake_validator = intake_patch.start()
        self.addCleanup(intake_patch.stop)
        self.intake_validator.side_effect = lambda *args, evaluated_at, **kwargs: replace(
            TARGET_INTAKE,
            evaluated_at=evaluated_at.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
        )

    def execute(self, runner: FakeRunner) -> None:
        execute_rolling_release(
            self.plan,
            confirm_release_tag=self.plan.deployment.tag,
            container_manifest_sha256=self.plan.deployment.container_manifest_sha256,
            domain=DOMAIN,
            evidence_output=self.evidence_output,
            target_intake_manifest=self.target_intake_manifest,
            target_environment="staging",
            runner=runner,
        )

    def evidence(self) -> dict[str, object]:
        return verify_evidence(self.evidence_output)

    def test_plan_is_web_api_only_and_not_production_acceptance(self) -> None:
        summary = plan_summary(self.plan)
        self.assertTrue(summary["rolling_release"])
        self.assertFalse(summary["production_acceptance"])
        self.assertTrue(summary["source_retained_after_switch"])
        self.assertEqual(summary["worker_release_strategy"], "unchanged-single-instance")
        environment = self.plan.compose_environment()
        self.assertEqual(environment["PLATFORM_API_IMAGE"], self.plan.source.images["api"])
        self.assertEqual(
            environment["PLATFORM_ROLLING_GREEN_API_IMAGE"],
            self.plan.deployment.images["api"],
        )

    def test_plan_loader_rejects_new_api_with_unchanged_old_worker_binary(self) -> None:
        with mock.patch(
            "scripts.rolling_release.load_deployment_plan",
            return_value=self.plan.deployment,
        ):
            with self.assertRaisesRegex(
                RollingReleaseError,
                "unchanged API/worker digest",
            ):
                rolling_release_module.load_rolling_plan(
                    Path("target.json"),
                    current_container_manifest_path=Path("source.json"),
                    rollback_backup_dir=self.route_dir,
                    rollback_redis_backup_dir=self.route_dir,
                    rollback_recovery_set="fixture",
                    rollback_key_file=self.route_dir / "key",
                    active_slot="blue",
                    route_dir=self.route_dir,
                )

    def test_success_keeps_edge_and_source_running_and_switches_pair_atomically(self) -> None:
        runner = FakeRunner(self.plan)
        self.execute(runner)
        commands = [" ".join(command) for command, _ in runner.calls]
        self.assertEqual(
            (self.route_dir / "active-slot.conf").read_bytes(),
            _canonical_route("green"),
        )
        state = json.loads((self.route_dir / "rolling-release-state.json").read_text())
        self.assertEqual(state["phase"], "COMPLETE_SOURCE_RETAINED")
        self.assertFalse(state["production_acceptance"])
        self.assertFalse(any(" stop edge" in command for command in commands))
        self.assertFalse(any(command.endswith(" stop api web") for command in commands))
        migrate = next(i for i, command in enumerate(commands) if " run --rm --no-deps migrate" in command)
        start = next(i for i, command in enumerate(commands) if command.endswith("api-green web-green"))
        reload_edge = next(i for i, command in enumerate(commands) if command.endswith("nginx -s reload"))
        external = next(i for i, command in enumerate(commands) if f"https://{DOMAIN}/releasez" in command)
        self.assertEqual([migrate, start, reload_edge, external], sorted((migrate, start, reload_edge, external)))
        evidence = self.evidence()
        checkpoint_time = self.intake_validator.call_args.kwargs["evaluated_at"]
        self.assertEqual(
            evidence["started_at"],
            checkpoint_time.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z"),
        )
        self.assertEqual(evidence["terminal_state"], TERMINAL_COMPLETE)
        self.assertTrue(evidence["workers"]["unchanged"])
        self.assertEqual(evidence["routes"]["after_sha256"], evidence["routes"]["target_sha256"])
        self.assertEqual(
            [item["attempt"] for item in evidence["public_releasez"]],
            [1, 2, 3],
        )
        self.assertEqual(
            {
                (item["release_role"], item["service"], item["slot"])
                for item in evidence["tls_observations"]
            },
            {
                ("source", "api", "blue"),
                ("source", "web", "blue"),
                ("target", "api", "green"),
                ("target", "web", "green"),
            },
        )
        self.assertTrue(
            all(
                item["expected_sha256"] == item["peer_sha256"] == TLS_FINGERPRINT
                and item["tls_version"] == "TLSv1.3"
                for item in evidence["tls_observations"] + evidence["public_releasez"]
            )
        )
        self.assertEqual(
            [(item["action"], item["result"]) for item in evidence["nginx_operations"]],
            [("test", "passed"), ("reload", "passed")],
        )
        serialized = json.dumps(evidence, sort_keys=True)
        self.assertNotIn(DOMAIN, serialized)
        self.assertNotIn(str(self.route_dir), serialized)

    def test_route_switch_preserves_the_edge_readable_file_mode(self) -> None:
        route = self.route_dir / "active-slot.conf"
        route.chmod(0o640)
        expected_mode = stat.S_IMODE(route.stat().st_mode)

        with mock.patch(
            "scripts.rolling_release._atomic_write",
            wraps=rolling_release_module._atomic_write,
        ) as atomic_write:
            self.execute(FakeRunner(self.plan))

        route_calls = [
            call
            for call in atomic_write.call_args_list
            if call.args[0].name == "active-slot.conf"
        ]
        self.assertEqual(len(route_calls), 1)
        self.assertEqual(route_calls[0].kwargs.get("mode"), expected_mode)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(route.stat().st_mode), expected_mode)

    def test_all_route_reads_use_bounded_stable_snapshots(self) -> None:
        original_read_bytes = Path.read_bytes

        def reject_route_read_bytes(path: Path) -> bytes:
            if path.name in {"active-slot.conf", "blue.conf", "green.conf"}:
                raise AssertionError("route Path.read_bytes bypassed the stable boundary")
            return original_read_bytes(path)

        with mock.patch.object(Path, "read_bytes", reject_route_read_bytes):
            self.execute(FakeRunner(self.plan))

        self.assertEqual(
            (self.route_dir / "active-slot.conf").read_bytes(),
            _canonical_route("green"),
        )

    def test_route_switch_does_not_reread_mode_after_the_snapshot(self) -> None:
        runner = FakeRunner(self.plan)
        environment = self.plan.compose_environment()
        original_stat = Path.stat

        def reject_following_route_stat(path: Path, *args, **kwargs):
            if path.name == "active-slot.conf" and kwargs.get("follow_symlinks", True):
                raise AssertionError("route mode was read outside the snapshot")
            return original_stat(path, *args, **kwargs)

        with mock.patch.object(
            Path,
            "stat",
            reject_following_route_stat,
        ):
            rolling_release_module._switch_route(
                self.plan,
                self.plan.target_slot,
                runner,
                environment,
                mock.Mock(),
            )

        self.assertEqual(
            (self.route_dir / "active-slot.conf").read_bytes(),
            _canonical_route("green"),
        )

    def test_route_replaced_before_switch_is_not_overwritten(self) -> None:
        route = self.route_dir / "active-slot.conf"
        route.write_bytes(b"unreviewed route\n")
        runner = FakeRunner(self.plan)

        with self.assertRaisesRegex(
            RollingReleaseError,
            "active rolling route changed before switch",
        ):
            rolling_release_module._switch_route(
                self.plan,
                self.plan.target_slot,
                runner,
                self.plan.compose_environment(),
                mock.Mock(),
            )

        self.assertEqual(route.read_bytes(), b"unreviewed route\n")
        self.assertEqual(runner.calls, [])

    def test_oversized_canonical_and_active_route_are_rejected(self) -> None:
        canonical_dir = self.route_dir / "canonical"
        canonical_dir.mkdir()
        oversized = b"x" * (16 * 1024 + 1)
        (canonical_dir / "blue.conf").write_bytes(oversized)
        (self.route_dir / "active-slot.conf").write_bytes(oversized)

        with mock.patch.object(rolling_release_module, "SLOT_DIR", canonical_dir):
            with self.assertRaisesRegex(
                RollingReleaseError,
                "rolling route file cannot be read safely",
            ):
                rolling_release_module._validate_route_dir(self.route_dir, "blue")

    def test_unsafe_canonical_route_error_is_sanitized(self) -> None:
        with mock.patch(
            "scripts.rolling_release.read_stable_bytes_with_metadata",
            side_effect=OSError("private filesystem detail"),
            create=True,
        ):
            with self.assertRaisesRegex(
                RollingReleaseError,
                "^rolling route file cannot be read safely$",
            ) as raised:
                _canonical_route("blue")

        self.assertNotIn("private filesystem detail", str(raised.exception))

    def test_evidence_is_closed_tamper_evident_and_write_once(self) -> None:
        self.execute(FakeRunner(self.plan))
        original = self.evidence_output.read_bytes()
        evidence = json.loads(original)
        self.assertEqual(evidence["target_intake"], TARGET_INTAKE.as_evidence())
        assert_expected_releases(
            evidence,
            source_tag=self.plan.source.tag,
            source_commit=self.plan.source.commit,
            source_manifest_sha256=self.plan.source.container_manifest_sha256,
            target_tag=self.plan.deployment.tag,
            target_commit=self.plan.deployment.commit,
            target_manifest_sha256=self.plan.deployment.container_manifest_sha256,
            target_environment=TARGET_INTAKE.environment,
            target_intake_manifest_sha256=TARGET_INTAKE.manifest_payload_sha256,
            target_intake_requirements_sha256=TARGET_INTAKE.requirements_sha256,
        )
        with self.assertRaisesRegex(RollingReleaseEvidenceError, "release binding"):
            assert_expected_releases(
                evidence,
                source_tag=self.plan.source.tag,
                source_commit=self.plan.source.commit,
                source_manifest_sha256=self.plan.source.container_manifest_sha256,
                target_tag="v9.9.9",
                target_commit=self.plan.deployment.commit,
                target_manifest_sha256=self.plan.deployment.container_manifest_sha256,
                target_environment=TARGET_INTAKE.environment,
                target_intake_manifest_sha256=TARGET_INTAKE.manifest_payload_sha256,
                target_intake_requirements_sha256=TARGET_INTAKE.requirements_sha256,
            )
        with self.assertRaisesRegex(RollingReleaseEvidenceError, "target intake"):
            assert_expected_releases(
                evidence,
                source_tag=self.plan.source.tag,
                source_commit=self.plan.source.commit,
                source_manifest_sha256=self.plan.source.container_manifest_sha256,
                target_tag=self.plan.deployment.tag,
                target_commit=self.plan.deployment.commit,
                target_manifest_sha256=self.plan.deployment.container_manifest_sha256,
                target_environment="production",
                target_intake_manifest_sha256=TARGET_INTAKE.manifest_payload_sha256,
                target_intake_requirements_sha256=TARGET_INTAKE.requirements_sha256,
            )
        verifier_arguments = [
            "--input",
            str(self.evidence_output),
            "--expected-source-tag",
            self.plan.source.tag,
            "--expected-source-commit",
            self.plan.source.commit,
            "--expected-source-container-manifest-sha256",
            self.plan.source.container_manifest_sha256,
            "--expected-target-tag",
            self.plan.deployment.tag,
            "--expected-target-commit",
            self.plan.deployment.commit,
            "--expected-target-container-manifest-sha256",
            self.plan.deployment.container_manifest_sha256,
            "--expected-target-environment",
            TARGET_INTAKE.environment,
            "--expected-target-intake-manifest-sha256",
            TARGET_INTAKE.manifest_payload_sha256,
            "--expected-target-intake-requirements-sha256",
            TARGET_INTAKE.requirements_sha256,
        ]
        self.assertEqual(evidence_main(verifier_arguments), 0)
        verifier_arguments[verifier_arguments.index("--expected-target-environment") + 1] = (
            "production"
        )
        self.assertEqual(evidence_main(verifier_arguments), 1)
        for forbidden in ("environment", "argv", "host_path", "certificate", "secret"):
            with self.subTest(forbidden=forbidden):
                changed = json.loads(original)
                changed[forbidden] = "forbidden"
                with self.assertRaisesRegex(RollingReleaseEvidenceError, "schema"):
                    validate_evidence(changed)
        evidence["source"]["tag"] = "v9.9.9"
        with self.assertRaisesRegex(RollingReleaseEvidenceError, "integrity"):
            validate_evidence(evidence)

        duplicate = original.decode("utf-8").replace(
                '"schema_version": 3,',
                '"schema_version": 3, "schema_version": 3,',
            1,
        )
        duplicate_path = self.route_dir / "duplicate-evidence.json"
        duplicate_path.write_text(duplicate, encoding="utf-8")
        with self.assertRaisesRegex(RollingReleaseEvidenceError, "duplicate keys"):
            verify_evidence(duplicate_path)

        reordered = json.loads(original)
        reordered["phases"][1], reordered["phases"][2] = (
            reordered["phases"][2],
            reordered["phases"][1],
        )
        with self.assertRaisesRegex(RollingReleaseEvidenceError, "phase sequence"):
            validate_evidence(reordered)

        second_runner = FakeRunner(self.plan)
        with self.assertRaisesRegex(RollingReleaseError, "evidence preflight"):
            self.execute(second_runner)
        self.assertEqual(second_runner.calls, [])
        self.assertEqual(self.evidence_output.read_bytes(), original)

    def test_public_target_failure_switches_back_before_candidate_stop(self) -> None:
        runner = FakeRunner(self.plan, fail_external=True)
        with self.assertRaisesRegex(RollingReleaseError, "source was restored"):
            self.execute(runner)
        self.assertEqual(
            (self.route_dir / "active-slot.conf").read_bytes(),
            _canonical_route("blue"),
        )
        commands = [" ".join(command) for command, _ in runner.calls]
        reloads = [i for i, command in enumerate(commands) if command.endswith("nginx -s reload")]
        candidate_stop = next(i for i, command in enumerate(commands) if command.endswith("stop api-green web-green"))
        self.assertEqual(len(reloads), 2)
        self.assertLess(reloads[-1], candidate_stop)
        evidence = self.evidence()
        self.assertEqual(evidence["terminal_state"], TERMINAL_SWITCHED_BACK)
        self.assertTrue(evidence["workers"]["unchanged"])
        self.assertEqual(evidence["routes"]["after_sha256"], evidence["routes"]["source_sha256"])
        source_passes = [
            item for item in evidence["public_releasez"]
            if item["release_role"] == "source" and item["result"] == "passed"
        ]
        self.assertEqual([item["attempt"] for item in source_passes], [1, 2, 3])

    def test_public_tls_identity_drift_switches_back_to_verified_source(self) -> None:
        runner = FakeRunner(self.plan)
        runner.external_tls_mismatches = 1
        with self.assertRaisesRegex(RollingReleaseError, "source was restored"):
            self.execute(runner)
        evidence = self.evidence()
        self.assertEqual(evidence["terminal_state"], TERMINAL_SWITCHED_BACK)
        failed = [
            item
            for item in evidence["public_releasez"]
            if item["release_role"] == "target" and item["result"] == "failed"
        ]
        self.assertEqual(len(failed), 1)
        self.assertIsNone(failed[0]["peer_sha256"])
        self.assertEqual(
            (self.route_dir / "active-slot.conf").read_bytes(),
            _canonical_route("blue"),
        )

    def test_internal_tls_identity_drift_fails_before_candidate_start(self) -> None:
        runner = FakeRunner(self.plan)
        runner.tls_fingerprint = "f" * 64
        with self.assertRaisesRegex(RollingReleaseError, "internal TLS peer identity"):
            self.execute(runner)
        commands = [" ".join(command) for command, _ in runner.calls]
        self.assertFalse(any(command.endswith("api-green web-green") for command in commands))
        self.assertEqual(self.evidence()["terminal_state"], TERMINAL_PRE_SWITCH_FAILED)

    def test_tls_evidence_rejects_peer_drift_and_unsupported_version(self) -> None:
        self.execute(FakeRunner(self.plan))
        evidence = self.evidence()
        drifted = json.loads(json.dumps(evidence))
        drifted["tls_observations"][0]["peer_sha256"] = "f" * 64
        with self.assertRaisesRegex(RollingReleaseEvidenceError, "internal TLS identity"):
            validate_evidence(drifted)
        unsupported = json.loads(json.dumps(evidence))
        unsupported["public_releasez"][0]["tls_version"] = "TLSv1.1"
        with self.assertRaisesRegex(RollingReleaseEvidenceError, "public TLS identity"):
            validate_evidence(unsupported)

    def test_failed_target_and_source_observations_record_route_unconfirmed(self) -> None:
        runner = FakeRunner(self.plan, external_failures=2)
        with self.assertRaisesRegex(RollingReleaseError, "recovery could not be confirmed"):
            self.execute(runner)
        evidence = self.evidence()
        self.assertEqual(evidence["terminal_state"], TERMINAL_ROUTE_UNCONFIRMED)
        self.assertTrue(evidence["workers"]["unchanged"])
        self.assertEqual(evidence["production_acceptance"], False)

    def test_reload_failure_restores_route_and_cleans_candidate(self) -> None:
        runner = FakeRunner(self.plan, fail_reload_once=True)
        with self.assertRaisesRegex(RollingReleaseError, "was restored"):
            self.execute(runner)
        self.assertEqual(
            (self.route_dir / "active-slot.conf").read_bytes(),
            _canonical_route("blue"),
        )
        commands = [" ".join(command) for command, _ in runner.calls]
        self.assertTrue(any(command.endswith("stop api-green web-green") for command in commands))
        self.assertEqual(self.evidence()["terminal_state"], TERMINAL_PRE_SWITCH_FAILED)

    def test_confirmation_failure_has_zero_runner_calls(self) -> None:
        runner = FakeRunner(self.plan)
        with self.assertRaises(RollingReleaseError):
            execute_rolling_release(
                self.plan,
                confirm_release_tag="wrong",
                container_manifest_sha256=self.plan.deployment.container_manifest_sha256,
                domain=DOMAIN,
                evidence_output=self.evidence_output,
                target_intake_manifest=self.target_intake_manifest,
                target_environment="staging",
                runner=runner,
            )
        self.assertEqual(runner.calls, [])
        evidence = self.evidence()
        self.assertEqual(evidence["terminal_state"], TERMINAL_PRE_SWITCH_FAILED)
        self.assertEqual(evidence["public_releasez"], [])

    def test_repository_evidence_path_is_rejected_before_runner_use(self) -> None:
        runner = FakeRunner(self.plan)
        repository_output = Path(__file__).resolve().parents[1] / "forbidden-evidence.json"
        with self.assertRaisesRegex(RollingReleaseError, "evidence preflight"):
            execute_rolling_release(
                self.plan,
                confirm_release_tag=self.plan.deployment.tag,
                container_manifest_sha256=self.plan.deployment.container_manifest_sha256,
                domain=DOMAIN,
                evidence_output=repository_output,
                target_intake_manifest=self.target_intake_manifest,
                target_environment="staging",
                runner=runner,
            )
        self.assertEqual(runner.calls, [])
        self.assertFalse(repository_output.exists())

    def test_route_changed_after_plan_fails_under_lock_before_runner_use(self) -> None:
        (self.route_dir / "active-slot.conf").write_bytes(_canonical_route("green"))
        runner = FakeRunner(self.plan)

        with self.assertRaisesRegex(
            RollingReleaseError, "active rolling route does not match the declared slot"
        ):
            self.execute(runner)

        self.assertEqual(runner.calls, [])

    def test_edge_route_mount_must_be_exact_and_read_only_before_migration(self) -> None:
        mutations = (
            {},
            {
                "Type": "bind",
                "Source": str(self.route_dir.parent.resolve()),
                "Destination": "/etc/nginx/edge-routing",
                "RW": False,
            },
            {
                "Type": "bind",
                "Source": str(self.route_dir.resolve()),
                "Destination": "/etc/nginx/edge-routing",
                "RW": True,
            },
        )
        for index, mount in enumerate(mutations):
            (self.route_dir / "active-slot.conf").write_bytes(_canonical_route("blue"))
            runner = FakeRunner(self.plan, edge_route_mount=mount)
            with self.subTest(mount=mount):
                with self.assertRaisesRegex(
                    RollingReleaseError,
                    "edge rolling route mount is invalid",
                ):
                    execute_rolling_release(
                        self.plan,
                        confirm_release_tag=self.plan.deployment.tag,
                        container_manifest_sha256=self.plan.deployment.container_manifest_sha256,
                        domain=DOMAIN,
                        evidence_output=self.route_dir / f"mount-{index}.json",
                        target_intake_manifest=self.target_intake_manifest,
                        target_environment="staging",
                        runner=runner,
                    )
                self.assertFalse(
                    any(" run --rm --no-deps migrate" in " ".join(call[0]) for call in runner.calls)
                )

    def test_phase0_intake_failure_precedes_evidence_lock_and_runner(self) -> None:
        runner = FakeRunner(self.plan)
        with mock.patch(
            "scripts.rolling_release.load_phase_checkpoint",
            side_effect=ValueError("private intake detail"),
        ), mock.patch("scripts.rolling_release.SubprocessRunner") as constructor, mock.patch(
            "scripts.rolling_release.release_control_lock"
        ) as release_lock:
            with self.assertRaisesRegex(
                RollingReleaseError, "^target intake Phase 0 preflight failed$"
            ) as raised:
                execute_rolling_release(
                    self.plan,
                    confirm_release_tag=self.plan.deployment.tag,
                    container_manifest_sha256=self.plan.deployment.container_manifest_sha256,
                    domain=DOMAIN,
                    evidence_output=self.evidence_output,
                    target_intake_manifest=self.target_intake_manifest,
                    target_environment="staging",
                    runner=runner,
                )
        constructor.assert_not_called()
        release_lock.assert_not_called()
        self.assertEqual(runner.calls, [])
        self.assertNotIn("private intake detail", str(raised.exception))

    def test_workers_keep_the_authenticated_source_digest_in_both_directions(self) -> None:
        for active_slot in ("blue", "green"):
            with self.subTest(active_slot=active_slot):
                (self.route_dir / "active-slot.conf").write_bytes(
                    _canonical_route(active_slot)
                )
                plan = _plan(self.route_dir, active_slot=active_slot)
                environment = plan.compose_environment()
                self.assertEqual(
                    environment["PLATFORM_ROLLING_WORKER_MAIL_IMAGE"],
                    plan.source.images["api"],
                )
                self.assertEqual(
                    environment["PLATFORM_ROLLING_WORKER_SUB2_IMAGE"],
                    plan.source.images["api"],
                )


if __name__ == "__main__":
    unittest.main()
