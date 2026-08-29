from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import traceback
import unittest
from unittest import mock

from scripts.backup_crypto import ALGORITHM, FORMAT_VERSION, encrypt_stream, key_id

from scripts.deploy_release import (
    DeploymentError,
    execute_deployment,
    load_deployment_plan,
    plan_summary,
)
from scripts.deploy_release_evidence import verify_evidence
from scripts.postgres_maintenance import _manifest_hmac_sha256
from scripts.release_control_lock import ReleaseControlLocked
from scripts.rollback_release import PRODUCTION_COMPOSE, PRODUCTION_ENV_FILE, _compose
from scripts.restore_readiness import PROBE_CONTAINER, PROBES, TLS_PROBE_PROGRAM
from scripts.validate_edge_tls import EdgeTlsError
from scripts.tls_runtime_identity import INTERNAL_ENDPOINT_SERVICES, TLS_HTTP_PROBE_PROGRAM
from scripts.vault_token_sinks import VaultTokenSinkError
from scripts.target_intake_preflight import PhaseCheckpointIdentity


TAG = "v1.2.3"
COMMIT = "a" * 40
ROLLBACK_TAG = "v1.2.2"
ROLLBACK_COMMIT = "d" * 40
ROLLBACK_MIGRATION_HEAD = "0017_mail_token_hash_unique"
DOMAIN = "platform.example.com"
TARGET_INTAKE = PhaseCheckpointIdentity(
    environment="staging",
    manifest_payload_sha256="9" * 64,
    requirements_sha256="8" * 64,
    checkpoint_phase=0,
)
NOW = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
RECOVERY_SET = "release-v1.2.2-20260821T115000Z"
THIRD_PARTY_DIGEST_ENV = {
    "POSTGRES_IMAGE_SHA256": "1" * 64,
    "REDIS_IMAGE_SHA256": "2" * 64,
    "KEYCLOAK_IMAGE_SHA256": "3" * 64,
    "ALERTMANAGER_IMAGE_SHA256": "4" * 64,
    "PROMETHEUS_IMAGE_SHA256": "5" * 64,
}
TLS_FINGERPRINT = "a" * 64
TLS_FINGERPRINTS = {
    service: TLS_FINGERPRINT for service in set(INTERNAL_ENDPOINT_SERVICES.values())
}
COMPOSE_COMMAND_INDEX = len(_compose("unused")) - 1
OPERATIONAL_SERVICES = (
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


def _manifest(
    *,
    tag: str = TAG,
    commit: str = COMMIT,
    migration_head: str = "0018_access_token_revocations",
) -> dict[str, object]:
    identity = (
        "https://github.com/example/manage/.github/workflows/"
        f"release.yml@refs/tags/{tag}"
    )
    images: dict[str, object] = {}
    digest_start = 4 if tag == ROLLBACK_TAG else 1
    for index, name in enumerate(("api", "web", "edge"), start=digest_start):
        images[name] = {
            "image": f"ghcr.io/example/manage-{name}",
            "digest": f"sha256:{str(index) * 64}",
            "sbom": {"file": f"{name}.spdx.json", "sha256": "b" * 64},
            "scan": {
                "tool": "trivy",
                "severities": ["HIGH", "CRITICAL"],
                "result": "passed",
                "file": f"{name}.trivy.sarif",
                "sha256": "c" * 64,
            },
            "signature": {
                "issuer": "https://token.actions.githubusercontent.com",
                "identity": identity,
            },
            "attestations": ["cosign-spdxjson", "github-build-provenance"],
        }
    return {
        "schema_version": 1,
        "tag": tag,
        "commit": commit,
        "migration_head": migration_head,
        "images": images,
    }


def _write_rollback_fixture(
    root: Path,
    *,
    created_at: datetime,
    schema_version: int = 5,
) -> tuple[Path, Path, Path]:
    root.mkdir(parents=True, exist_ok=True)
    container_manifest_path = root / "rollback-container-manifest.json"
    container_manifest_path.write_text(
        json.dumps(
            _manifest(
                tag=ROLLBACK_TAG,
                commit=ROLLBACK_COMMIT,
                migration_head=ROLLBACK_MIGRATION_HEAD,
            ),
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    container_manifest_sha256 = hashlib.sha256(
        container_manifest_path.read_bytes()
    ).hexdigest()
    key_file = root / "rollback-backup.key"
    key = b"rollback-point-key-material-32!!"
    assert len(key) == 32
    key_file.write_bytes(key)
    backup_dir = root / "rollback-backup"
    backup_dir.mkdir()
    databases: dict[str, dict[str, object]] = {}
    for logical_name, database in (
        ("platform", "email_platform"),
        ("keycloak", "keycloak"),
    ):
        artifact = f"{logical_name}.dump.enc"
        with (backup_dir / artifact).open("wb") as destination:
            encrypt_stream(
                io.BytesIO(f"{logical_name}-backup".encode()),
                destination,
                key,
                logical_name=logical_name,
                source_database=database,
            )
        ciphertext = (backup_dir / artifact).read_bytes()
        databases[logical_name] = {
            "database": database,
            "artifact": artifact,
            "sha256": hashlib.sha256(ciphertext).hexdigest(),
            "size_bytes": len(ciphertext),
            "algorithm": ALGORITHM,
            "format_version": FORMAT_VERSION,
            "key_id": key_id(key),
        }
    manifest: dict[str, object] = {
        "schema_version": schema_version,
        "created_at": created_at.isoformat(),
        "databases": databases,
    }
    if schema_version in {4, 5}:
        manifest.update(
            {
                "release_tag": ROLLBACK_TAG,
                "release_commit": ROLLBACK_COMMIT,
                "migration_head": ROLLBACK_MIGRATION_HEAD,
                "container_manifest_sha256": container_manifest_sha256,
            }
        )
    if schema_version == 5:
        manifest["manifest_hmac_sha256"] = _manifest_hmac_sha256(manifest, key)
    (backup_dir / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    redis_backup_dir = root / "redis-backup"
    redis_backup_dir.mkdir()
    (redis_backup_dir / "fixture-created-at.txt").write_text(
        created_at.isoformat(), encoding="utf-8"
    )
    (redis_backup_dir / "redis-manifest.json").write_text(
        '{"schema_version":1}\n', encoding="utf-8"
    )
    return container_manifest_path, backup_dir, key_file


class FakeRunner:
    def __init__(
        self,
        *,
        current_images: dict[str, str],
        git_head: str = COMMIT,
        fail_contains: str | None = None,
        wrong_current_service: str | None = None,
        wrong_target_service: str | None = None,
        running_services: tuple[str, ...] | None = None,
    ):
        self.current_images = current_images
        self.git_head = git_head
        self.fail_contains = fail_contains
        self.wrong_current_service = wrong_current_service
        self.wrong_target_service = wrong_target_service
        self.running_services = running_services or OPERATIONAL_SERVICES
        self.tls_fingerprint = TLS_FINGERPRINT
        self.calls: list[tuple[list[str], dict[str, str] | None]] = []

    def run(self, command, *, env=None, capture_output=False):
        command = list(command)
        copied_env = dict(env) if env is not None else None
        self.calls.append((command, copied_env))
        rendered = " ".join(command)
        if self.fail_contains and self.fail_contains in rendered:
            raise subprocess.CalledProcessError(1, command)
        if command[:2] == ["trivy", "image"]:
            output = Path(command[command.index("--output") + 1])
            output.write_text(
                json.dumps(
                    {
                        "runs": [
                            {
                                "tool": {"driver": {"name": "Trivy"}},
                                "properties": {"imageName": command[-1]},
                                "results": [],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            return ""
        if command[:2] == ["git", "-C"] and command[3:] == [
            "rev-parse",
            "--verify",
            "HEAD",
        ]:
            return self.git_head + "\n"
        compose = (
            command[COMPOSE_COMMAND_INDEX:]
            if command[:2] == ["docker", "compose"]
            else []
        )
        if compose == ["ps", "--status", "running", "--services"]:
            return "\n".join(self.running_services) + "\n"
        if compose[:2] == ["ps", "-q"]:
            return f"{compose[2]}-id\n"
        if command[:4] == ["docker", "inspect", "--format", "{{.Config.Image}}"]:
            service = command[4].removesuffix("-id")
            variable = {
                "edge": "PLATFORM_EDGE_IMAGE",
                "web": "PLATFORM_WEB_IMAGE",
            }.get(service, "PLATFORM_API_IMAGE")
            assert copied_env is not None
            current_phase = (
                copied_env["PLATFORM_API_IMAGE"] == self.current_images["api"]
            )
            wrong_service = (
                self.wrong_current_service
                if current_phase
                else self.wrong_target_service
            )
            if service == wrong_service:
                return "ghcr.io/example/wrong@sha256:" + "f" * 64
            return copied_env[variable]
        if TLS_HTTP_PROBE_PROGRAM in command:
            return json.dumps(
                {
                    "peer_sha256": self.tls_fingerprint,
                    "tls_version": "TLSv1.3",
                }
            )
        return ""


class DeployReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        digest_env_patch = mock.patch.dict(os.environ, THIRD_PARTY_DIGEST_ENV)
        digest_env_patch.start()
        self.addCleanup(digest_env_patch.stop)
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.target_intake_manifest = self.root / "target-intake.json"
        self.evidence_sequence = 0
        self.permission_patch = mock.patch(
            "scripts.backup_crypto._validate_key_permissions"
        )
        self.permission_patch.start()
        self.addCleanup(self.permission_patch.stop)
        self.redis_verifier_patch = mock.patch(
            "scripts.rollback_release.verify_release_backup",
            side_effect=self._verify_redis_fixture,
        )
        self.redis_verifier = self.redis_verifier_patch.start()
        self.addCleanup(self.redis_verifier_patch.stop)
        self.edge_tls_patch = mock.patch(
            "scripts.deploy_release.validate_edge_tls",
            return_value=TLS_FINGERPRINT,
        )
        self.edge_tls_validator = self.edge_tls_patch.start()
        self.addCleanup(self.edge_tls_patch.stop)
        internal_tls_patch = mock.patch(
            "scripts.deploy_release.expected_internal_fingerprints",
            return_value=TLS_FINGERPRINTS,
        )
        self.internal_tls_validator = internal_tls_patch.start()
        self.addCleanup(internal_tls_patch.stop)
        self.vault_sink_patch = mock.patch(
            "scripts.deploy_release.validate_vault_token_sinks"
        )
        self.vault_sink_validator = self.vault_sink_patch.start()
        self.addCleanup(self.vault_sink_patch.stop)
        self.intake_patch = mock.patch(
            "scripts.deploy_release.load_phase_checkpoint", return_value=TARGET_INTAKE
        )
        self.intake_validator = self.intake_patch.start()
        self.addCleanup(self.intake_patch.stop)
        self.manifest_path = self.root / "container-release-manifest.json"
        self.manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")
        (
            self.rollback_manifest_path,
            self.rollback_backup_dir,
            self.rollback_key_file,
        ) = _write_rollback_fixture(
            self.root,
            created_at=NOW - timedelta(minutes=10),
        )
        self.plan = self.load_plan()

    @staticmethod
    def _verify_redis_fixture(input_dir, **kwargs):
        created_at = datetime.fromisoformat(
            (Path(input_dir) / "fixture-created-at.txt").read_text(
                encoding="utf-8"
            )
        )
        if kwargs.get("recovery_set") != RECOVERY_SET:
            raise ValueError("Redis recovery set mismatch")
        manifest_path = Path(input_dir) / "redis-manifest.json"
        with manifest_path.open("rb") as stream:
            manifest_sha256 = hashlib.sha256(stream.read()).hexdigest()
        if kwargs.get("_include_manifest_sha256"):
            return {}, created_at, manifest_sha256
        return {}, created_at

    def load_plan(
        self,
        *,
        now: datetime = NOW,
        rollback_manifest_path: Path | None = None,
        rollback_backup_dir: Path | None = None,
        rollback_redis_backup_dir: Path | None = None,
        rollback_recovery_set: str = RECOVERY_SET,
        rollback_key_file: Path | None = None,
    ):
        return load_deployment_plan(
            self.manifest_path,
            rollback_container_manifest_path=(
                rollback_manifest_path or self.rollback_manifest_path
            ),
            rollback_backup_dir=rollback_backup_dir or self.rollback_backup_dir,
            rollback_redis_backup_dir=(
                rollback_redis_backup_dir
                or (rollback_backup_dir or self.rollback_backup_dir).parent
                / "redis-backup"
            ),
            rollback_recovery_set=rollback_recovery_set,
            rollback_key_file=rollback_key_file or self.rollback_key_file,
            now=now,
        )

    def runner(self, **kwargs) -> FakeRunner:
        return FakeRunner(current_images=self.plan.rollback.images, **kwargs)

    def evidence_output(self) -> Path:
        self.evidence_sequence += 1
        self.last_evidence_output = (
            self.root / f"deployment-evidence-{self.evidence_sequence}.json"
        )
        return self.last_evidence_output

    def execute(self, runner: FakeRunner) -> Path:
        evidence_output = self.evidence_output()
        execute_deployment(
            self.plan,
            confirm_release_tag=TAG,
            container_manifest_sha256=self.plan.container_manifest_sha256,
            domain=DOMAIN,
            evidence_output=evidence_output,
            target_intake_manifest=self.target_intake_manifest,
            target_environment="staging",
            runner=runner,
        )
        return evidence_output

    def test_plan_is_immutable_preflight_not_rolling_acceptance(self) -> None:
        summary = plan_summary(self.plan)
        self.assertFalse(summary["production_acceptance"])
        self.assertFalse(summary["rolling_release"])
        self.assertTrue(all("@sha256:" in image for image in summary["images"].values()))
        self.assertEqual(summary["rollback_release_tag"], ROLLBACK_TAG)
        self.assertEqual(
            summary["rollback_database_bundle"], "platform+keycloak+redis"
        )
        self.assertEqual(summary["rollback_recovery_set"], RECOVERY_SET)
        self.assertEqual(
            summary["rollback_max_recovery_point_skew_seconds"], 300
        )
        serialized = json.dumps(summary)
        self.assertNotIn(str(self.rollback_key_file), serialized)
        self.assertNotIn(str(self.rollback_backup_dir), serialized)

    def test_forward_and_rollback_plans_do_not_reread_authenticated_manifests(
        self,
    ) -> None:
        watched = {
            self.manifest_path,
            self.rollback_manifest_path,
            self.rollback_backup_dir / "manifest.json",
            self.rollback_backup_dir.parent / "redis-backup" / "redis-manifest.json",
        }
        read_bytes = Path.read_bytes

        def reject_manifest_reread(candidate: Path) -> bytes:
            if candidate in watched:
                raise AssertionError(f"manifest path was read twice: {candidate.name}")
            return read_bytes(candidate)

        with mock.patch.object(Path, "read_bytes", reject_manifest_reread):
            plan = self.load_plan()

        self.assertEqual(plan.container_manifest_sha256, self.plan.container_manifest_sha256)
        self.assertEqual(
            plan.rollback.postgres_manifest_sha256,
            self.plan.rollback.postgres_manifest_sha256,
        )

    def test_execute_orders_verified_pull_edge_closed_and_smoke(self) -> None:
        runner = self.runner()
        evidence_output = self.execute(runner)
        self.edge_tls_validator.assert_called_once_with(PRODUCTION_ENV_FILE, DOMAIN)
        commands = [" ".join(call[0]) for call in runner.calls]
        rollback_verify = next(
            i
            for i, command in enumerate(commands)
            if command.startswith("cosign verify ")
            and self.plan.rollback.images["api"] in command
        )
        current_runtime = max(
            i
            for i, command in enumerate(commands)
            if command.startswith("docker inspect --format")
            and runner.calls[i][1]
            and runner.calls[i][1]["PLATFORM_API_IMAGE"]
            == self.plan.rollback.images["api"]
        )
        target_verify = next(
            i
            for i, command in enumerate(commands)
            if command.startswith("cosign verify ")
            and self.plan.images["api"] in command
        )
        upstream_scans = [
            i for i, command in enumerate(commands)
            if command.startswith("trivy image ")
        ]
        self.assertEqual(len(upstream_scans), 5)
        pull = next(i for i, command in enumerate(commands) if command.startswith("docker pull "))
        stop_command = " ".join(_compose("stop", "edge"))
        edge_command = " ".join(
            _compose("up", "-d", "--no-build", "--pull", "never", "--force-recreate", "edge")
        )
        stop = commands.index(stop_command)
        backend = next(
            i
            for i, command in enumerate(commands)
            if " ".join(_compose("up")) in command and command.endswith("web")
        )
        internal = next(
            i
            for i, command in enumerate(commands)
            if " ".join(_compose("exec", "-T", "api")) in command
            and "https://api:8443/readyz" in command
        )
        edge = commands.index(edge_command)
        external = next(
            i for i, command in enumerate(commands) if f"https://{DOMAIN}/readyz" in command
        )
        positions = [
            rollback_verify,
            current_runtime,
            max(upstream_scans),
            target_verify,
            pull,
            stop,
            backend,
            internal,
            edge,
            external,
        ]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(
            self.vault_sink_validator.call_args_list,
            [
                mock.call(PRODUCTION_ENV_FILE, PRODUCTION_COMPOSE),
                mock.call(PRODUCTION_ENV_FILE, PRODUCTION_COMPOSE),
            ],
        )
        self.assertEqual(
            [call[0][3] for call in runner.calls[:3]],
            ["rev-parse", "diff", "diff"],
        )
        self.assertTrue(
            all(
                all(
                    environment.get(name) == digest
                    for name, digest in THIRD_PARTY_DIGEST_ENV.items()
                )
                for command, environment in runner.calls
                if command[:2] == ["docker", "compose"]
            )
        )
        evidence = verify_evidence(evidence_output)
        self.assertEqual(evidence["terminal_state"], "succeeded")
        self.assertFalse(evidence["production_acceptance"])
        self.assertFalse(evidence["rolling_release"])
        self.assertEqual(evidence["images"]["expected"], evidence["images"]["observed"])
        self.assertTrue(all(evidence["third_party_images"].values()))
        self.assertNotIn(str(self.rollback_key_file), json.dumps(evidence))

    def test_vault_sink_preflight_failure_precedes_runner_construction(self) -> None:
        private_detail = "D:/private/vault-agent/api/token"
        self.vault_sink_validator.side_effect = VaultTokenSinkError(private_detail)
        with mock.patch("scripts.deploy_release.SubprocessRunner") as constructor:
            with self.assertRaisesRegex(
                DeploymentError,
                "^production Vault token sink preflight failed$",
            ) as raised:
                execute_deployment(
                    self.plan,
                    confirm_release_tag=TAG,
                    container_manifest_sha256=self.plan.container_manifest_sha256,
                    domain=DOMAIN,
                    evidence_output=self.evidence_output(),
                    target_intake_manifest=self.target_intake_manifest,
                    target_environment="staging",
                )
        constructor.assert_not_called()
        self.assertNotIn(private_detail, str(raised.exception))

    def test_vault_sink_recheck_fails_after_internal_smoke_before_edge(self) -> None:
        runner = self.runner()
        private_detail = "D:/private/vault-agent/mail/token"
        checks = 0

        def validate(_env_file: Path, _compose_file: Path) -> None:
            nonlocal checks
            checks += 1
            commands = [" ".join(command) for command, _ in runner.calls]
            if checks == 1:
                self.assertEqual(commands, [])
                return
            self.assertTrue(
                all(any(url in command for command in commands) for url in PROBES)
            )
            self.assertNotIn(
                " ".join(
                    _compose("up", "-d", "--no-build", "--pull", "never", "--force-recreate", "edge")
                ),
                commands,
            )
            raise VaultTokenSinkError(private_detail)

        self.vault_sink_validator.side_effect = validate
        with self.assertRaisesRegex(
            DeploymentError,
            "^Vault token sink recheck failed with public edge closed$",
        ) as raised:
            self.execute(runner)

        commands = [" ".join(command) for command, _ in runner.calls]
        self.assertEqual(checks, 2)
        self.assertNotIn(private_detail, str(raised.exception))
        self.assertNotIn(
            " ".join(_compose("up", "-d", "--no-build", "--pull", "never", "--force-recreate", "edge")),
            commands,
        )
        self.assertIn(" ".join(_compose("stop", "edge")), commands)
        compose_prefix = _compose("unused")[:-1]
        self.assertTrue(
            all(
                command[: len(compose_prefix)] == compose_prefix
                for command, _ in runner.calls
                if command[:2] == ["docker", "compose"]
            )
        )
        self.assertTrue(
            all(
                "--no-build --pull never" in command
                for command in commands
                if " ".join(_compose("up")) in command
            )
        )
        smoke_calls = [
            call[0]
            for call in runner.calls
            if call[0][COMPOSE_COMMAND_INDEX : COMPOSE_COMMAND_INDEX + 2]
            == ["exec", "-T"]
            and TLS_HTTP_PROBE_PROGRAM in call[0]
        ]
        self.assertEqual(
            {
                call[call.index(TLS_HTTP_PROBE_PROGRAM) + 1]
                for call in smoke_calls
            },
            set(PROBES),
        )
        for call in smoke_calls:
            self.assertEqual(call[COMPOSE_COMMAND_INDEX + 2], PROBE_CONTAINER)
            self.assertEqual(call[call.index("-c") + 1], TLS_HTTP_PROBE_PROGRAM)

    def test_deployment_external_smoke_uses_strict_shared_program(self) -> None:
        runner = self.runner()
        self.execute(runner)
        external_calls = [
            command
            for command, _ in runner.calls
            if command[:3] == [sys.executable, "-c", TLS_HTTP_PROBE_PROGRAM]
        ]
        self.assertEqual(len(external_calls), 2)
        self.assertEqual(
            {command[3] for command in external_calls},
            {
                f"https://{DOMAIN}/readyz",
                f"https://identity.{DOMAIN}/realms/email-platform/.well-known/openid-configuration",
            },
        )
        program = external_calls[0][2]
        self.assertIn("http.client.HTTPSConnection", program)
        self.assertIn("connection.sock.getpeercert(binary_form=True)", program)
        self.assertIn("connection.sock.version()", program)
        self.assertIn("ssl.TLSVersion.TLSv1_2", program)

    def test_invalid_third_party_digest_fails_before_checkout(self) -> None:
        runner = self.runner()
        with mock.patch.dict(
            os.environ,
            {"POSTGRES_IMAGE_SHA256": "postgres:16-alpine"},
        ):
            with self.assertRaisesRegex(
                DeploymentError, "third-party image digest preflight"
            ):
                self.execute(runner)
        self.assertEqual(runner.calls, [])

    def test_public_edge_tls_failure_is_read_only_and_redacted(self) -> None:
        runner = self.runner()
        self.edge_tls_validator.side_effect = EdgeTlsError("private-cert-path")
        with self.assertRaisesRegex(
            DeploymentError,
            "public edge TLS preflight failed",
        ) as raised:
            self.execute(runner)
        self.assertEqual(runner.calls, [])
        self.assertNotIn("private-cert-path", str(raised.exception))

    def test_process_compose_input_override_fails_before_checkout_and_is_redacted(self) -> None:
        runner = self.runner()
        leaked_value = "operator-private-tls-key-path"
        with mock.patch.dict(os.environ, {"PLATFORM_TLS_KEY_FILE": leaked_value}):
            with self.assertRaisesRegex(
                DeploymentError, "production Compose environment preflight failed"
            ) as raised:
                self.execute(runner)
        self.assertEqual(runner.calls, [])
        self.assertNotIn(leaked_value, str(raised.exception))

    def test_plaintext_runtime_credentials_fail_before_any_runner_call(self) -> None:
        samples = (
            "PLATFORM_VAULT_SUB2_TOKEN",
            "PLATFORM_VAULT_API_SECRET_ID",
            "ALEMBIC_DATABASE_URL",
            "POSTGRES_APP_PASSWORD",
        )
        for name in samples:
            runner = self.runner()
            sentinel = f"SENSITIVE_SENTINEL_{name}"
            with self.subTest(name=name), mock.patch.dict(
                os.environ, {name: sentinel}
            ):
                with self.assertRaisesRegex(
                    DeploymentError,
                    "^production Compose environment preflight failed$",
                ) as raised:
                    self.execute(runner)
                self.assertEqual(runner.calls, [])
                self.assertNotIn(
                    sentinel,
                    "".join(traceback.format_exception(raised.exception)),
                )

    def test_docker_target_environment_fails_before_any_runner_access(self) -> None:
        values = {
            "DOCKER_HOST": "tcp://decoy.example.invalid:2375",
            "DOCKER_CONTEXT": "decoy-context",
            "DOCKER_CONFIG": "operator-private-docker-config",
        }
        for name, nonempty_value in values.items():
            for value in (nonempty_value, ""):
                runner = self.runner()
                with self.subTest(name=name, empty=value == ""), mock.patch.dict(
                    os.environ,
                    {name: value},
                ):
                    error: DeploymentError | None = None
                    try:
                        self.execute(runner)
                    except DeploymentError as caught:
                        error = caught
                    self.assertEqual(
                        (str(error), len(runner.calls)),
                        ("production Compose environment preflight failed", 0),
                    )

    def test_docker_tls_environment_fails_before_any_runner_access(self) -> None:
        for name in ("DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
            for value in ("1", "0", "", "operator-decoy"):
                runner = self.runner()
                with self.subTest(name=name, value=value), mock.patch.dict(
                    os.environ,
                    {name: value},
                ):
                    error: DeploymentError | None = None
                    try:
                        self.execute(runner)
                    except DeploymentError as caught:
                        error = caught
                    self.assertEqual(
                        (str(error), len(runner.calls)),
                        ("production Compose environment preflight failed", 0),
                    )

    def test_compose_control_variables_are_rejected_before_git(self) -> None:
        for name in (
            "COMPOSE_PROJECT_NAME",
            "COMPOSE_PROFILES",
            "COMPOSE_ENV_FILES",
        ):
            runner = self.runner()
            with self.subTest(name=name), mock.patch.dict(os.environ, {name: "unsafe"}):
                with self.assertRaisesRegex(DeploymentError, "checkout preflight"):
                    self.execute(runner)
            self.assertEqual(runner.calls, [])

    def test_compose_commands_pin_production_env_file_and_project_name(self) -> None:
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(
            _compose("ps")[:10],
            [
                "docker",
                "compose",
                "--project-directory",
                str(root),
                "--env-file",
                str(root / ".env"),
                "--project-name",
                "email-platform",
                "-f",
                str(root / "docker-compose.yml"),
            ],
        )

    def test_preflight_failure_does_not_interrupt_current_release(self) -> None:
        runner = self.runner(fail_contains=self.plan.images["api"])
        with self.assertRaisesRegex(DeploymentError, "deployment preflight"):
            self.execute(runner)
        self.assertFalse(any(call[0][:2] == ["docker", "pull"] for call in runner.calls))
        self.assertFalse(
            any(
                call[0][COMPOSE_COMMAND_INDEX : COMPOSE_COMMAND_INDEX + 1]
                == ["stop"]
                for call in runner.calls
            )
        )

    def test_missing_monitoring_service_fails_before_pull_or_runtime_mutation(self) -> None:
        for missing in ("prometheus", "alertmanager"):
            runner = self.runner(
                running_services=tuple(
                    service for service in OPERATIONAL_SERVICES if service != missing
                )
            )
            with self.subTest(missing=missing):
                with self.assertRaisesRegex(
                    DeploymentError, "rollback readiness preflight failed"
                ):
                    self.execute(runner)
            commands = [call[0] for call in runner.calls]
            self.assertFalse(any(command[:2] == ["docker", "pull"] for command in commands))
            self.assertFalse(
                any(
                    command[:2] == ["docker", "compose"]
                    and command[COMPOSE_COMMAND_INDEX] in {"stop", "up"}
                    for command in commands
                )
            )

    def test_monitoring_loss_after_edge_start_fails_and_recloses_edge(self) -> None:
        runner = self.runner(running_services=OPERATIONAL_SERVICES)
        original_run = runner.run
        edge_up = " ".join(
            _compose("up", "-d", "--no-build", "--pull", "never", "--force-recreate", "edge")
        )

        def lose_monitoring(command, *, env=None, capture_output=False):
            prior = [" ".join(call[0]) for call in runner.calls]
            if edge_up in prior:
                runner.running_services = tuple(
                    service for service in OPERATIONAL_SERVICES if service != "prometheus"
                )
            return original_run(command, env=env, capture_output=capture_output)

        runner.run = lose_monitoring
        with self.assertRaisesRegex(DeploymentError, "edge closed"):
            self.execute(runner)
        commands = [" ".join(call[0]) for call in runner.calls]
        self.assertIn(edge_up, commands)
        self.assertEqual(commands[-1], " ".join(_compose("stop", "edge")))

    def test_upstream_scan_failure_does_not_pull_or_mutate_compose(self) -> None:
        runner = self.runner(fail_contains="redis@sha256:")
        with self.assertRaisesRegex(DeploymentError, "upstream image scan"):
            self.execute(runner)
        commands = [call[0] for call in runner.calls]
        self.assertFalse(any(command[:2] == ["docker", "pull"] for command in commands))
        self.assertFalse(
            any(
                command[COMPOSE_COMMAND_INDEX : COMPOSE_COMMAND_INDEX + 1]
                in (["stop"], ["up"])
                for command in commands
            )
        )

    def test_current_runtime_digest_mismatch_fails_without_pull_or_compose_mutation(self) -> None:
        runner = self.runner(wrong_current_service="worker-mail")
        with self.assertRaisesRegex(DeploymentError, "rollback readiness"):
            self.execute(runner)
        commands = [call[0] for call in runner.calls]
        self.assertFalse(any(command[:2] == ["docker", "pull"] for command in commands))
        self.assertFalse(
            any(
                command[COMPOSE_COMMAND_INDEX : COMPOSE_COMMAND_INDEX + 1]
                in (["stop"], ["up"])
                for command in commands
            )
        )

    def test_release_checkout_failures_are_read_only_and_redacted(self) -> None:
        cases = (
            ("head", {"git_head": "f" * 40}),
            ("worktree", {"fail_contains": "diff --quiet --no-ext-diff --"}),
            (
                "index",
                {"fail_contains": "diff --cached --quiet --no-ext-diff --"},
            ),
            ("git", {"fail_contains": "rev-parse --verify HEAD"}),
        )
        for label, options in cases:
            runner = self.runner(**options)
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    DeploymentError, "release checkout preflight failed"
                ) as raised:
                    self.execute(runner)
                self.assertTrue(runner.calls)
                self.assertTrue(all(call[0][0] == "git" for call in runner.calls))
                self.assertEqual(str(raised.exception), "release checkout preflight failed")
                self.assertNotIn("docker-compose.yml", str(raised.exception))

    def test_compose_file_and_default_override_are_rejected_before_git(self) -> None:
        runner = self.runner()
        with mock.patch.dict("os.environ", {"COMPOSE_FILE": "secret-override.yml"}):
            with self.assertRaisesRegex(DeploymentError, "checkout preflight"):
                self.execute(runner)
        self.assertEqual(runner.calls, [])

        runner = self.runner()
        with mock.patch("scripts.rollback_release.Path.exists", return_value=True):
            with self.assertRaisesRegex(DeploymentError, "checkout preflight"):
                self.execute(runner)
        self.assertEqual(runner.calls, [])

    def test_backend_failure_keeps_edge_closed(self) -> None:
        runner = self.runner(
            fail_contains=" ".join(
                _compose("up", "-d", "--no-build", "--pull", "never", "--force-recreate", "migrate")
            )
        )
        with self.assertRaisesRegex(DeploymentError, "edge closed"):
            self.execute(runner)
        commands = [" ".join(call[0]) for call in runner.calls]
        self.assertEqual(commands.count(" ".join(_compose("stop", "edge"))), 1)
        self.assertNotIn(
            " ".join(_compose("up", "-d", "--no-build", "--pull", "never", "--force-recreate", "edge")),
            commands,
        )

    def test_web_and_keycloak_internal_probe_failures_keep_edge_closed(self) -> None:
        for failed_url in (
            "https://web:8443/",
            "https://keycloak:9000/health/ready",
            "https://keycloak:8443/realms/email-platform/.well-known/openid-configuration",
        ):
            runner = self.runner(fail_contains=failed_url)
            with self.subTest(failed_url=failed_url):
                with self.assertRaisesRegex(DeploymentError, "edge closed"):
                    self.execute(runner)
                commands = [" ".join(call[0]) for call in runner.calls]
                self.assertNotIn(
                    " ".join(
                        _compose(
                            "up",
                            "-d",
                            "--no-build",
                            "--pull",
                            "never",
                            "edge",
                        )
                    ),
                    commands,
                )
                self.assertIn(" ".join(_compose("stop", "edge")), commands)

    def test_runtime_digest_mismatch_keeps_edge_closed(self) -> None:
        runner = self.runner(wrong_target_service="worker-mail")
        with self.assertRaisesRegex(DeploymentError, "edge closed"):
            self.execute(runner)
        commands = [" ".join(call[0]) for call in runner.calls]
        self.assertNotIn(
            " ".join(_compose("up", "-d", "--no-build", "--pull", "never", "--force-recreate", "edge")),
            commands,
        )
        self.assertIn(" ".join(_compose("stop", "edge")), commands)

    def test_external_smoke_failure_closes_edge_again(self) -> None:
        runner = self.runner(fail_contains=f"https://{DOMAIN}/readyz")
        with self.assertRaisesRegex(DeploymentError, "edge closed"):
            self.execute(runner)
        commands = [" ".join(call[0]) for call in runner.calls]
        edge = commands.index(
            " ".join(_compose("up", "-d", "--no-build", "--pull", "never", "--force-recreate", "edge"))
        )
        self.assertEqual(commands[-1], " ".join(_compose("stop", "edge")))
        self.assertGreater(len(commands) - 1, edge)

    def test_external_tls_identity_drift_closes_edge_again(self) -> None:
        runner = self.runner()
        original_run = runner.run

        def drift_external_peer(command, *, env=None, capture_output=False):
            if TLS_HTTP_PROBE_PROGRAM in command and f"https://{DOMAIN}/readyz" in command:
                runner.calls.append((list(command), dict(env) if env is not None else None))
                return json.dumps(
                    {"peer_sha256": "b" * 64, "tls_version": "TLSv1.3"}
                )
            return original_run(command, env=env, capture_output=capture_output)

        runner.run = drift_external_peer
        with self.assertRaisesRegex(DeploymentError, "edge closed"):
            self.execute(runner)
        commands = [" ".join(call[0]) for call in runner.calls]
        self.assertEqual(commands[-1], " ".join(_compose("stop", "edge")))
        evidence = verify_evidence(self.last_evidence_output)
        self.assertEqual(evidence["terminal_state"], "edge_closed_failure")

    def test_external_smoke_and_edge_stop_failure_report_unconfirmed_closure(self) -> None:
        runner = self.runner(fail_contains=f"https://{DOMAIN}/readyz")
        original_run = runner.run
        edge_up = " ".join(
            _compose("up", "-d", "--no-build", "--pull", "never", "--force-recreate", "edge")
        )
        edge_stop = " ".join(_compose("stop", "edge"))

        def fail_final_edge_stop(command, *, env=None, capture_output=False):
            rendered = " ".join(command)
            prior_commands = [" ".join(call[0]) for call in runner.calls]
            if rendered == edge_stop and edge_up in prior_commands:
                runner.calls.append((list(command), dict(env) if env is not None else None))
                raise subprocess.CalledProcessError(1, command, stderr="SENSITIVE_STOP_DETAIL")
            return original_run(command, env=env, capture_output=capture_output)

        runner.run = fail_final_edge_stop
        with self.assertRaisesRegex(
            DeploymentError, "edge closure could not be confirmed"
        ) as raised:
            self.execute(runner)
        self.assertNotIn("SENSITIVE_STOP_DETAIL", str(raised.exception))
        self.assertEqual(" ".join(runner.calls[-1][0]), edge_stop)
        evidence = verify_evidence(self.last_evidence_output)
        self.assertEqual(evidence["terminal_state"], "edge_unconfirmed")
        self.assertEqual(evidence["edge"]["final_state"], "unconfirmed")

    def test_confirmation_and_manifest_hash_fail_before_commands(self) -> None:
        for tag, digest in (("v9.9.9", self.plan.container_manifest_sha256), (TAG, "0" * 64)):
            runner = self.runner()
            with self.subTest(tag=tag, digest=digest):
                with self.assertRaises(DeploymentError):
                    execute_deployment(
                        self.plan,
                        confirm_release_tag=tag,
                        container_manifest_sha256=digest,
                        domain=DOMAIN,
                        evidence_output=self.evidence_output(),
                        target_intake_manifest=self.target_intake_manifest,
                        target_environment="staging",
                        runner=runner,
                    )
                self.assertEqual(runner.calls, [])
                evidence = verify_evidence(self.last_evidence_output)
                self.assertEqual(evidence["terminal_state"], "preflight_failed")
                self.assertEqual(evidence["edge"]["final_state"], "not_mutated")

    def test_release_lock_contention_writes_preflight_evidence_without_runner(self) -> None:
        runner = self.runner()
        evidence_output = self.evidence_output()
        with mock.patch(
            "scripts.deploy_release.release_control_lock",
            side_effect=ReleaseControlLocked("SENSITIVE_LOCK_DETAIL"),
        ):
            with self.assertRaisesRegex(
                DeploymentError, "^another release control operation is active$"
            ) as raised:
                execute_deployment(
                    self.plan,
                    confirm_release_tag=TAG,
                    container_manifest_sha256=self.plan.container_manifest_sha256,
                    domain=DOMAIN,
                    evidence_output=evidence_output,
                    target_intake_manifest=self.target_intake_manifest,
                    target_environment="staging",
                    runner=runner,
                )
        self.assertEqual(runner.calls, [])
        self.assertNotIn("SENSITIVE_LOCK_DETAIL", str(raised.exception))
        self.assertEqual(
            verify_evidence(evidence_output)["terminal_state"], "preflight_failed"
        )

    def test_unsafe_evidence_output_fails_before_lock_and_runner(self) -> None:
        runner = self.runner()
        repository_output = Path(__file__).resolve().parents[1] / "unsafe-evidence.json"
        for output in (Path("relative-evidence.json"), repository_output):
            with self.subTest(output=output), mock.patch(
                "scripts.deploy_release.release_control_lock"
            ) as release_lock:
                with self.assertRaisesRegex(DeploymentError, "evidence preflight"):
                    execute_deployment(
                        self.plan,
                        confirm_release_tag=TAG,
                        container_manifest_sha256=self.plan.container_manifest_sha256,
                        domain=DOMAIN,
                        evidence_output=output,
                        target_intake_manifest=self.target_intake_manifest,
                        target_environment="staging",
                        runner=runner,
                    )
                release_lock.assert_not_called()
                self.assertEqual(runner.calls, [])

    def test_phase0_intake_failure_precedes_evidence_lock_and_runner(self) -> None:
        runner = self.runner()
        self.intake_validator.side_effect = ValueError("private intake detail")
        with mock.patch("scripts.deploy_release.SubprocessRunner") as constructor, mock.patch(
            "scripts.deploy_release.release_control_lock"
        ) as release_lock:
            with self.assertRaisesRegex(
                DeploymentError, "^target intake Phase 0 preflight failed$"
            ) as raised:
                execute_deployment(
                    self.plan,
                    confirm_release_tag=TAG,
                    container_manifest_sha256=self.plan.container_manifest_sha256,
                    domain=DOMAIN,
                    evidence_output=self.evidence_output(),
                    target_intake_manifest=self.target_intake_manifest,
                    target_environment="staging",
                    runner=runner,
                )
        constructor.assert_not_called()
        release_lock.assert_not_called()
        self.assertEqual(runner.calls, [])
        self.assertNotIn("private intake detail", str(raised.exception))

    def test_keyboard_interrupt_recloses_edge_writes_evidence_and_propagates(self) -> None:
        runner = self.runner()
        original_run = runner.run

        def interrupt_external(command, *, env=None, capture_output=False):
            if f"https://{DOMAIN}/readyz" in command:
                runner.calls.append((list(command), dict(env) if env is not None else None))
                raise KeyboardInterrupt
            return original_run(command, env=env, capture_output=capture_output)

        runner.run = interrupt_external
        with self.assertRaises(KeyboardInterrupt):
            self.execute(runner)
        commands = [" ".join(command) for command, _ in runner.calls]
        self.assertEqual(commands[-1], " ".join(_compose("stop", "edge")))
        evidence = verify_evidence(self.last_evidence_output)
        self.assertEqual(evidence["terminal_state"], "edge_closed_failure")
        self.assertEqual(evidence["edge"]["final_state"], "closed_confirmed")

    def test_success_evidence_publication_failure_recloses_edge(self) -> None:
        runner = self.runner()
        with mock.patch(
            "scripts.deploy_release._publish_evidence",
            side_effect=DeploymentError("deployment evidence publication failed"),
        ):
            with self.assertRaisesRegex(
                DeploymentError,
                "^deployment evidence publication failed; public edge was closed$",
            ):
                self.execute(runner)
        commands = [" ".join(command) for command, _ in runner.calls]
        edge_up = " ".join(
            _compose("up", "-d", "--no-build", "--pull", "never", "--force-recreate", "edge")
        )
        self.assertIn(edge_up, commands)
        self.assertEqual(commands[-1], " ".join(_compose("stop", "edge")))

    def test_manifest_rejects_mutable_digest_and_non_ghcr_image(self) -> None:
        for field, value in (
            ("digest", "latest"),
            ("digest", "sha256:" + "f" * 63),
            ("image", "docker.io/example/manage-api"),
        ):
            manifest = _manifest()
            images = manifest["images"]
            assert isinstance(images, dict)
            api = images["api"]
            assert isinstance(api, dict)
            api[field] = value
            self.manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.subTest(field=field, value=value):
                with self.assertRaisesRegex(DeploymentError, "manifest is invalid"):
                    self.load_plan()

    def test_stale_and_future_rollback_points_are_rejected(self) -> None:
        for label, created_at, expected in (
            ("stale", NOW - timedelta(hours=1, seconds=1), "stale"),
            ("future", NOW + timedelta(minutes=5, seconds=1), "future"),
        ):
            root = self.root / label
            root.mkdir()
            rollback_manifest, backup_dir, key_file = _write_rollback_fixture(
                root,
                created_at=created_at,
            )
            with self.subTest(label=label):
                with self.assertRaisesRegex(DeploymentError, expected):
                    self.load_plan(
                        rollback_manifest_path=rollback_manifest,
                        rollback_backup_dir=backup_dir,
                        rollback_key_file=key_file,
                    )

    def test_redis_stale_future_and_cross_store_time_drift_are_rejected(self) -> None:
        cases = (
            (
                "redis-stale",
                NOW - timedelta(hours=1, seconds=1),
                NOW - timedelta(minutes=56, seconds=1),
                "stale",
            ),
            (
                "redis-future",
                NOW + timedelta(minutes=5, seconds=1),
                NOW + timedelta(minutes=1),
                "future",
            ),
            (
                "cross-store-drift",
                NOW - timedelta(minutes=3),
                NOW - timedelta(minutes=10),
                "authenticated rollback point is invalid",
            ),
        )
        for label, redis_created_at, postgres_created_at, expected in cases:
            root = self.root / label
            rollback_manifest, backup_dir, key_file = _write_rollback_fixture(
                root,
                created_at=postgres_created_at,
            )
            (root / "redis-backup" / "fixture-created-at.txt").write_text(
                redis_created_at.isoformat(), encoding="utf-8"
            )
            with self.subTest(label=label):
                with self.assertRaisesRegex(DeploymentError, expected):
                    self.load_plan(
                        rollback_manifest_path=rollback_manifest,
                        rollback_backup_dir=backup_dir,
                        rollback_key_file=key_file,
                    )

    def test_missing_tampered_and_wrong_set_redis_points_fail_preflight(self) -> None:
        for label, error, recovery_set in (
            ("missing", FileNotFoundError("missing Redis backup"), RECOVERY_SET),
            ("tampered", ValueError("Redis authentication failed"), RECOVERY_SET),
            ("wrong-set", None, "release-v9.9.9-wrong"),
        ):
            with self.subTest(label=label):
                if error is None:
                    context = mock.patch(
                        "scripts.rollback_release.verify_release_backup",
                        side_effect=self._verify_redis_fixture,
                    )
                else:
                    context = mock.patch(
                        "scripts.rollback_release.verify_release_backup",
                        side_effect=error,
                    )
                with context:
                    with self.assertRaisesRegex(
                        DeploymentError, "authenticated rollback point is invalid"
                    ):
                        self.load_plan(rollback_recovery_set=recovery_set)

    def test_old_deployment_plan_call_without_redis_point_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            load_deployment_plan(
                self.manifest_path,
                rollback_container_manifest_path=self.rollback_manifest_path,
                rollback_backup_dir=self.rollback_backup_dir,
                rollback_key_file=self.rollback_key_file,
                now=NOW,
            )

    def test_legacy_release_bundle_is_not_a_deployment_rollback_point(self) -> None:
        rollback_manifest, backup_dir, key_file = _write_rollback_fixture(
            self.root / "legacy-schema",
            created_at=NOW - timedelta(minutes=10),
            schema_version=4,
        )
        with self.assertRaisesRegex(
            DeploymentError, "authenticated rollback point is invalid"
        ):
            self.load_plan(
                rollback_manifest_path=rollback_manifest,
                rollback_backup_dir=backup_dir,
                rollback_key_file=key_file,
            )

    def _rewrite_backup_manifest(self, mutate) -> None:
        path = self.rollback_backup_dir / "manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        mutate(manifest)
        key = self.rollback_key_file.read_bytes()
        manifest["manifest_hmac_sha256"] = _manifest_hmac_sha256(manifest, key)
        path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")

    def test_wrong_binding_key_and_missing_database_fail_closed_without_secret_leak(self) -> None:
        cases = (
            ("binding", lambda manifest: manifest.__setitem__("release_tag", "v9.9.9"), None),
            (
                "missing-db",
                lambda manifest: manifest["databases"].pop("keycloak"),
                None,
            ),
            ("wrong-key", None, b"different-rollback-key-material!"),
        )
        for label, mutate, wrong_key in cases:
            with self.subTest(label=label):
                if mutate is not None:
                    self._rewrite_backup_manifest(mutate)
                key_path = self.rollback_key_file
                if wrong_key is not None:
                    self.assertEqual(len(wrong_key), 32)
                    key_path = self.root / "wrong-secret.key"
                    key_path.write_bytes(wrong_key)
                with self.assertRaisesRegex(
                    DeploymentError, "authenticated rollback point is invalid"
                ) as raised:
                    self.load_plan(rollback_key_file=key_path)
                message = str(raised.exception)
                self.assertNotIn(str(key_path), message)
                self.assertNotIn("different-rollback-key-material", message)
                if mutate is not None:
                    (
                        self.rollback_manifest_path,
                        self.rollback_backup_dir,
                        self.rollback_key_file,
                    ) = _write_rollback_fixture(
                        self.root / f"reset-{label}",
                        created_at=NOW - timedelta(minutes=10),
                    )


if __name__ == "__main__":
    unittest.main()
