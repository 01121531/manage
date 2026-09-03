import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import traceback
import unittest
from contextlib import redirect_stderr
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from uuid import uuid4

from scripts.rollback_release import (
    ComposeEnvironmentError,
    FORBIDDEN_PRODUCTION_CREDENTIAL_VARIABLES,
    PRODUCTION_COMPOSE,
    PRODUCTION_ENV_FILE,
    RollbackError,
    SubprocessRunner,
    _compose,
    _external_smoke,
    _validated_third_party_image_environment,
    execute_rollback as _execute_rollback,
    load_rollback_plan as _load_rollback_plan,
    main as rollback_main,
    plan_summary,
)
from scripts.rollback_release_evidence import (
    RollbackReleaseEvidenceError,
    TERMINAL_EDGE_CLOSED_FAILURE,
    TERMINAL_EDGE_UNCONFIRMED,
    TERMINAL_PREFLIGHT_FAILED,
    TERMINAL_SUCCEEDED,
    assert_expected_release,
    seal_evidence,
    validate_evidence,
    verify_evidence,
)
from scripts.validate_edge_tls import EdgeTlsError
from scripts.tls_runtime_identity import INTERNAL_ENDPOINT_SERVICES, TLS_HTTP_PROBE_PROGRAM
from scripts.vault_token_sinks import VaultTokenSinkError
from scripts.backup_crypto import ALGORITHM, FORMAT_VERSION, encrypt_stream, key_id
from scripts.postgres_maintenance import _manifest_hmac_sha256
from scripts.release_control_lock import ReleaseControlLocked
from scripts.restore_readiness import (
    PROBE_CONTAINER,
    PROBES,
    TLS_PROBE_PROGRAM,
    restore_contract_errors,
)
from scripts.verify_runbooks import ROOT, rollback_runbook_errors


TAG = "v1.2.3"
COMMIT = "a" * 40
MIGRATION_HEAD = "0014_audit_evidence_fields"
DIGEST = "sha256:" + "b" * 64
ISSUER = "https://token.actions.githubusercontent.com"
RECOVERY_SET = "release-v1.2.3-20260820T000000Z"
BACKUP_CREATED_AT = datetime(2026, 8, 20, tzinfo=timezone.utc)
TLS_FINGERPRINT = "a" * 64
TLS_FINGERPRINTS = {
    service: TLS_FINGERPRINT for service in set(INTERNAL_ENDPOINT_SERVICES.values())
}
THIRD_PARTY_DIGEST_ENV = {
    "POSTGRES_IMAGE_SHA256": "1" * 64,
    "REDIS_IMAGE_SHA256": "2" * 64,
    "KEYCLOAK_IMAGE_SHA256": "3" * 64,
    "ALERTMANAGER_IMAGE_SHA256": "4" * 64,
    "PROMETHEUS_IMAGE_SHA256": "5" * 64,
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


def execute_rollback(plan, *, evidence_output: Path | None = None, **kwargs):
    output = evidence_output or (
        plan.redis_backup_dir.parent / f"rollback-evidence-{uuid4().hex}.json"
    )
    return _execute_rollback(plan, evidence_output=output, **kwargs)


def load_rollback_plan(
    manifest_path: Path,
    backup_dir: Path,
    key_file: Path,
    *,
    redis_backup_dir: Path | None = None,
    recovery_set: str = RECOVERY_SET,
):
    return _load_rollback_plan(
        manifest_path,
        backup_dir,
        key_file,
        redis_backup_dir=redis_backup_dir or backup_dir.parent / "redis-backup",
        recovery_set=recovery_set,
    )


def _image_metadata(name: str) -> dict[str, object]:
    return {
        "image": f"ghcr.io/example/manage-{name}",
        "digest": DIGEST,
        "sbom": {"file": f"{name}.spdx.json", "sha256": "c" * 64},
        "scan": {
            "tool": "trivy",
            "severities": ["HIGH", "CRITICAL"],
            "result": "passed",
            "file": f"{name}.trivy.sarif",
            "sha256": "d" * 64,
        },
        "signature": {
            "issuer": ISSUER,
            "identity": (
                "https://github.com/example/manage/.github/workflows/"
                f"release.yml@refs/tags/{TAG}"
            ),
        },
        "attestations": ["cosign-spdxjson", "github-build-provenance"],
    }


def _write_fixture(root: Path, *, schema_version: int = 5) -> tuple[Path, Path, Path]:
    manifest_path = root / "container-release-manifest.json"
    container_manifest = {
        "schema_version": 1,
        "tag": TAG,
        "commit": COMMIT,
        "migration_head": MIGRATION_HEAD,
        "images": {
            name: _image_metadata(name) for name in ("api", "web", "edge")
        },
    }
    manifest_path.write_text(
        json.dumps(container_manifest, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()

    backup_dir = root / "backup"
    backup_dir.mkdir()
    key_file = root / "backup.key"
    key = b"r" * 32
    key_file.write_bytes(key)
    databases: dict[str, dict[str, object]] = {}
    for logical_name, database in (
        ("platform", "email_platform"),
        ("keycloak", "keycloak"),
    ):
        data = f"{logical_name}-backup".encode()
        artifact = f"{logical_name}.dump.enc"
        with (backup_dir / artifact).open("wb") as destination:
            encrypt_stream(
                io.BytesIO(data),
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
    backup_manifest: dict[str, object] = {
        "schema_version": schema_version,
        "created_at": "2026-08-20T00:00:00+00:00",
        "databases": databases,
    }
    if schema_version in {4, 5}:
        backup_manifest.update(
            {
                "release_tag": TAG,
                "release_commit": COMMIT,
                "migration_head": MIGRATION_HEAD,
                "container_manifest_sha256": manifest_sha256,
            }
        )
    if schema_version == 5:
        backup_manifest["manifest_hmac_sha256"] = _manifest_hmac_sha256(
            backup_manifest,
            key,
        )
    (backup_dir / "manifest.json").write_text(
        json.dumps(backup_manifest, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    redis_backup_dir = root / "redis-backup"
    redis_backup_dir.mkdir(exist_ok=True)
    (redis_backup_dir / "redis-manifest.json").write_text(
        '{"schema_version":1}\n', encoding="utf-8"
    )
    return manifest_path, backup_dir, key_file


class RecordingRunner:
    def __init__(
        self,
        images: dict[str, str],
        *,
        running_services: tuple[str, ...] | None = None,
    ) -> None:
        self.images = images
        self.git_head = COMMIT
        self.calls: list[tuple[list[str], dict[str, str]]] = []
        self.fail_contains: str | None = None
        self.mismatched_service: str | None = None
        self.running_services = running_services or OPERATIONAL_SERVICES
        self.tls_fingerprint = TLS_FINGERPRINT

    def run(self, command, *, env=None, capture_output=False):
        rendered = [str(item) for item in command]
        environment = dict(env or {})
        self.calls.append((rendered, environment))
        joined = " ".join(rendered)
        if self.fail_contains and self.fail_contains in joined:
            raise subprocess.CalledProcessError(1, rendered)
        if rendered[:2] == ["git", "-C"] and rendered[3:] == [
            "rev-parse",
            "--verify",
            "HEAD",
        ]:
            return self.git_head + "\n"
        compose = (
            rendered[COMPOSE_COMMAND_INDEX:]
            if rendered[:2] == ["docker", "compose"]
            else []
        )
        if compose[:2] == ["ps", "-q"]:
            return f"{compose[2]}-id\n"
        if rendered[:3] == ["docker", "inspect", "--format"]:
            service = rendered[-1].removesuffix("-id")
            if service == self.mismatched_service:
                return "ghcr.io/example/wrong@sha256:" + "e" * 64 + "\n"
            image_name = "api" if service in {"api", "worker-mail", "worker-sub2"} else service
            return self.images[image_name] + "\n"
        if compose == [
            "ps",
            "--status",
            "running",
            "--services",
        ]:
            return "\n".join(self.running_services) + "\n"
        if TLS_HTTP_PROBE_PROGRAM in rendered:
            return json.dumps(
                {
                    "peer_sha256": self.tls_fingerprint,
                    "tls_version": "TLSv1.3",
                }
            )
        return ""


class RollbackReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        digest_env_patch = mock.patch.dict(
            os.environ, THIRD_PARTY_DIGEST_ENV, clear=True
        )
        digest_env_patch.start()
        self.addCleanup(digest_env_patch.stop)
        patcher = mock.patch(
            "scripts.backup_crypto._validate_key_permissions",
            return_value=None,
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        redis_verifier = mock.patch(
            "scripts.rollback_release.verify_release_backup",
            return_value=({}, BACKUP_CREATED_AT, "e" * 64),
        )
        self.redis_verifier = redis_verifier.start()
        self.addCleanup(redis_verifier.stop)
        edge_tls = mock.patch(
            "scripts.rollback_release.validate_edge_tls",
            return_value=TLS_FINGERPRINT,
        )
        self.edge_tls_validator = edge_tls.start()
        self.addCleanup(edge_tls.stop)
        internal_tls = mock.patch(
            "scripts.rollback_release.expected_internal_fingerprints",
            return_value=TLS_FINGERPRINTS,
        )
        self.internal_tls_validator = internal_tls.start()
        self.addCleanup(internal_tls.stop)
        vault_sinks = mock.patch(
            "scripts.rollback_release.validate_vault_token_sinks"
        )
        self.vault_sink_validator = vault_sinks.start()
        self.addCleanup(vault_sinks.stop)
        sub2_egress = mock.patch(
            "scripts.rollback_release.validate_sub2_egress_policy"
        )
        self.sub2_egress_validator = sub2_egress.start()
        self.addCleanup(sub2_egress.stop)

    def test_rollback_runbook_is_executable_and_has_no_legacy_path(self) -> None:
        text = (ROOT / "deploy" / "runbooks" / "rollback.md").read_text(
            encoding="utf-8"
        )
        self.assertEqual(rollback_runbook_errors(text), [])
        self.assertTrue(
            rollback_runbook_errors(
                text + "\npython -m scripts.postgres_maintenance restore --input old.dump\n"
            )
        )
        self.assertTrue(
            rollback_runbook_errors(
                text.replace("--confirm-release-tag", "--skip-confirmation")
            )
        )
        self.assertTrue(
            rollback_runbook_errors(
                text.replace(
                    "authenticated encrypted schema-v5",
                    "encrypted schema-v4",
                )
            )
        )
        self.assertTrue(
            rollback_runbook_errors(
                text.replace(
                    "`GH_TOKEN` is copied only",
                    "GitHub credentials are inherited by every tool",
                )
            )
        )

    def test_plan_requires_release_bound_dual_database_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, backup_dir, key_file = _write_fixture(root)
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            summary = plan_summary(plan)
            self.assertEqual(summary["release_tag"], TAG)
            self.assertEqual(
                summary["database_bundle"], "platform+keycloak+redis"
            )
            self.assertEqual(summary["recovery_set"], RECOVERY_SET)
            self.assertEqual(summary["max_recovery_point_skew_seconds"], 300)
            self.assertEqual(
                summary["redis_backup_created_at"],
                BACKUP_CREATED_AT.isoformat(),
            )
            self.assertFalse(summary["production_acceptance"])
            self.assertTrue(plan.images["api"].endswith("@" + DIGEST))

            legacy_root = root / "legacy"
            legacy_root.mkdir()
            legacy_manifest, legacy_backup, legacy_key = _write_fixture(
                legacy_root, schema_version=1
            )
            with self.assertRaisesRegex(ValueError, "unsupported backup manifest schema"):
                load_rollback_plan(legacy_manifest, legacy_backup, legacy_key)

            v4_root = root / "v4"
            v4_root.mkdir()
            v4_manifest, v4_backup, v4_key = _write_fixture(
                v4_root, schema_version=4
            )
            with self.assertRaisesRegex(ValueError, "schema v4"):
                load_rollback_plan(v4_manifest, v4_backup, v4_key)

    def test_plan_rejects_container_manifest_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            backup_manifest_path = backup_dir / "manifest.json"
            backup_manifest = json.loads(
                backup_manifest_path.read_text(encoding="utf-8")
            )
            backup_manifest["container_manifest_sha256"] = "f" * 64
            backup_manifest_path.write_text(
                json.dumps(backup_manifest), encoding="utf-8"
            )
            with self.assertRaisesRegex(
                ValueError, "authentication"
            ):
                load_rollback_plan(manifest_path, backup_dir, key_file)

    def test_execute_orders_verification_restore_and_edge_last(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            runner = RecordingRunner(plan.images)
            execute_rollback(
                plan,
                confirm_release_tag=TAG,
                platform_target_db="email_platform",
                keycloak_target_db="keycloak",
                domain="platform.example.invalid",
                runner=runner,
            )

        commands = [" ".join(command) for command, _ in runner.calls]
        cosign_index = next(
            index for index, command in enumerate(commands) if command.startswith("cosign verify ")
        )
        pull_index = next(
            index for index, command in enumerate(commands) if command.startswith("docker pull ")
        )
        stop_index = commands.index(
            " ".join(
                _compose(
                    "stop",
                    "edge",
                    "api",
                    "worker-mail",
                    "worker-sub2",
                    "web",
                    "keycloak",
                    "redis",
                )
            )
        )
        restore_index = next(
            index
            for index, command in enumerate(commands)
            if "scripts.postgres_maintenance restore-bundle" in command
        )
        redis_restore_index = next(
            index
            for index, command in enumerate(commands)
            if "scripts.redis_maintenance restore-release" in command
        )
        redis_up_index = commands.index(
            " ".join(
                _compose(
                    "up", "-d", "--no-build", "--pull", "never", "redis"
                )
            )
        )
        redis_health_index = commands.index(
            " ".join(
                _compose(
                    "exec", "-T", "redis", "/usr/local/bin/redis-healthcheck"
                )
            )
        )
        backend_up_index = next(
            index
            for index, command in enumerate(commands)
            if " ".join(_compose("up")) in command and command.endswith("web")
        )
        edge_up_index = commands.index(
            " ".join(_compose("up", "-d", "--no-build", "--pull", "never", "--force-recreate", "edge"))
        )
        self.assertLess(cosign_index, pull_index)
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
        self.assertLess(pull_index, stop_index)
        self.assertLess(stop_index, restore_index)
        self.assertLess(restore_index, redis_restore_index)

        self.assertLess(redis_restore_index, redis_up_index)
        self.assertLess(redis_up_index, redis_health_index)
        self.assertLess(redis_health_index, backend_up_index)
        self.assertLess(backend_up_index, edge_up_index)
        self.assertEqual(
            self.vault_sink_validator.call_args_list,
            [
                mock.call(PRODUCTION_ENV_FILE, PRODUCTION_COMPOSE),
                mock.call(PRODUCTION_ENV_FILE, PRODUCTION_COMPOSE),
            ],
        )
        self.assertIn("--release-tag v1.2.3", commands[restore_index])
        self.assertIn(f"--key-file {plan.key_file}", commands[restore_index])
        self.assertNotIn((b"r" * 32).decode(), commands[restore_index])
        self.assertIn("--container-manifest-sha256", commands[restore_index])
        self.assertIn(
            f"--postgres-manifest {plan.postgres_manifest_path}",
            commands[redis_restore_index],
        )
        self.assertNotIn("--postgres-manifest-sha256", commands[redis_restore_index])
        self.assertIn(
            f"--confirm-release-tag {TAG}", commands[redis_restore_index]
        )
        self.assertEqual(
            runner.calls[stop_index][1]["PLATFORM_API_IMAGE"],
            plan.images["api"],
        )
        compose_prefix = _compose("unused")[:-1]
        self.assertTrue(
            all(
                command[: len(compose_prefix)] == compose_prefix
                for command, _ in runner.calls
                if command[:2] == ["docker", "compose"]
            )
        )
        smoke_calls = [
            command
            for command, _ in runner.calls
            if command[COMPOSE_COMMAND_INDEX : COMPOSE_COMMAND_INDEX + 2]
            == ["exec", "-T"]
            and TLS_HTTP_PROBE_PROGRAM in command
        ]
        self.assertEqual(
            {
                command[command.index(TLS_HTTP_PROBE_PROGRAM) + 1]
                for command in smoke_calls
            },
            set(PROBES),
        )
        self.assertEqual(restore_contract_errors(), [])
        for command in smoke_calls:
            program = command[command.index("-c") + 1]
            self.assertEqual(command[COMPOSE_COMMAND_INDEX + 2], PROBE_CONTAINER)
            self.assertEqual(program, TLS_HTTP_PROBE_PROGRAM)
            self.assertIn("http.client.HTTPSConnection", program)
            self.assertIn("TLSVersion.TLSv1_2", program)
            self.assertIn("getpeercert(binary_form=True)", program)
            self.assertIn("connection.request", program)
            self.assertNotIn("CERT_NONE", program)
            self.assertNotIn("check_hostname=False", program)

    def test_vault_sink_preflight_failure_precedes_runner_construction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            private_detail = "D:/private/vault-agent/sub2/token"
            self.vault_sink_validator.side_effect = VaultTokenSinkError(
                private_detail
            )
            with mock.patch("scripts.rollback_release.SubprocessRunner") as constructor:
                with self.assertRaisesRegex(
                    RollbackError,
                    "^production Vault token sink preflight failed$",
                ) as raised:
                    execute_rollback(
                        plan,
                        confirm_release_tag=TAG,
                        platform_target_db="email_platform",
                        keycloak_target_db="keycloak",
                        domain="platform.example.invalid",
                    )
        constructor.assert_not_called()
        self.assertNotIn(private_detail, str(raised.exception))

    def test_vault_sink_recheck_fails_after_restore_and_smoke_before_edge(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            runner = RecordingRunner(plan.images)
            private_detail = "D:/private/vault-agent/api/token"
            checks = 0

            def validate(_env_file: Path, _compose_file: Path) -> None:
                nonlocal checks
                checks += 1
                commands = [" ".join(command) for command, _ in runner.calls]
                if checks == 1:
                    self.assertEqual(commands, [])
                    return
                self.assertTrue(
                    any("scripts.postgres_maintenance restore-bundle" in command for command in commands)
                )
                self.assertTrue(
                    any("scripts.redis_maintenance restore-release" in command for command in commands)
                )
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
                RollbackError,
                "^Vault token sink recheck failed with public edge closed$",
            ) as raised:
                execute_rollback(
                    plan,
                    confirm_release_tag=TAG,
                    platform_target_db="email_platform",
                    keycloak_target_db="keycloak",
                    domain="platform.example.invalid",
                    runner=runner,
                )

        commands = [" ".join(command) for command, _ in runner.calls]
        self.assertEqual(checks, 2)
        self.assertNotIn(private_detail, str(raised.exception))
        self.assertNotIn(
            " ".join(_compose("up", "-d", "--no-build", "--pull", "never", "--force-recreate", "edge")),
            commands,
        )

    def test_invalid_third_party_digest_fails_before_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            runner = RecordingRunner(plan.images)
            with mock.patch.dict(
                os.environ,
                {"REDIS_IMAGE_SHA256": "redis:7-alpine"},
            ):
                with self.assertRaisesRegex(
                    RollbackError, "REDIS_IMAGE_SHA256"
                ):
                    execute_rollback(
                        plan,
                        confirm_release_tag=TAG,
                        platform_target_db="email_platform",
                        keycloak_target_db="keycloak",
                        domain="platform.example.invalid",
                        runner=runner,
                    )
            self.assertEqual(runner.calls, [])

    def test_process_compose_input_override_fails_before_checkout_and_is_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            runner = RecordingRunner(plan.images)
            leaked_value = "operator-private-postgres-role"
            with mock.patch.dict(os.environ, {"POSTGRES_USER": leaked_value}):
                with self.assertRaisesRegex(
                    RollbackError, "production Compose environment preflight failed"
                ) as raised:
                    execute_rollback(
                        plan,
                        confirm_release_tag=TAG,
                        platform_target_db="email_platform",
                        keycloak_target_db="keycloak",
                        domain="platform.example.invalid",
                        runner=runner,
                    )
            self.assertEqual(runner.calls, [])
            self.assertNotIn(leaked_value, str(raised.exception))

    def test_plaintext_production_credential_inventory_fails_by_presence(self) -> None:
        safe_environment = dict(THIRD_PARTY_DIGEST_ENV)
        safe_environment.update(
            {
                "PATH": "reviewed-tool-path",
                "GH_TOKEN": "reviewed-supply-chain-auth",
                "PYTHONPATH": "unreviewed-python-path",
                "HTTPS_PROXY": "http://unreviewed-proxy.invalid",
                "TRIVY_SERVER": "https://unreviewed-trivy.invalid",
            }
        )
        validated = _validated_third_party_image_environment(safe_environment)
        self.assertEqual(set(validated), {*THIRD_PARTY_DIGEST_ENV, "PATH"})
        self.assertNotIn("GH_TOKEN", validated)
        for name in FORBIDDEN_PRODUCTION_CREDENTIAL_VARIABLES:
            for value in ("", "SENSITIVE_SENTINEL"):
                with self.subTest(name=name, value=value):
                    environment = dict(safe_environment)
                    environment[name] = value
                    with self.assertRaisesRegex(
                        ComposeEnvironmentError,
                        "^production Compose environment preflight failed$",
                    ) as raised:
                        _validated_third_party_image_environment(environment)
                    rendered = "".join(
                        traceback.format_exception(raised.exception)
                    )
                    self.assertNotIn(name, rendered)
                    if value:
                        self.assertNotIn(value, rendered)

    def test_subprocess_runner_requires_an_explicit_environment(self) -> None:
        with mock.patch("scripts.rollback_release.subprocess.run") as run:
            with self.assertRaisesRegex(
                RollbackError, "^explicit subprocess environment is required$"
            ):
                SubprocessRunner().run(["must-not-run"])
        run.assert_not_called()

    def test_github_token_is_scoped_only_to_github_attestation_calls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            runner = RecordingRunner(plan.images)
            with mock.patch.dict(
                os.environ,
                {
                    "GH_TOKEN": "SENSITIVE_GITHUB_SENTINEL",
                    "PYTHONPATH": "SENSITIVE_PYTHON_SENTINEL",
                    "HTTPS_PROXY": "SENSITIVE_PROXY_SENTINEL",
                    "TRIVY_SERVER": "SENSITIVE_TRIVY_SENTINEL",
                },
            ):
                execute_rollback(
                    plan,
                    confirm_release_tag=TAG,
                    platform_target_db="email_platform",
                    keycloak_target_db="keycloak",
                    domain="platform.example.invalid",
                    runner=runner,
                )

        github_calls = 0
        for command, environment in runner.calls:
            is_github_attestation = command[:3] == ["gh", "attestation", "verify"]
            if is_github_attestation:
                github_calls += 1
                self.assertEqual(
                    environment.get("GH_TOKEN"), "SENSITIVE_GITHUB_SENTINEL"
                )
            else:
                self.assertNotIn("GH_TOKEN", environment)
            self.assertNotIn("PYTHONPATH", environment)
            self.assertNotIn("HTTPS_PROXY", environment)
            self.assertNotIn("TRIVY_SERVER", environment)
        self.assertEqual(github_calls, 3)

    def test_plaintext_runtime_credentials_fail_before_any_runner_call(self) -> None:
        samples = (
            "PLATFORM_VAULT_API_TOKEN",
            "PLATFORM_VAULT_MAIL_SECRET_ID",
            "PLATFORM_DATABASE_URL",
            "REDIS_HEALTHCHECK_PASSWORD",
        )
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            for name in samples:
                runner = RecordingRunner(plan.images)
                sentinel = f"SENSITIVE_SENTINEL_{name}"
                with self.subTest(name=name), mock.patch.dict(
                    os.environ, {name: sentinel}
                ):
                    with self.assertRaisesRegex(
                        RollbackError,
                        "^production Compose environment preflight failed$",
                    ) as raised:
                        execute_rollback(
                            plan,
                            confirm_release_tag=TAG,
                            platform_target_db="email_platform",
                            keycloak_target_db="keycloak",
                            domain="platform.example.invalid",
                            runner=runner,
                        )
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
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            for name, nonempty_value in values.items():
                for value in (nonempty_value, ""):
                    runner = RecordingRunner(plan.images)
                    with self.subTest(name=name, empty=value == ""), mock.patch.dict(
                        os.environ,
                        {name: value},
                    ):
                        error: RollbackError | None = None
                        try:
                            execute_rollback(
                                plan,
                                confirm_release_tag=TAG,
                                platform_target_db="email_platform",
                                keycloak_target_db="keycloak",
                                domain="platform.example.invalid",
                                runner=runner,
                            )
                        except RollbackError as caught:
                            error = caught
                        self.assertEqual(
                            (str(error), len(runner.calls)),
                            ("production Compose environment preflight failed", 0),
                        )

    def test_docker_tls_environment_fails_before_any_runner_access(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            for name in ("DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
                for value in ("1", "0", "", "operator-decoy"):
                    runner = RecordingRunner(plan.images)
                    with self.subTest(name=name, value=value), mock.patch.dict(
                        os.environ,
                        {name: value},
                    ):
                        error: RollbackError | None = None
                        try:
                            execute_rollback(
                                plan,
                                confirm_release_tag=TAG,
                                platform_target_db="email_platform",
                                keycloak_target_db="keycloak",
                                domain="platform.example.invalid",
                                runner=runner,
                            )
                        except RollbackError as caught:
                            error = caught
                        self.assertEqual(
                            (str(error), len(runner.calls)),
                            ("production Compose environment preflight failed", 0),
                        )

    def test_compose_control_variables_are_rejected_before_git(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            for name in (
                "COMPOSE_PROJECT_NAME",
                "COMPOSE_PROFILES",
                "COMPOSE_ENV_FILES",
            ):
                runner = RecordingRunner(plan.images)
                with self.subTest(name=name), mock.patch.dict(
                    os.environ, {name: "unsafe"}
                ):
                    with self.assertRaisesRegex(RollbackError, "checkout preflight"):
                        execute_rollback(
                            plan,
                            confirm_release_tag=TAG,
                            platform_target_db="email_platform",
                            keycloak_target_db="keycloak",
                            domain="platform.example.invalid",
                            runner=runner,
                        )
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

    def test_internal_tls_smoke_failure_keeps_edge_closed(self) -> None:
        for failed_url in (
            "https://web:8443/",
            "https://keycloak:9000/health/ready",
            "https://keycloak:8443/realms/email-platform/.well-known/openid-configuration",
        ):
            with tempfile.TemporaryDirectory() as directory:
                manifest_path, backup_dir, key_file = _write_fixture(
                    Path(directory)
                )
                plan = load_rollback_plan(manifest_path, backup_dir, key_file)
                runner = RecordingRunner(plan.images)
                runner.fail_contains = failed_url
                with self.subTest(failed_url=failed_url):
                    with self.assertRaises(subprocess.CalledProcessError):
                        execute_rollback(
                            plan,
                            confirm_release_tag=TAG,
                            platform_target_db="email_platform",
                            keycloak_target_db="keycloak",
                            domain="platform.example.invalid",
                            runner=runner,
                        )
                    commands = [
                        " ".join(command) for command, _ in runner.calls
                    ]
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

    def test_shared_smoke_contract_rejects_status_or_redirect_relaxation(self) -> None:
        relaxed_programs = (
            TLS_PROBE_PROGRAM.replace(
                "response.getcode()==200 or sys.exit(2); ",
                "response.getcode()<400 or sys.exit(2); ",
                1,
            ),
            TLS_PROBE_PROGRAM.replace(
                "response.geturl()==sys.argv[1] or sys.exit(3); ", "", 1
            ),
        )
        for program in relaxed_programs:
            with self.subTest(program=program):
                self.assertTrue(restore_contract_errors(program, PROBES))

    def test_external_smoke_uses_same_verified_connection_identity_contract(self) -> None:
        runner = RecordingRunner({})
        _external_smoke(
            "platform.example.invalid",
            runner,
            {},
            TLS_FINGERPRINT,
            mock.Mock(),
        )
        external_calls = [
            command
            for command, _ in runner.calls
            if command[:3] == [sys.executable, "-c", TLS_HTTP_PROBE_PROGRAM]
        ]
        self.assertEqual(len(external_calls), 2)
        self.assertEqual(
            {command[3] for command in external_calls},
            {
                "https://platform.example.invalid/readyz",
                "https://identity.platform.example.invalid/realms/email-platform/.well-known/openid-configuration",
            },
        )
        self.assertIn("connection.connect()", TLS_HTTP_PROBE_PROGRAM)
        self.assertIn("connection.sock.getpeercert(binary_form=True)", TLS_HTTP_PROBE_PROGRAM)
        self.assertIn("connection.request", TLS_HTTP_PROBE_PROGRAM)

    def test_preflight_failure_never_stops_services(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            runner = RecordingRunner(plan.images)
            runner.fail_contains = "cosign verify "
            with self.assertRaises(subprocess.CalledProcessError):
                execute_rollback(
                    plan,
                    confirm_release_tag=TAG,
                    platform_target_db="email_platform",
                    keycloak_target_db="keycloak",
                    domain="platform.example.invalid",
                    runner=runner,
                )
        commands = [" ".join(command) for command, _ in runner.calls]
        self.assertFalse(any(" ".join(_compose("stop")) in command for command in commands))

    def test_missing_monitoring_service_fails_before_pull_stop_or_restore(self) -> None:
        for missing in ("prometheus", "alertmanager"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as directory:
                manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
                plan = load_rollback_plan(manifest_path, backup_dir, key_file)
                runner = RecordingRunner(
                    plan.images,
                    running_services=tuple(
                        service for service in OPERATIONAL_SERVICES if service != missing
                    ),
                )
                with self.assertRaisesRegex(RollbackError, "operational services"):
                    execute_rollback(
                        plan,
                        confirm_release_tag=TAG,
                        platform_target_db="email_platform",
                        keycloak_target_db="keycloak",
                        domain="platform.example.invalid",
                        runner=runner,
                    )
            commands = [command for command, _ in runner.calls]
            self.assertFalse(any(command[:2] == ["docker", "pull"] for command in commands))
            self.assertFalse(
                any(
                    command[:2] == ["docker", "compose"]
                    and command[COMPOSE_COMMAND_INDEX] in {"stop", "up"}
                    for command in commands
                )
            )
            self.assertFalse(
                any("scripts.postgres_maintenance" in " ".join(command) for command in commands)
            )

    def test_public_edge_tls_failure_precedes_every_runner_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            runner = RecordingRunner(plan.images)
            self.edge_tls_validator.side_effect = EdgeTlsError("private-cert-path")
            with self.assertRaisesRegex(
                RollbackError,
                "public edge TLS preflight failed",
            ) as raised:
                execute_rollback(
                    plan,
                    confirm_release_tag=TAG,
                    platform_target_db="email_platform",
                    keycloak_target_db="keycloak",
                    domain="platform.example.invalid",
                    runner=runner,
                )
        self.assertEqual(runner.calls, [])
        self.assertNotIn("private-cert-path", str(raised.exception))
        self.edge_tls_validator.assert_called_once_with(
            PRODUCTION_ENV_FILE,
            "platform.example.invalid",
        )

    def test_release_checkout_failures_precede_supply_chain_and_do_not_leak(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            cases = (
                ("head", "f" * 40, None),
                ("worktree", COMMIT, "diff --quiet --no-ext-diff --"),
                ("index", COMMIT, "diff --cached --quiet --no-ext-diff --"),
                ("git", COMMIT, "rev-parse --verify HEAD"),
            )
            for label, head, failure in cases:
                runner = RecordingRunner(plan.images)
                runner.git_head = head
                runner.fail_contains = failure
                with self.subTest(label=label):
                    with self.assertRaisesRegex(
                        RollbackError, "release checkout preflight failed"
                    ) as raised:
                        execute_rollback(
                            plan,
                            confirm_release_tag=TAG,
                            platform_target_db="email_platform",
                            keycloak_target_db="keycloak",
                            domain="platform.example.invalid",
                            runner=runner,
                        )
                    self.assertTrue(runner.calls)
                    self.assertTrue(
                        all(command[0] == "git" for command, _ in runner.calls)
                    )
                    self.assertEqual(
                        str(raised.exception), "release checkout preflight failed"
                    )

    def test_rollback_rejects_compose_file_and_default_override_before_git(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            runner = RecordingRunner(plan.images)
            with mock.patch.dict(
                "os.environ", {"COMPOSE_FILE": "private-override.yml"}
            ):
                with self.assertRaisesRegex(RollbackError, "checkout preflight"):
                    execute_rollback(
                        plan,
                        confirm_release_tag=TAG,
                        platform_target_db="email_platform",
                        keycloak_target_db="keycloak",
                        domain="platform.example.invalid",
                        runner=runner,
                    )
            self.assertEqual(runner.calls, [])

            runner = RecordingRunner(plan.images)
            with mock.patch("scripts.rollback_release.Path.exists", return_value=True):
                with self.assertRaisesRegex(RollbackError, "checkout preflight"):
                    execute_rollback(
                        plan,
                        confirm_release_tag=TAG,
                        platform_target_db="email_platform",
                        keycloak_target_db="keycloak",
                        domain="platform.example.invalid",
                        runner=runner,
                    )
            self.assertEqual(runner.calls, [])

    def test_restore_failure_never_starts_services(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            runner = RecordingRunner(plan.images)
            runner.fail_contains = "scripts.postgres_maintenance restore-bundle"
            with self.assertRaises(subprocess.CalledProcessError):
                execute_rollback(
                    plan,
                    confirm_release_tag=TAG,
                    platform_target_db="email_platform",
                    keycloak_target_db="keycloak",
                    domain="platform.example.invalid",
                    runner=runner,
                )
        commands = [" ".join(command) for command, _ in runner.calls]
        self.assertTrue(any(" ".join(_compose("stop", "edge")) in command for command in commands))
        self.assertFalse(any(" ".join(_compose("up")) in command for command in commands))

    def test_redis_restore_and_health_fail_before_backend_or_edge(self) -> None:
        for label, failure in (
            ("restore", "scripts.redis_maintenance restore-release"),
            ("health", "/usr/local/bin/redis-healthcheck"),
        ):
            with tempfile.TemporaryDirectory() as directory:
                manifest_path, backup_dir, key_file = _write_fixture(
                    Path(directory)
                )
                plan = load_rollback_plan(manifest_path, backup_dir, key_file)
                runner = RecordingRunner(plan.images)
                runner.fail_contains = failure
                with self.subTest(label=label):
                    with self.assertRaises(subprocess.CalledProcessError):
                        execute_rollback(
                            plan,
                            confirm_release_tag=TAG,
                            platform_target_db="email_platform",
                            keycloak_target_db="keycloak",
                            domain="platform.example.invalid",
                            runner=runner,
                        )
                    commands = [
                        " ".join(command) for command, _ in runner.calls
                    ]
                    self.assertFalse(
                        any(
                            " ".join(_compose("up")) in command
                            and command.endswith("web")
                            for command in commands
                        )
                    )
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

    def test_redis_recovery_point_binding_and_time_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            call = self.redis_verifier.call_args
            self.assertEqual(call.kwargs["recovery_set"], RECOVERY_SET)
            self.assertEqual(
                call.kwargs["postgres_manifest_sha256"],
                plan.postgres_manifest_sha256,
            )
            self.assertEqual(call.kwargs["release_tag"], TAG)

            self.redis_verifier.reset_mock()
            self.redis_verifier.return_value = (
                {},
                BACKUP_CREATED_AT + timedelta(minutes=5, seconds=1),
                "e" * 64,
            )
            with self.assertRaisesRegex(RollbackError, "too far apart"):
                load_rollback_plan(manifest_path, backup_dir, key_file)

            for label, error in (
                ("missing", ValueError("Redis backup is missing")),
                ("tampered", ValueError("Redis backup authentication failed")),
                ("wrong-set", ValueError("Redis recovery set mismatch")),
            ):
                self.redis_verifier.side_effect = error
                with self.subTest(label=label):
                    with self.assertRaises(ValueError):
                        load_rollback_plan(manifest_path, backup_dir, key_file)
            self.redis_verifier.side_effect = None

    def test_old_load_call_without_redis_recovery_point_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            with self.assertRaises(TypeError):
                _load_rollback_plan(manifest_path, backup_dir, key_file)

    def test_runtime_image_mismatch_keeps_edge_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            runner = RecordingRunner(plan.images)
            runner.mismatched_service = "api"
            with self.assertRaisesRegex(RollbackError, "runtime image"):
                execute_rollback(
                    plan,
                    confirm_release_tag=TAG,
                    platform_target_db="email_platform",
                    keycloak_target_db="keycloak",
                    domain="platform.example.invalid",
                    runner=runner,
                )
        commands = [" ".join(command) for command, _ in runner.calls]
        self.assertNotIn(
            " ".join(_compose("up", "-d", "--no-build", "--pull", "never", "--force-recreate", "edge")), commands
        )

    def test_external_smoke_failure_stops_edge_again(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            runner = RecordingRunner(plan.images)
            runner.fail_contains = "https://platform.example.invalid/readyz"
            with self.assertRaises(subprocess.CalledProcessError):
                execute_rollback(
                    plan,
                    confirm_release_tag=TAG,
                    platform_target_db="email_platform",
                    keycloak_target_db="keycloak",
                    domain="platform.example.invalid",
                    runner=runner,
                )
        commands = [" ".join(command) for command, _ in runner.calls]
        self.assertIn(
            " ".join(_compose("up", "-d", "--no-build", "--pull", "never", "--force-recreate", "edge")), commands
        )
        self.assertEqual(commands[-1], " ".join(_compose("stop", "edge")))

    def test_external_tls_identity_drift_stops_edge_again(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            runner = RecordingRunner(plan.images)
            original_run = runner.run

            def drift_external_peer(command, *, env=None, capture_output=False):
                rendered = [str(item) for item in command]
                if (
                    TLS_HTTP_PROBE_PROGRAM in rendered
                    and "https://platform.example.invalid/readyz" in rendered
                ):
                    runner.calls.append((rendered, dict(env or {})))
                    return json.dumps(
                        {"peer_sha256": "b" * 64, "tls_version": "TLSv1.3"}
                    )
                return original_run(command, env=env, capture_output=capture_output)

            runner.run = drift_external_peer
            with self.assertRaisesRegex(RollbackError, "external TLS peer identity"):
                execute_rollback(
                    plan,
                    confirm_release_tag=TAG,
                    platform_target_db="email_platform",
                    keycloak_target_db="keycloak",
                    domain="platform.example.invalid",
                    runner=runner,
                )
        commands = [" ".join(command) for command, _ in runner.calls]
        self.assertEqual(commands[-1], " ".join(_compose("stop", "edge")))

    def test_monitoring_loss_after_edge_start_fails_and_recloses_edge(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            runner = RecordingRunner(plan.images, running_services=OPERATIONAL_SERVICES)
            original_run = runner.run
            edge_up = " ".join(
                _compose("up", "-d", "--no-build", "--pull", "never", "--force-recreate", "edge")
            )

            def lose_monitoring(command, *, env=None, capture_output=False):
                prior = [" ".join(call[0]) for call in runner.calls]
                if edge_up in prior:
                    runner.running_services = tuple(
                        service
                        for service in OPERATIONAL_SERVICES
                        if service != "alertmanager"
                    )
                return original_run(command, env=env, capture_output=capture_output)

            runner.run = lose_monitoring
            with self.assertRaisesRegex(RollbackError, "operational services"):
                execute_rollback(
                    plan,
                    confirm_release_tag=TAG,
                    platform_target_db="email_platform",
                    keycloak_target_db="keycloak",
                    domain="platform.example.invalid",
                    runner=runner,
                )
        commands = [" ".join(command) for command, _ in runner.calls]
        self.assertIn(edge_up, commands)
        self.assertEqual(commands[-1], " ".join(_compose("stop", "edge")))

    def test_external_smoke_and_edge_stop_failure_report_unconfirmed_closure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, backup_dir, key_file = _write_fixture(root)
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            evidence_output = root / "rollback-evidence.json"
            runner = RecordingRunner(plan.images)
            runner.fail_contains = "https://platform.example.invalid/readyz"
            original_run = runner.run
            edge_up = " ".join(
                _compose("up", "-d", "--no-build", "--pull", "never", "--force-recreate", "edge")
            )
            edge_stop = " ".join(_compose("stop", "edge"))

            def fail_final_edge_stop(command, *, env=None, capture_output=False):
                rendered = " ".join(command)
                prior_commands = [" ".join(call[0]) for call in runner.calls]
                if rendered == edge_stop and edge_up in prior_commands:
                    runner.calls.append((list(command), dict(env or {})))
                    raise subprocess.CalledProcessError(
                        1, command, stderr="SENSITIVE_STOP_DETAIL"
                    )
                return original_run(command, env=env, capture_output=capture_output)

            runner.run = fail_final_edge_stop
            with self.assertRaisesRegex(
                RollbackError, "edge closure could not be confirmed"
            ) as raised:
                execute_rollback(
                    plan,
                    confirm_release_tag=TAG,
                    platform_target_db="email_platform",
                    keycloak_target_db="keycloak",
                    domain="platform.example.invalid",
                    evidence_output=evidence_output,
                    runner=runner,
                )
            evidence = verify_evidence(evidence_output)
            self.assertEqual(evidence["terminal_state"], TERMINAL_EDGE_UNCONFIRMED)
            self.assertTrue(evidence["edge"]["start_attempted"])
            self.assertEqual(evidence["edge"]["stop_confirmations"], 1)
            invalid = {key: value for key, value in evidence.items() if key != "integrity"}
            invalid["edge"]["stop_confirmations"] = 0
            with self.assertRaisesRegex(RollbackReleaseEvidenceError, "unconfirmed-edge"):
                seal_evidence(invalid)
            invalid = {
                key: value for key, value in verify_evidence(evidence_output).items()
                if key != "integrity"
            }
            invalid["edge"]["start_attempted"] = False
            with self.assertRaisesRegex(
                RollbackReleaseEvidenceError, "edge start|unconfirmed-edge"
            ):
                seal_evidence(invalid)
        self.assertNotIn("SENSITIVE_STOP_DETAIL", str(raised.exception))
        self.assertEqual(" ".join(runner.calls[-1][0]), edge_stop)

    def test_confirmation_is_required_before_any_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            runner = RecordingRunner(plan.images)
            with self.assertRaisesRegex(RollbackError, "confirmation"):
                execute_rollback(
                    plan,
                    confirm_release_tag="v9.9.9",
                    platform_target_db="email_platform",
                    keycloak_target_db="keycloak",
                    domain="platform.example.invalid",
                    runner=runner,
                )
            self.assertEqual(runner.calls, [])

    def test_invalid_target_inputs_fail_before_any_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir, key_file = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            for database, domain in (
                ("bad-name", "platform.example.invalid"),
                ("email_platform", "bad..domain"),
            ):
                runner = RecordingRunner(plan.images)
                with self.subTest(database=database, domain=domain):
                    with self.assertRaises(RollbackError):
                        execute_rollback(
                            plan,
                            confirm_release_tag=TAG,
                            platform_target_db=database,
                            keycloak_target_db="keycloak",
                            domain=domain,
                            runner=runner,
                        )
                    self.assertEqual(runner.calls, [])

    def test_success_writes_closed_release_bound_write_once_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, backup_dir, key_file = _write_fixture(root)
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            output = root / "rollback-evidence.json"
            runner = RecordingRunner(plan.images)
            execute_rollback(
                plan,
                confirm_release_tag=TAG,
                platform_target_db="email_platform",
                keycloak_target_db="keycloak",
                domain="platform.example.invalid",
                evidence_output=output,
                runner=runner,
            )
            evidence = verify_evidence(output)
            self.assertEqual(evidence["terminal_state"], TERMINAL_SUCCEEDED)
            self.assertEqual(evidence["images"]["observed"], evidence["images"]["expected"])
            self.assertEqual(evidence["edge"]["final_state"], "open_verified")
            self.assertEqual(evidence["checks"]["internal_probes_passed"], len(PROBES))
            assert_expected_release(
                evidence,
                release_tag=plan.tag,
                release_commit=plan.commit,
                migration_head=plan.migration_head,
                container_manifest_sha256=plan.container_manifest_sha256,
                postgres_manifest_sha256=plan.postgres_manifest_sha256,
                redis_manifest_sha256=plan.redis_manifest_sha256,
                recovery_set=plan.recovery_set,
                images={
                    "api": plan.images["api"],
                    "worker_mail": plan.images["api"],
                    "worker_sub2": plan.images["api"],
                    "web": plan.images["web"],
                    "edge": plan.images["edge"],
                },
            )
            serialized = output.read_text(encoding="utf-8")
            for forbidden in (
                "platform.example.invalid",
                "email_platform",
                str(root),
                "argv",
                "environment",
                "certificate",
            ):
                self.assertNotIn(forbidden, serialized)
            original = output.read_bytes()
            second_runner = RecordingRunner(plan.images)
            with self.assertRaisesRegex(RollbackError, "evidence preflight"):
                execute_rollback(
                    plan,
                    confirm_release_tag=TAG,
                    platform_target_db="email_platform",
                    keycloak_target_db="keycloak",
                    domain="platform.example.invalid",
                    evidence_output=output,
                    runner=second_runner,
                )
            self.assertEqual(second_runner.calls, [])
            self.assertEqual(output.read_bytes(), original)

    def test_hardlink_commit_cleanup_failure_keeps_published_evidence_successful(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, backup_dir, key_file = _write_fixture(root)
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            output = root / "rollback-evidence.json"
            with mock.patch(
                "scripts.backup_output_policy.Path.unlink",
                side_effect=PermissionError("temporary cleanup denied"),
            ):
                execute_rollback(
                    plan,
                    confirm_release_tag=TAG,
                    platform_target_db="email_platform",
                    keycloak_target_db="keycloak",
                    domain="platform.example.invalid",
                    evidence_output=output,
                    runner=RecordingRunner(plan.images),
                )
            self.assertEqual(verify_evidence(output)["terminal_state"], TERMINAL_SUCCEEDED)

    def test_safe_short_recovery_set_is_validated_before_runner_and_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, backup_dir, key_file = _write_fixture(root)
            plan = replace(
                load_rollback_plan(manifest_path, backup_dir, key_file),
                recovery_set="x",
            )
            output = root / "rollback-evidence.json"
            execute_rollback(
                plan,
                confirm_release_tag=TAG,
                platform_target_db="email_platform",
                keycloak_target_db="keycloak",
                domain="platform.example.invalid",
                evidence_output=output,
                runner=RecordingRunner(plan.images),
            )
            self.assertEqual(verify_evidence(output)["recovery"]["recovery_set"], "x")

    def test_evidence_records_preflight_closed_failure_and_unconfirmed_terminals(self) -> None:
        cases = (
            ("preflight", "v9.9.9", None, TERMINAL_PREFLIGHT_FAILED),
            (
                "restore",
                TAG,
                "scripts.postgres_maintenance restore-bundle",
                TERMINAL_EDGE_CLOSED_FAILURE,
            ),
        )
        for label, confirmation, failure, terminal in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest_path, backup_dir, key_file = _write_fixture(root)
                plan = load_rollback_plan(manifest_path, backup_dir, key_file)
                output = root / "rollback-evidence.json"
                runner = RecordingRunner(plan.images)
                runner.fail_contains = failure
                with self.assertRaises((RollbackError, subprocess.CalledProcessError)):
                    execute_rollback(
                        plan,
                        confirm_release_tag=confirmation,
                        platform_target_db="email_platform",
                        keycloak_target_db="keycloak",
                        domain="platform.example.invalid",
                        evidence_output=output,
                        runner=runner,
                    )
                evidence = verify_evidence(output)
                self.assertEqual(evidence["terminal_state"], terminal)
                if terminal == TERMINAL_PREFLIGHT_FAILED:
                    self.assertEqual(runner.calls, [])
                    self.assertEqual(evidence["edge"]["final_state"], "not_mutated")
                else:
                    self.assertEqual(evidence["edge"]["final_state"], "closed_confirmed")

    def test_release_lock_contention_writes_preflight_evidence_without_runner_use(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, backup_dir, key_file = _write_fixture(root)
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            output = root / "rollback-evidence.json"
            runner = RecordingRunner(plan.images)
            with mock.patch(
                "scripts.rollback_release.release_control_lock",
                side_effect=ReleaseControlLocked("private-lock-detail"),
            ):
                with self.assertRaisesRegex(
                    RollbackError, "another release control operation is active"
                ) as raised:
                    execute_rollback(
                        plan,
                        confirm_release_tag=TAG,
                        platform_target_db="email_platform",
                        keycloak_target_db="keycloak",
                        domain="platform.example.invalid",
                        evidence_output=output,
                        runner=runner,
                    )
            self.assertEqual(runner.calls, [])
            self.assertEqual(
                verify_evidence(output)["terminal_state"], TERMINAL_PREFLIGHT_FAILED
            )
            self.assertNotIn("private-lock-detail", str(raised.exception))

    def test_keyword_plan_lock_contention_writes_preflight_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, backup_dir, key_file = _write_fixture(root)
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            output = root / "rollback-evidence.json"
            runner = RecordingRunner(plan.images)
            with mock.patch(
                "scripts.rollback_release.release_control_lock",
                side_effect=ReleaseControlLocked("private-lock-detail"),
            ):
                with self.assertRaisesRegex(
                    RollbackError, "^another release control operation is active$"
                ) as raised:
                    _execute_rollback(
                        plan=plan,
                        confirm_release_tag=TAG,
                        platform_target_db="email_platform",
                        keycloak_target_db="keycloak",
                        domain="platform.example.invalid",
                        evidence_output=output,
                        runner=runner,
                    )
            self.assertEqual(runner.calls, [])
            self.assertEqual(
                verify_evidence(output)["terminal_state"], TERMINAL_PREFLIGHT_FAILED
            )
            self.assertNotIn("private-lock-detail", str(raised.exception))

    def test_release_control_rejects_missing_or_duplicate_plan_before_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, backup_dir, key_file = _write_fixture(root)
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            runner = RecordingRunner(plan.images)
            arguments = {
                "confirm_release_tag": TAG,
                "platform_target_db": "email_platform",
                "keycloak_target_db": "keycloak",
                "domain": "platform.example.invalid",
                "evidence_output": root / "rollback-evidence.json",
                "runner": runner,
            }
            with mock.patch(
                "scripts.rollback_release.release_control_lock"
            ) as release_lock:
                with self.assertRaises(TypeError):
                    _execute_rollback(**arguments)
                with self.assertRaises(TypeError):
                    _execute_rollback(plan, plan=plan, **arguments)
            release_lock.assert_not_called()
            self.assertEqual(runner.calls, [])
            self.assertFalse(arguments["evidence_output"].exists())

    def test_unconfirmed_edge_terminal_is_not_masked_by_evidence_publication_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, backup_dir, key_file = _write_fixture(root)
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            output = root / "rollback-evidence.json"
            runner = RecordingRunner(plan.images)
            runner.fail_contains = "https://platform.example.invalid/readyz"
            original_run = runner.run
            edge_up = " ".join(_compose("up", "-d", "--no-build", "--pull", "never", "--force-recreate", "edge"))
            edge_stop = " ".join(_compose("stop", "edge"))

            def fail_final_edge_stop(command, *, env=None, capture_output=False):
                rendered = " ".join(command)
                prior = [" ".join(call[0]) for call in runner.calls]
                if rendered == edge_stop and edge_up in prior:
                    runner.calls.append((list(command), dict(env or {})))
                    raise subprocess.CalledProcessError(1, command)
                return original_run(command, env=env, capture_output=capture_output)

            runner.run = fail_final_edge_stop
            with mock.patch(
                "scripts.rollback_release.RollbackReleaseEvidenceRecorder.write",
                side_effect=RollbackReleaseEvidenceError("private-output-detail"),
            ):
                with self.assertRaisesRegex(
                    RollbackError, "edge closure could not be confirmed"
                ) as raised:
                    execute_rollback(
                        plan,
                        confirm_release_tag=TAG,
                        platform_target_db="email_platform",
                        keycloak_target_db="keycloak",
                        domain="platform.example.invalid",
                        evidence_output=output,
                        runner=runner,
                    )
            self.assertNotIn("private-output-detail", str(raised.exception))

    def test_success_evidence_publication_failure_closes_edge(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, backup_dir, key_file = _write_fixture(root)
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            runner = RecordingRunner(plan.images)
            with mock.patch(
                "scripts.rollback_release.RollbackReleaseEvidenceRecorder.write",
                side_effect=RollbackReleaseEvidenceError("private-output-detail"),
            ):
                with self.assertRaisesRegex(
                    RollbackError, "evidence publication failed; public edge was closed"
                ) as raised:
                    execute_rollback(
                        plan,
                        confirm_release_tag=TAG,
                        platform_target_db="email_platform",
                        keycloak_target_db="keycloak",
                        domain="platform.example.invalid",
                        evidence_output=root / "rollback-evidence.json",
                        runner=runner,
                    )
            self.assertEqual(" ".join(runner.calls[-1][0]), " ".join(_compose("stop", "edge")))
            self.assertNotIn("private-output-detail", str(raised.exception))

    def test_unclassified_exception_and_keyboard_interrupt_compensate_after_edge_start(self) -> None:
        cases: tuple[tuple[str, BaseException], ...] = (
            ("runtime", RuntimeError("SENSITIVE_RUNTIME_DETAIL")),
            ("interrupt", KeyboardInterrupt()),
        )
        for label, injected in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest_path, backup_dir, key_file = _write_fixture(root)
                plan = load_rollback_plan(manifest_path, backup_dir, key_file)
                output = root / "rollback-evidence.json"
                runner = RecordingRunner(plan.images)
                original_run = runner.run

                def interrupt_after_edge(command, *, env=None, capture_output=False):
                    if "https://platform.example.invalid/readyz" in " ".join(command):
                        runner.calls.append((list(command), dict(env or {})))
                        raise injected
                    return original_run(command, env=env, capture_output=capture_output)

                runner.run = interrupt_after_edge
                if isinstance(injected, KeyboardInterrupt):
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        execute_rollback(
                            plan,
                            confirm_release_tag=TAG,
                            platform_target_db="email_platform",
                            keycloak_target_db="keycloak",
                            domain="platform.example.invalid",
                            evidence_output=output,
                            runner=runner,
                        )
                    self.assertIs(raised.exception, injected)
                else:
                    with self.assertRaisesRegex(
                        RollbackError, "^rollback execution failed$"
                    ) as raised:
                        execute_rollback(
                            plan,
                            confirm_release_tag=TAG,
                            platform_target_db="email_platform",
                            keycloak_target_db="keycloak",
                            domain="platform.example.invalid",
                            evidence_output=output,
                            runner=runner,
                        )
                    self.assertNotIn("SENSITIVE_RUNTIME_DETAIL", str(raised.exception))
                self.assertEqual(
                    " ".join(runner.calls[-1][0]), " ".join(_compose("stop", "edge"))
                )
                self.assertEqual(
                    verify_evidence(output)["terminal_state"],
                    TERMINAL_EDGE_CLOSED_FAILURE,
                )

    def test_stop_runtime_error_is_edge_unconfirmed_and_does_not_leak(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, backup_dir, key_file = _write_fixture(root)
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            output = root / "rollback-evidence.json"
            runner = RecordingRunner(plan.images)
            original_run = runner.run
            stop_edge = [str(item) for item in _compose("stop", "edge")]

            def fail_execution_and_stop(command, *, env=None, capture_output=False):
                rendered = [str(item) for item in command]
                if "https://platform.example.invalid/readyz" in " ".join(rendered):
                    runner.calls.append((rendered, dict(env or {})))
                    raise RuntimeError("SENSITIVE_EXECUTION_DETAIL")
                if rendered == stop_edge:
                    runner.calls.append((rendered, dict(env or {})))
                    raise RuntimeError("SENSITIVE_STOP_DETAIL")
                return original_run(command, env=env, capture_output=capture_output)

            runner.run = fail_execution_and_stop
            with self.assertRaisesRegex(
                RollbackError,
                "^rollback failed and public edge closure could not be confirmed$",
            ) as raised:
                execute_rollback(
                    plan,
                    confirm_release_tag=TAG,
                    platform_target_db="email_platform",
                    keycloak_target_db="keycloak",
                    domain="platform.example.invalid",
                    evidence_output=output,
                    runner=runner,
                )
            self.assertNotIn("SENSITIVE", str(raised.exception))
            payload = verify_evidence(output)
            self.assertEqual(payload["terminal_state"], TERMINAL_EDGE_UNCONFIRMED)
            self.assertNotIn("SENSITIVE", output.read_text(encoding="utf-8"))

    def test_cli_stderr_does_not_leak_unclassified_exception(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, backup_dir, key_file = _write_fixture(root)
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            output = root / "rollback-evidence.json"
            runner = RecordingRunner(plan.images)
            original_run = runner.run

            def fail_after_edge(command, *, env=None, capture_output=False):
                if "https://platform.example.invalid/readyz" in " ".join(command):
                    runner.calls.append((list(command), dict(env or {})))
                    raise RuntimeError("SENSITIVE_CLI_DETAIL")
                return original_run(command, env=env, capture_output=capture_output)

            runner.run = fail_after_edge
            stderr = io.StringIO()
            arguments = [
                "execute",
                "--container-manifest",
                str(manifest_path),
                "--backup-dir",
                str(backup_dir),
                "--redis-backup-dir",
                str(root / "redis-backup"),
                "--recovery-set",
                RECOVERY_SET,
                "--key-file",
                str(key_file),
                "--confirm-release-tag",
                TAG,
                "--domain",
                "platform.example.invalid",
                "--evidence-output",
                str(output),
            ]
            with mock.patch(
                "scripts.rollback_release.SubprocessRunner", return_value=runner
            ), redirect_stderr(stderr):
                result = rollback_main(arguments)
            self.assertEqual(result, 1)
            self.assertEqual(stderr.getvalue(), "rollback-release-failed\n")
            self.assertNotIn("SENSITIVE_CLI_DETAIL", stderr.getvalue())
            self.assertEqual(
                verify_evidence(output)["terminal_state"],
                TERMINAL_EDGE_CLOSED_FAILURE,
            )

    def test_evidence_rejects_unknown_duplicate_tampered_and_cross_release_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, backup_dir, key_file = _write_fixture(root)
            plan = load_rollback_plan(manifest_path, backup_dir, key_file)
            output = root / "rollback-evidence.json"
            execute_rollback(
                plan,
                confirm_release_tag=TAG,
                platform_target_db="email_platform",
                keycloak_target_db="keycloak",
                domain="platform.example.invalid",
                evidence_output=output,
                runner=RecordingRunner(plan.images),
            )
            original = output.read_text(encoding="utf-8")
            changed = json.loads(original)
            changed["host_path"] = "forbidden"
            with self.assertRaisesRegex(RollbackReleaseEvidenceError, "schema"):
                validate_evidence(changed)
            changed = json.loads(original)
            changed["release"]["tag"] = "v9.9.9"
            with self.assertRaisesRegex(
                RollbackReleaseEvidenceError, "fingerprint|integrity"
            ):
                validate_evidence(changed)
            payload = json.loads(original)
            payload.pop("integrity")
            payload["execution_fingerprint"] = "f" * 64
            with self.assertRaisesRegex(RollbackReleaseEvidenceError, "fingerprint"):
                seal_evidence(payload)
            payload = json.loads(original)
            payload.pop("integrity")
            payload["recovery"]["redis_created_at"] = "2026-08-20T00:10:01Z"
            with self.assertRaisesRegex(RollbackReleaseEvidenceError, "too far apart"):
                seal_evidence(payload)
            payload = json.loads(original)
            payload.pop("integrity")
            payload["images"]["observed"]["api"] = (
                "ghcr.io/example/manage-api@sha256:" + "e" * 64
            )
            with self.assertRaisesRegex(RollbackReleaseEvidenceError, "observed"):
                seal_evidence(payload)
            implication_mutations = (
                ("preflight", ("checks", "supply_chain_verified"), False, "preflight phase"),
                ("preflight-pull", ("checks", "images_pulled"), False, "preflight phase"),
                ("preflight-vault", ("checks", "vault_sink_checks_passed"), 0, "preflight phase"),
                ("preflight-ops", ("checks", "operational_checks_passed"), 0, "preflight phase"),
                ("internal-api", ("images", "observed", "api"), None, "internal verification"),
                ("internal-mail", ("images", "observed", "worker_mail"), None, "internal verification"),
                ("internal-sub2", ("images", "observed", "worker_sub2"), None, "internal verification"),
                ("internal-web", ("images", "observed", "web"), None, "internal verification"),
                ("internal-probes", ("checks", "internal_probes_passed"), 6, "internal verification"),
                ("edge", ("edge", "start_attempted"), False, "edge start"),
                ("external-edge", ("images", "observed", "edge"), None, "external verification"),
                ("external", ("checks", "external_probes_passed"), 1, "external verification"),
            )
            for label, keys, value, expected_error in implication_mutations:
                with self.subTest(implication=label):
                    payload = json.loads(original)
                    payload.pop("integrity")
                    target = payload
                    for key in keys[:-1]:
                        target = target[key]
                    target[keys[-1]] = value
                    with self.assertRaisesRegex(
                        RollbackReleaseEvidenceError, expected_error
                    ):
                        seal_evidence(payload)
            duplicate = original.replace(
                '"schema_version": 2,',
                '"schema_version": 2, "schema_version": 2,',
                1,
            )
            duplicate_path = root / "duplicate.json"
            duplicate_path.write_text(duplicate, encoding="utf-8")
            with self.assertRaisesRegex(RollbackReleaseEvidenceError, "duplicate keys"):
                verify_evidence(duplicate_path)
            with self.assertRaisesRegex(RollbackReleaseEvidenceError, "release binding"):
                assert_expected_release(
                    verify_evidence(output),
                    release_tag="v9.9.9",
                    release_commit=plan.commit,
                    migration_head=plan.migration_head,
                    container_manifest_sha256=plan.container_manifest_sha256,
                    postgres_manifest_sha256=plan.postgres_manifest_sha256,
                    redis_manifest_sha256=plan.redis_manifest_sha256,
                    recovery_set=plan.recovery_set,
                    images={
                        "api": plan.images["api"],
                        "worker_mail": plan.images["api"],
                        "worker_sub2": plan.images["api"],
                        "web": plan.images["web"],
                        "edge": plan.images["edge"],
                    },
                )


if __name__ == "__main__":
    unittest.main()
