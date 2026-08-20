import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.rollback_release import (
    RollbackError,
    execute_rollback,
    load_rollback_plan,
    plan_summary,
)
from scripts.verify_runbooks import ROOT, rollback_runbook_errors


TAG = "v1.2.3"
COMMIT = "a" * 40
MIGRATION_HEAD = "0014_audit_evidence_fields"
DIGEST = "sha256:" + "b" * 64
ISSUER = "https://token.actions.githubusercontent.com"


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


def _write_fixture(root: Path, *, schema_version: int = 2) -> tuple[Path, Path]:
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
    databases: dict[str, dict[str, object]] = {}
    for logical_name, database in (
        ("platform", "email_platform"),
        ("keycloak", "keycloak"),
    ):
        data = f"{logical_name}-backup".encode()
        artifact = f"{logical_name}.dump"
        (backup_dir / artifact).write_bytes(data)
        databases[logical_name] = {
            "database": database,
            "artifact": artifact,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size_bytes": len(data),
        }
    backup_manifest: dict[str, object] = {
        "schema_version": schema_version,
        "created_at": "2026-08-20T00:00:00+00:00",
        "databases": databases,
    }
    if schema_version == 2:
        backup_manifest.update(
            {
                "release_tag": TAG,
                "release_commit": COMMIT,
                "migration_head": MIGRATION_HEAD,
                "container_manifest_sha256": manifest_sha256,
            }
        )
    (backup_dir / "manifest.json").write_text(
        json.dumps(backup_manifest, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest_path, backup_dir


class RecordingRunner:
    def __init__(self, images: dict[str, str]) -> None:
        self.images = images
        self.calls: list[tuple[list[str], dict[str, str]]] = []
        self.fail_contains: str | None = None
        self.mismatched_service: str | None = None

    def run(self, command, *, env=None, capture_output=False):
        rendered = [str(item) for item in command]
        environment = dict(env or {})
        self.calls.append((rendered, environment))
        joined = " ".join(rendered)
        if self.fail_contains and self.fail_contains in joined:
            raise subprocess.CalledProcessError(1, rendered)
        if rendered[:4] == ["docker", "compose", "ps", "-q"]:
            return f"{rendered[4]}-id\n"
        if rendered[:3] == ["docker", "inspect", "--format"]:
            service = rendered[-1].removesuffix("-id")
            if service == self.mismatched_service:
                return "ghcr.io/example/wrong@sha256:" + "e" * 64 + "\n"
            image_name = "api" if service in {"api", "worker-mail", "worker-sub2"} else service
            return self.images[image_name] + "\n"
        if rendered[:6] == [
            "docker",
            "compose",
            "ps",
            "--status",
            "running",
            "--services",
        ]:
            return "keycloak\napi\nworker-mail\nworker-sub2\nweb\n"
        return ""


class RollbackReleaseTests(unittest.TestCase):
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

    def test_plan_requires_release_bound_dual_database_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, backup_dir = _write_fixture(root)
            plan = load_rollback_plan(manifest_path, backup_dir)
            summary = plan_summary(plan)
            self.assertEqual(summary["release_tag"], TAG)
            self.assertEqual(summary["database_bundle"], "platform+keycloak")
            self.assertFalse(summary["production_acceptance"])
            self.assertTrue(plan.images["api"].endswith("@" + DIGEST))

            legacy_root = root / "legacy"
            legacy_root.mkdir()
            legacy_manifest, legacy_backup = _write_fixture(
                legacy_root, schema_version=1
            )
            with self.assertRaisesRegex(ValueError, "not release-bound"):
                load_rollback_plan(legacy_manifest, legacy_backup)

    def test_plan_rejects_container_manifest_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir = _write_fixture(Path(directory))
            backup_manifest_path = backup_dir / "manifest.json"
            backup_manifest = json.loads(
                backup_manifest_path.read_text(encoding="utf-8")
            )
            backup_manifest["container_manifest_sha256"] = "f" * 64
            backup_manifest_path.write_text(
                json.dumps(backup_manifest), encoding="utf-8"
            )
            with self.assertRaisesRegex(
                ValueError, "container_manifest_sha256"
            ):
                load_rollback_plan(manifest_path, backup_dir)

    def test_execute_orders_verification_restore_and_edge_last(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir)
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
            "docker compose stop edge api worker-mail worker-sub2 web keycloak"
        )
        restore_index = next(
            index
            for index, command in enumerate(commands)
            if "scripts.postgres_maintenance restore-bundle" in command
        )
        backend_up_index = next(
            index
            for index, command in enumerate(commands)
            if command.startswith("docker compose up") and command.endswith("web")
        )
        edge_up_index = commands.index(
            "docker compose up -d --no-build --pull never edge"
        )
        self.assertLess(cosign_index, pull_index)
        self.assertLess(pull_index, stop_index)
        self.assertLess(stop_index, restore_index)
        self.assertLess(restore_index, backend_up_index)
        self.assertLess(backend_up_index, edge_up_index)
        self.assertIn("--release-tag v1.2.3", commands[restore_index])
        self.assertIn("--container-manifest-sha256", commands[restore_index])
        self.assertEqual(
            runner.calls[stop_index][1]["PLATFORM_API_IMAGE"],
            plan.images["api"],
        )

    def test_preflight_failure_never_stops_services(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir)
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
        self.assertFalse(any("docker compose stop" in command for command in commands))

    def test_restore_failure_never_starts_services(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir)
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
        self.assertTrue(any("docker compose stop edge" in command for command in commands))
        self.assertFalse(any("docker compose up" in command for command in commands))

    def test_runtime_image_mismatch_keeps_edge_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir)
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
            "docker compose up -d --no-build --pull never edge", commands
        )

    def test_external_smoke_failure_stops_edge_again(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir)
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
            "docker compose up -d --no-build --pull never edge", commands
        )
        self.assertEqual(commands[-1], "docker compose stop edge")

    def test_confirmation_is_required_before_any_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path, backup_dir = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir)
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
            manifest_path, backup_dir = _write_fixture(Path(directory))
            plan = load_rollback_plan(manifest_path, backup_dir)
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


if __name__ == "__main__":
    unittest.main()
