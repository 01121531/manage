import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import redis_maintenance
from scripts import verify_signoff_template
from scripts.verify_backup_tools import redis_backup_contract_errors
from scripts.verify_runbooks import redis_recovery_runbook_errors


ROOT = Path(__file__).resolve().parents[1]
RUNBOOK_ROOT = ROOT / "deploy" / "runbooks"


class RedisRecoveryRunbookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.documents = {
            name: (RUNBOOK_ROOT / name).read_text(encoding="utf-8")
            for name in ("restore.md", "rollback.md", "deploy.md")
        }

    def errors(self, documents=None) -> list[str]:
        return redis_recovery_runbook_errors(documents or self.documents)

    def test_current_guidance_has_complete_bound_restore_contract(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_rejects_missing_redis_command_and_unsafe_restore_order(self) -> None:
        without_restore = {
            name: text.replace(
                "python -m scripts.redis_maintenance restore-release",
                "redis restore omitted",
            )
            for name, text in self.documents.items()
        }
        self.assertTrue(self.errors(without_restore))

        restore = self.documents["restore.md"]
        postgres_restore = "python -m scripts.postgres_maintenance restore-bundle"
        redis_verify = "python -m scripts.redis_maintenance verify-release"
        unsafe_order = restore.replace(postgres_restore, "ORDER_PLACEHOLDER", 1)
        unsafe_order = unsafe_order.replace(redis_verify, postgres_restore, 1)
        unsafe_order = unsafe_order.replace("ORDER_PLACEHOLDER", redis_verify, 1)
        changed = {**self.documents, "restore.md": unsafe_order}
        self.assertTrue(any("order is unsafe" in error for error in self.errors(changed)))

    def test_rejects_relative_repository_paths_and_password_argv(self) -> None:
        relative = self.documents["restore.md"].replace(
            "--input-dir C:\\ProgramData\\EmailPlatform\\backups\\redis-",
            "--input-dir .\\deploy\\backups\\redis-",
            1,
        )
        self.assertNotEqual(relative, self.documents["restore.md"])
        errors = self.errors({**self.documents, "restore.md": relative})
        self.assertTrue(any("relative/repository path" in error for error in errors))

        password_argv = self.documents["restore.md"] + "\nredis-cli -a plaintext PING\n"
        errors = self.errors({**self.documents, "restore.md": password_argv})
        self.assertTrue(any("unsafe command text" in error for error in errors))

    def test_rejects_ping_only_restore_evidence(self) -> None:
        ping_only = {
            name: text.replace("DBSIZE", "PING").replace("PTTL", "PING")
            for name, text in self.documents.items()
        }
        errors = self.errors(ping_only)
        self.assertTrue(errors)
        self.assertTrue(any("DBSIZE" in error or "PTTL" in error for error in errors))

    def test_each_runbook_requires_the_backup_restart_fatal_contract(self) -> None:
        phrase = "Redis restart could not be confirmed` is fatal"
        for name, text in self.documents.items():
            with self.subTest(name=name):
                changed = {**self.documents, name: text.replace(phrase, "restart omitted")}
                errors = self.errors(changed)
                self.assertTrue(
                    any(name in error and "restart contract" in error for error in errors),
                    errors,
                )


class RedisRecoveryToolGateTests(unittest.TestCase):
    def test_current_cli_and_release_manifest_contract_pass(self) -> None:
        self.assertEqual(redis_backup_contract_errors(redis_maintenance), [])

    def test_rejects_wrong_artifact_schema_and_incomplete_release_binding(self) -> None:
        with mock.patch.object(redis_maintenance, "MANIFEST_SCHEMA", 2):
            self.assertTrue(redis_backup_contract_errors(redis_maintenance))
        with mock.patch.object(
            redis_maintenance,
            "_RELEASE_FIELDS",
            ("release_tag", "release_commit"),
        ):
            self.assertTrue(redis_backup_contract_errors(redis_maintenance))

    def test_rejects_missing_restart_or_health_contract(self) -> None:
        for name in ("_start_command", "_health_command"):
            with self.subTest(name=name), mock.patch.object(
                redis_maintenance, name, None, create=True
            ):
                self.assertTrue(redis_backup_contract_errors(redis_maintenance))
        with mock.patch.object(
            redis_maintenance,
            "_start_command",
            return_value=redis_maintenance._compose_command("start", "redis"),
        ):
            self.assertTrue(redis_backup_contract_errors(redis_maintenance))
        with mock.patch.object(
            redis_maintenance,
            "_health_command",
            return_value=redis_maintenance._compose_command("exec", "redis", "true"),
        ):
            self.assertTrue(redis_backup_contract_errors(redis_maintenance))


class RedisRecoverySignoffGateTests(unittest.TestCase):
    def test_rejects_signoff_without_redis_recovery_evidence(self) -> None:
        source = verify_signoff_template.TEMPLATE.read_text(encoding="utf-8")
        incomplete = source.replace(
            "Redis restored key count, representative TTL samples and expired-key non-revival evidence:",
            "Redis recovery evidence omitted:",
        )
        self.assertNotEqual(incomplete, source)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "production-signoff-template.md"
            path.write_text(incomplete, encoding="utf-8")
            with (
                mock.patch.object(verify_signoff_template, "TEMPLATE", path),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(verify_signoff_template.main(), 1)


if __name__ == "__main__":
    unittest.main()
