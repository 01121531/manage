from __future__ import annotations

import unittest
from pathlib import Path

from scripts.verify_runbooks import (
    deploy_recovery_creation_errors,
    release_environment_runbook_errors,
)


POSTGRES_BACKUP = (
    "python -m scripts.postgres_maintenance backup-bundle "
    "--output-dir C:\\backups\\postgres-current "
    "--key-file C:\\secrets\\backup.key "
    "--platform-db email_platform --keycloak-db keycloak "
    "--release-tag v1.2.3 "
    "--release-commit 0123456789abcdef0123456789abcdef01234567 "
    "--migration-head 0018_access_token_revocations "
    f"--container-manifest-sha256 {'a' * 64}"
)
REDIS_BACKUP = "python -m scripts.redis_maintenance backup-release"
REDIS_VERIFY = "python -m scripts.redis_maintenance verify-release"


def deploy_text(*commands: str) -> str:
    return "\n".join(
        (
            "# Deploy",
            "## Create and authenticate the current rollback recovery set",
            *commands,
            "## Execute",
        )
    )


class DeployRecoveryRunbookTests(unittest.TestCase):
    def test_real_deploy_runbook_has_scoped_release_environment_guidance(self) -> None:
        root = Path(__file__).resolve().parents[1]
        text = (root / "deploy" / "runbooks" / "deploy.md").read_text(
            encoding="utf-8"
        )
        self.assertEqual(release_environment_runbook_errors(text, label="deploy"), [])
        changed = text.replace(
            "explicit environment rebuilt from only the reviewed OS",
            "inherited process environment",
            1,
        )
        self.assertTrue(release_environment_runbook_errors(changed, label="deploy"))

    def test_accepts_complete_release_bound_recovery_creation_order(self) -> None:
        text = deploy_text(POSTGRES_BACKUP, REDIS_BACKUP, REDIS_VERIFY)

        self.assertEqual(deploy_recovery_creation_errors(text), [])

    def test_rejects_missing_postgres_backup_command(self) -> None:
        text = deploy_text(REDIS_BACKUP, REDIS_VERIFY)

        self.assertTrue(deploy_recovery_creation_errors(text))

    def test_rejects_postgres_backup_after_redis_backup(self) -> None:
        text = deploy_text(REDIS_BACKUP, POSTGRES_BACKUP, REDIS_VERIFY)

        self.assertTrue(deploy_recovery_creation_errors(text))

    def test_rejects_generic_postgres_bundle_without_release_binding(self) -> None:
        generic = (
            "python -m scripts.postgres_maintenance backup-bundle "
            "--output-dir C:\\backups\\postgres-current "
            "--key-file C:\\secrets\\backup.key "
            "--platform-db email_platform --keycloak-db keycloak"
        )
        text = deploy_text(generic, REDIS_BACKUP, REDIS_VERIFY)

        errors = deploy_recovery_creation_errors(text)

        self.assertTrue(any("release binding" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
