from __future__ import annotations

import unittest

from scripts.verify_backup_tools import (
    PRODUCTION_COMPOSE_PREFIX,
    production_compose_identity_errors,
)


class BackupComposeIdentityGateTests(unittest.TestCase):
    def test_accepts_only_the_fixed_production_prefix(self) -> None:
        command = [*PRODUCTION_COMPOSE_PREFIX, "exec", "-T", "postgres", "true"]

        self.assertEqual(production_compose_identity_errors((command,), "PostgreSQL"), [])

    def test_rejects_missing_project_name(self) -> None:
        command = [item for item in PRODUCTION_COMPOSE_PREFIX if item != "email-platform"]

        self.assertTrue(production_compose_identity_errors((command,), "PostgreSQL"))

    def test_rejects_relative_path_or_reordered_prefix(self) -> None:
        relative = list(PRODUCTION_COMPOSE_PREFIX)
        relative[3] = "."
        reordered = list(PRODUCTION_COMPOSE_PREFIX)
        reordered[2], reordered[4] = reordered[4], reordered[2]

        self.assertTrue(production_compose_identity_errors((relative,), "Redis"))
        self.assertTrue(production_compose_identity_errors((reordered,), "Redis"))


if __name__ == "__main__":
    unittest.main()
