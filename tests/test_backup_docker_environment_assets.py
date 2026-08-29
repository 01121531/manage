import unittest
from pathlib import Path

from scripts.verify_backup_tools import production_docker_environment_contract_errors


ROOT = Path(__file__).resolve().parents[1]


class BackupDockerEnvironmentAssetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.helper = (ROOT / "scripts" / "production_docker_environment.py").read_text(
            encoding="utf-8"
        )
        self.postgres = (ROOT / "scripts" / "postgres_maintenance.py").read_text(
            encoding="utf-8"
        )
        self.redis = (ROOT / "scripts" / "redis_maintenance.py").read_text(
            encoding="utf-8"
        )

    def errors(self, *, helper=None, postgres=None, redis=None):
        return production_docker_environment_contract_errors(
            helper if helper is not None else self.helper,
            postgres if postgres is not None else self.postgres,
            redis if redis is not None else self.redis,
        )

    def test_current_assets_satisfy_contract(self) -> None:
        self.assertEqual(self.errors(), [])

    def test_helper_inventory_and_presence_guard_are_static_contracts(self) -> None:
        mutations = (
            self.helper.replace('    "DOCKER_CERT_PATH",', '    "DOCKER_API_VERSION",', 1),
            self.helper.replace(
                "if any(name in environment for name in FORBIDDEN_PRODUCTION_DOCKER_VARIABLES):",
                "if any(environment.get(name) for name in FORBIDDEN_PRODUCTION_DOCKER_VARIABLES):",
                1,
            ),
            self.helper.replace(
                "    if any(name in environment for name in FORBIDDEN_PRODUCTION_DOCKER_VARIABLES):\n"
                "        raise ProductionDockerEnvironmentError(\n"
                '            "production backup Docker environment preflight failed"\n'
                "        )\n",
                "",
                1,
            ),
        )
        for helper in mutations:
            with self.subTest():
                self.assertTrue(
                    any("Docker environment" in error for error in self.errors(helper=helper)),
                    self.errors(helper=helper),
                )

    def test_every_postgres_docker_entrypoint_is_gated_first(self) -> None:
        entrypoints = (
            "count_tables",
            "count_rows",
            "critical_row_counts",
            "backup_database",
            "restore_database",
            "run_backup",
            "backup_bundle",
            "restore_bundle",
            "run_restore",
            "run_drill",
            "drill_bundle",
        )
        for entrypoint in entrypoints:
            marker = f"def {entrypoint}("
            start = self.postgres.index(marker)
            call = self.postgres.index(
                "    _validate_production_docker_environment()\n",
                start,
            )
            changed = self.postgres[:call] + self.postgres[call + len(
                "    _validate_production_docker_environment()\n"
            ):]
            with self.subTest(entrypoint=entrypoint):
                self.assertTrue(
                    any(entrypoint in error for error in self.errors(postgres=changed)),
                    self.errors(postgres=changed),
                )

    def test_every_redis_docker_entrypoint_is_gated_first(self) -> None:
        for entrypoint in ("backup_release", "restore_release"):
            marker = f"def {entrypoint}("
            start = self.redis.index(marker)
            call = self.redis.index(
                "    _validate_production_docker_environment()\n",
                start,
            )
            changed = self.redis[:call] + self.redis[call + len(
                "    _validate_production_docker_environment()\n"
            ):]
            with self.subTest(entrypoint=entrypoint):
                self.assertTrue(
                    any(entrypoint in error for error in self.errors(redis=changed)),
                    self.errors(redis=changed),
                )

    def test_preflight_reordering_after_sensitive_work_is_rejected(self) -> None:
        postgres = self.postgres.replace(
            "    _validate_production_docker_environment()\n"
            "    path = prepare_write_once_file(output_path)\n",
            "    path = prepare_write_once_file(output_path)\n"
            "    _validate_production_docker_environment()\n",
            1,
        )
        redis = self.redis.replace(
            "    _validate_production_docker_environment()\n"
            "    directory_claim = create_write_once_directory(output_dir)\n",
            "    directory_claim = create_write_once_directory(output_dir)\n"
            "    _validate_production_docker_environment()\n",
            1,
        )
        self.assertTrue(
            any("backup_database" in error for error in self.errors(postgres=postgres)),
            self.errors(postgres=postgres),
        )
        self.assertTrue(
            any("backup_release" in error for error in self.errors(redis=redis)),
            self.errors(redis=redis),
        )


if __name__ == "__main__":
    unittest.main()
