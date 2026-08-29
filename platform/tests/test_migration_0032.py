import io
import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0032_upload_phase_tracking"
PREVIOUS_REVISION = "0031_card_pool_routing"


class UploadPhaseTrackingMigrationTests(unittest.TestCase):
    def test_postgresql_offline_sql_includes_the_phase_backfill(self) -> None:
        output = io.StringIO()
        config = Config(str(ROOT / "alembic.ini"), output_buffer=output)
        config.cmd_opts = type(
            "Options",
            (),
            {
                "x": [
                    "db_url=postgresql+psycopg://placeholder:placeholder@localhost/db"
                ]
            },
        )()

        command.upgrade(config, "0030_mailbox_task_routing:0032_upload_phase_tracking", sql=True)

        sql = output.getvalue()
        self.assertIn("UPDATE operational_policy_versions", sql)
        self.assertIn("UPDATE upload_jobs SET phase_updated_at = updated_at", sql)

    def test_upgrade_marks_legacy_jobs_without_inventing_a_phase(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "upload-phase.db"
            url = f"sqlite+pysqlite:///{database.as_posix()}"
            previous = os.environ.get("ALEMBIC_DATABASE_URL")
            os.environ["ALEMBIC_DATABASE_URL"] = url
            engine = create_engine(url)
            try:
                with engine.begin() as connection:
                    connection.execute(
                        text(
                            "CREATE TABLE upload_jobs ("
                            "id VARCHAR(36) PRIMARY KEY, updated_at DATETIME NOT NULL)"
                        )
                    )
                    connection.execute(
                        text(
                            "CREATE TABLE audit_events ("
                            "id VARCHAR(36) PRIMARY KEY, tenant_id VARCHAR(64) NOT NULL, "
                            "entity_type VARCHAR(80) NOT NULL, entity_id VARCHAR(64))"
                        )
                    )
                    connection.execute(
                        text(
                            "CREATE TABLE alembic_version ("
                            "version_num VARCHAR(255) NOT NULL PRIMARY KEY)"
                        )
                    )
                    connection.execute(
                        text("INSERT INTO alembic_version VALUES (:revision)"),
                        {"revision": PREVIOUS_REVISION},
                    )
                    connection.execute(
                        text(
                            "INSERT INTO upload_jobs VALUES "
                            "('legacy-job', '2026-01-02 03:04:05')"
                        )
                    )

                command.upgrade(Config(str(ROOT / "alembic.ini")), REVISION)
                upload_columns = {
                    item["name"] for item in inspect(engine).get_columns("upload_jobs")
                }
                self.assertTrue(
                    {"phase", "phase_sequence", "phase_updated_at"}.issubset(
                        upload_columns
                    )
                )
                with engine.begin() as connection:
                    legacy = connection.execute(
                        text(
                            "SELECT phase, phase_sequence, phase_updated_at "
                            "FROM upload_jobs WHERE id='legacy-job'"
                        )
                    ).one()
                    self.assertEqual(legacy.phase, "legacy_unclassified")
                    self.assertEqual(legacy.phase_sequence, 0)
                    self.assertTrue(str(legacy.phase_updated_at).startswith("2026-01-02"))
                    connection.execute(
                        text(
                            "INSERT INTO audit_events "
                            "(id, tenant_id, entity_type, entity_id, aggregate_sequence) "
                            "VALUES ('event-1', 'tenant-a', 'upload_job', 'job-1', 1)"
                        )
                    )
                index_names = {
                    item["name"] for item in inspect(engine).get_indexes("audit_events")
                }
                self.assertIn("ix_audit_events_upload_phase_sequence", index_names)
            finally:
                if previous is None:
                    os.environ.pop("ALEMBIC_DATABASE_URL", None)
                else:
                    os.environ["ALEMBIC_DATABASE_URL"] = previous
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
