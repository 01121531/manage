import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]


class AuditEvidenceMigrationTests(unittest.TestCase):
    def test_0013_to_0014_backfills_evidence_and_is_reversible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "audit-migration.db"
            url = f"sqlite+pysqlite:///{database.as_posix()}"
            engine = create_engine(url)
            with engine.begin() as connection:
                connection.execute(
                    text(
                        """
                        CREATE TABLE audit_events (
                            id VARCHAR(36) PRIMARY KEY,
                            tenant_id VARCHAR(64) NOT NULL,
                            user_id VARCHAR(36),
                            device_id VARCHAR(36),
                            event_type VARCHAR(80) NOT NULL,
                            entity_type VARCHAR(80) NOT NULL,
                            entity_id VARCHAR(64),
                            trace_id VARCHAR(36) NOT NULL,
                            details_json TEXT NOT NULL,
                            created_at DATETIME NOT NULL
                        )
                        """
                    )
                )
                connection.execute(
                    text(
                        """
                        INSERT INTO audit_events (
                            id, tenant_id, user_id, device_id, event_type,
                            entity_type, entity_id, trace_id, details_json, created_at
                        ) VALUES (
                            'event-1', 'tenant-a', 'user-1', 'device-1',
                            'upload.unknown', 'upload', 'job-1', 'trace-1', '{}',
                            '2026-08-20 00:00:00'
                        )
                        """
                    )
                )
                connection.execute(
                    text(
                        "CREATE TABLE alembic_version "
                        "(version_num VARCHAR(64) NOT NULL PRIMARY KEY)"
                    )
                )
                connection.execute(
                    text(
                        "INSERT INTO alembic_version (version_num) "
                        "VALUES ('0013_card_secret_ref_unique')"
                    )
                )

            previous_url = os.environ.get("ALEMBIC_DATABASE_URL")
            os.environ["ALEMBIC_DATABASE_URL"] = url
            try:
                config = Config(str(ROOT / "alembic.ini"))
                command.upgrade(config, "0014_audit_evidence_fields")
                columns = {column["name"]: column for column in inspect(engine).get_columns("audit_events")}
                for name in (
                    "actor_id",
                    "action",
                    "result",
                    "ip_address",
                    "user_agent",
                    "policy_version",
                ):
                    self.assertIn(name, columns)
                self.assertFalse(columns["action"]["nullable"])
                self.assertFalse(columns["result"]["nullable"])
                with engine.connect() as connection:
                    row = connection.execute(
                        text(
                            "SELECT actor_id, action, result FROM audit_events "
                            "WHERE id = 'event-1'"
                        )
                    ).one()
                    self.assertEqual(tuple(row), ("user-1", "upload.unknown", "unknown"))
                    head = connection.execute(
                        text("SELECT version_num FROM alembic_version")
                    ).scalar_one()
                    self.assertEqual(head, "0014_audit_evidence_fields")

                command.downgrade(config, "0013_card_secret_ref_unique")
                remaining = {
                    column["name"] for column in inspect(engine).get_columns("audit_events")
                }
                self.assertNotIn("actor_id", remaining)
                self.assertNotIn("policy_version", remaining)
            finally:
                if previous_url is None:
                    os.environ.pop("ALEMBIC_DATABASE_URL", None)
                else:
                    os.environ["ALEMBIC_DATABASE_URL"] = previous_url
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
