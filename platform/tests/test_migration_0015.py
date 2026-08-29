import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]


class MailboxHealthMigrationTests(unittest.TestCase):
    def test_0014_to_0015_backfills_unknown_health_and_is_reversible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "mailbox-health-migration.db"
            url = f"sqlite+pysqlite:///{database.as_posix()}"
            previous_url = os.environ.get("ALEMBIC_DATABASE_URL")
            os.environ["ALEMBIC_DATABASE_URL"] = url
            engine = create_engine(url)
            try:
                with engine.begin() as connection:
                    connection.execute(
                        text(
                            """
                            CREATE TABLE mailboxes (
                                id VARCHAR(36) PRIMARY KEY,
                                tenant_id VARCHAR(64) NOT NULL,
                                email_masked VARCHAR(255) NOT NULL,
                                connector_type VARCHAR(64) NOT NULL,
                                secret_ref VARCHAR(255) NOT NULL,
                                is_active BOOLEAN NOT NULL,
                                created_at DATETIME NOT NULL
                            )
                            """
                        )
                    )
                    connection.execute(
                        text(
                            """
                            INSERT INTO mailboxes (
                                id, tenant_id, email_masked, connector_type,
                                secret_ref, is_active, created_at
                            ) VALUES (
                                'mailbox-1', 'tenant-a', 'm***@example.invalid',
                                'fake', 'vault://secret/mailboxes/mailbox-1', 1,
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
                            "VALUES ('0014_audit_evidence_fields')"
                        )
                    )

                config = Config(str(ROOT / "alembic.ini"))
                command.upgrade(config, "0015_mailbox_health")
                columns = {
                    column["name"]: column
                    for column in inspect(engine).get_columns("mailboxes")
                }
                self.assertIn("health_status", columns)
                self.assertIn("last_checked_at", columns)
                self.assertIn("last_error_code", columns)
                self.assertFalse(columns["health_status"]["nullable"])
                with engine.connect() as connection:
                    row = connection.execute(
                        text(
                            "SELECT health_status, last_checked_at, last_error_code "
                            "FROM mailboxes WHERE id = 'mailbox-1'"
                        )
                    ).one()
                    self.assertEqual(tuple(row), ("unknown", None, None))
                    self.assertEqual(
                        connection.execute(
                            text("SELECT version_num FROM alembic_version")
                        ).scalar_one(),
                        "0015_mailbox_health",
                    )

                command.downgrade(config, "0014_audit_evidence_fields")
                remaining = {
                    column["name"]
                    for column in inspect(engine).get_columns("mailboxes")
                }
                self.assertNotIn("health_status", remaining)
                self.assertNotIn("last_checked_at", remaining)
                self.assertNotIn("last_error_code", remaining)
            finally:
                if previous_url is None:
                    os.environ.pop("ALEMBIC_DATABASE_URL", None)
                else:
                    os.environ["ALEMBIC_DATABASE_URL"] = previous_url
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
