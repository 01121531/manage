import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]


class DeviceLastSeenMigrationTests(unittest.TestCase):
    def test_0015_to_0016_preserves_existing_devices_and_is_reversible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "device-last-seen-migration.db"
            url = f"sqlite+pysqlite:///{database.as_posix()}"
            previous_url = os.environ.get("ALEMBIC_DATABASE_URL")
            os.environ["ALEMBIC_DATABASE_URL"] = url
            engine = create_engine(url)
            try:
                with engine.begin() as connection:
                    connection.execute(
                        text(
                            """
                            CREATE TABLE devices (
                                id VARCHAR(36) PRIMARY KEY,
                                tenant_id VARCHAR(64) NOT NULL,
                                user_id VARCHAR(36) NOT NULL,
                                name VARCHAR(120) NOT NULL,
                                revoked_at DATETIME,
                                created_at DATETIME NOT NULL
                            )
                            """
                        )
                    )
                    connection.execute(
                        text(
                            """
                            INSERT INTO devices (
                                id, tenant_id, user_id, name, revoked_at, created_at
                            ) VALUES (
                                'device-1', 'tenant-a', 'user-1', 'existing', NULL,
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
                            "VALUES ('0015_mailbox_health')"
                        )
                    )

                config = Config(str(ROOT / "alembic.ini"))
                command.upgrade(config, "0016_device_last_seen")
                columns = {
                    column["name"]: column
                    for column in inspect(engine).get_columns("devices")
                }
                self.assertIn("last_seen_at", columns)
                self.assertTrue(columns["last_seen_at"]["nullable"])
                with engine.connect() as connection:
                    self.assertIsNone(
                        connection.execute(
                            text(
                                "SELECT last_seen_at FROM devices "
                                "WHERE id = 'device-1'"
                            )
                        ).scalar_one()
                    )
                    self.assertEqual(
                        connection.execute(
                            text("SELECT version_num FROM alembic_version")
                        ).scalar_one(),
                        "0016_device_last_seen",
                    )

                command.downgrade(config, "0015_mailbox_health")
                remaining = {
                    column["name"]
                    for column in inspect(engine).get_columns("devices")
                }
                self.assertNotIn("last_seen_at", remaining)
            finally:
                if previous_url is None:
                    os.environ.pop("ALEMBIC_DATABASE_URL", None)
                else:
                    os.environ["ALEMBIC_DATABASE_URL"] = previous_url
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
