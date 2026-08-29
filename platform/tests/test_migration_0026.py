import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0026_mail_message_metadata"
PREVIOUS_REVISION = "0025_oidc_session_revocations"
COMPATIBILITY_FLOOR = "0024_schema_compatibility"


class MailMessageMetadataMigrationTests(unittest.TestCase):
    def test_upgrade_adds_nullable_hash_without_raising_floor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "mail-message-metadata.db"
            url = f"sqlite+pysqlite:///{database.as_posix()}"
            engine = create_engine(url)
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "CREATE TABLE mail_sessions ("
                        "id VARCHAR(36) NOT NULL PRIMARY KEY, "
                        "delivered_code VARCHAR(8), "
                        "delivered_at DATETIME)"
                    )
                )
                connection.execute(
                    text(
                        "INSERT INTO mail_sessions "
                        "(id, delivered_code, delivered_at) "
                        "VALUES ('session-1', NULL, NULL)"
                    )
                )
                connection.execute(
                    text(
                        "CREATE TABLE platform_schema_compatibility ("
                        "singleton_id INTEGER NOT NULL PRIMARY KEY, "
                        "minimum_app_revision VARCHAR(255) NOT NULL)"
                    )
                )
                connection.execute(
                    text(
                        "INSERT INTO platform_schema_compatibility "
                        "(singleton_id, minimum_app_revision) VALUES (1, :revision)"
                    ),
                    {"revision": COMPATIBILITY_FLOOR},
                )
                connection.execute(
                    text(
                        "CREATE TABLE alembic_version "
                        "(version_num VARCHAR(255) NOT NULL PRIMARY KEY)"
                    )
                )
                connection.execute(
                    text(
                        "INSERT INTO alembic_version(version_num) VALUES (:revision)"
                    ),
                    {"revision": PREVIOUS_REVISION},
                )

            previous = os.environ.get("ALEMBIC_DATABASE_URL")
            os.environ["ALEMBIC_DATABASE_URL"] = url
            try:
                config = Config(str(ROOT / "alembic.ini"))
                command.upgrade(config, REVISION)
                columns = {
                    item["name"]: item
                    for item in inspect(engine).get_columns("mail_sessions")
                }
                metadata_column = columns["delivered_message_id_hash"]
                self.assertTrue(metadata_column["nullable"])
                self.assertEqual(metadata_column["type"].length, 64)
                with engine.connect() as connection:
                    self.assertIsNone(
                        connection.execute(
                            text(
                                "SELECT delivered_message_id_hash "
                                "FROM mail_sessions WHERE id = 'session-1'"
                            )
                        ).scalar_one()
                    )
                    self.assertEqual(
                        connection.execute(
                            text(
                                "SELECT minimum_app_revision "
                                "FROM platform_schema_compatibility "
                                "WHERE singleton_id = 1"
                            )
                        ).scalar_one(),
                        COMPATIBILITY_FLOOR,
                    )
                    self.assertEqual(
                        connection.execute(
                            text("SELECT version_num FROM alembic_version")
                        ).scalar_one(),
                        REVISION,
                    )

                command.downgrade(config, PREVIOUS_REVISION)
                remaining = {
                    item["name"]
                    for item in inspect(engine).get_columns("mail_sessions")
                }
                self.assertNotIn("delivered_message_id_hash", remaining)
            finally:
                if previous is None:
                    os.environ.pop("ALEMBIC_DATABASE_URL", None)
                else:
                    os.environ["ALEMBIC_DATABASE_URL"] = previous
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
