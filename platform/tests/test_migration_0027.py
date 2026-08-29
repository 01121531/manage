import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0027_card_allocation_reason"
PREVIOUS_REVISION = "0026_mail_message_metadata"
COMPATIBILITY_FLOOR = "0024_schema_compatibility"


class CardAllocationReasonMigrationTests(unittest.TestCase):
    def test_upgrade_backfills_reason_without_raising_compatibility_floor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "card-allocation-reason.db"
            url = f"sqlite+pysqlite:///{database.as_posix()}"
            engine = create_engine(url)
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "CREATE TABLE card_allocations ("
                        "id VARCHAR(36) NOT NULL PRIMARY KEY, "
                        "status VARCHAR(32) NOT NULL)"
                    )
                )
                connection.execute(
                    text(
                        "INSERT INTO card_allocations (id, status) "
                        "VALUES ('allocation-1', 'active')"
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
                    for item in inspect(engine).get_columns("card_allocations")
                }
                reason_column = columns["allocation_reason_code"]
                self.assertFalse(reason_column["nullable"])
                self.assertEqual(reason_column["type"].length, 80)
                with engine.connect() as connection:
                    self.assertEqual(
                        connection.execute(
                            text(
                                "SELECT allocation_reason_code "
                                "FROM card_allocations WHERE id = 'allocation-1'"
                            )
                        ).scalar_one(),
                        "task_assigned",
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

                command.downgrade(config, PREVIOUS_REVISION)
                remaining = {
                    item["name"]
                    for item in inspect(engine).get_columns("card_allocations")
                }
                self.assertNotIn("allocation_reason_code", remaining)
            finally:
                if previous is None:
                    os.environ.pop("ALEMBIC_DATABASE_URL", None)
                else:
                    os.environ["ALEMBIC_DATABASE_URL"] = previous
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
