import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0029_card_replacement"
PREVIOUS_REVISION = "0028_operational_policy_governance"
COMPATIBILITY_FLOOR = "0024_schema_compatibility"


class CardReplacementMigrationTests(unittest.TestCase):
    def test_upgrade_adds_unique_replacement_links_without_raising_floor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "card-replacement.db"
            url = f"sqlite+pysqlite:///{database.as_posix()}"
            engine = create_engine(url)
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "CREATE TABLE card_allocations ("
                        "id VARCHAR(36) NOT NULL PRIMARY KEY)"
                    )
                )
                connection.execute(
                    text(
                        "CREATE TABLE tasks ("
                        "id VARCHAR(36) NOT NULL PRIMARY KEY)"
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
                inspector = inspect(engine)
                self.assertIn(
                    "card_allocation_replacements", inspector.get_table_names()
                )
                columns = {
                    item["name"]: item
                    for item in inspector.get_columns(
                        "card_allocation_replacements"
                    )
                }
                self.assertFalse(columns["original_allocation_id"]["nullable"])
                self.assertFalse(columns["replacement_allocation_id"]["nullable"])
                self.assertEqual(columns["tenant_id"]["type"].length, 64)
                self.assertIn(
                    "uq_card_allocation_replacements_replacement_id",
                    {
                        item["name"]
                        for item in inspector.get_unique_constraints(
                            "card_allocation_replacements"
                        )
                    },
                )
                self.assertCountEqual(
                    [
                        (
                            item["constrained_columns"],
                            item["referred_table"],
                            item["referred_columns"],
                        )
                        for item in inspector.get_foreign_keys(
                            "card_allocation_replacements"
                        )
                    ],
                    [
                        (["original_allocation_id"], "card_allocations", ["id"]),
                        (["replacement_allocation_id"], "card_allocations", ["id"]),
                        (["task_id"], "tasks", ["id"]),
                    ],
                )
                with engine.connect() as connection:
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
                self.assertNotIn(
                    "card_allocation_replacements",
                    inspect(engine).get_table_names(),
                )
            finally:
                if previous is None:
                    os.environ.pop("ALEMBIC_DATABASE_URL", None)
                else:
                    os.environ["ALEMBIC_DATABASE_URL"] = previous
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
