import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0024_schema_compatibility"
PREVIOUS_REVISION = "0023_card_events"


class SchemaCompatibilityMigrationTests(unittest.TestCase):
    def test_upgrade_adds_single_compatibility_floor_and_downgrade_removes_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "schema-compatibility.db"
            url = f"sqlite+pysqlite:///{database.as_posix()}"
            engine = create_engine(url)
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "CREATE TABLE alembic_version "
                        "(version_num VARCHAR(255) NOT NULL PRIMARY KEY)"
                    )
                )
                connection.execute(
                    text("INSERT INTO alembic_version(version_num) VALUES (:revision)"),
                    {"revision": PREVIOUS_REVISION},
                )
            previous = os.environ.get("ALEMBIC_DATABASE_URL")
            os.environ["ALEMBIC_DATABASE_URL"] = url
            try:
                config = Config(str(ROOT / "alembic.ini"))
                command.upgrade(config, REVISION)
                with engine.connect() as connection:
                    row = connection.execute(
                        text(
                            "SELECT singleton_id, minimum_app_revision "
                            "FROM platform_schema_compatibility"
                        )
                    ).one()
                self.assertEqual(tuple(row), (1, REVISION))
                command.downgrade(config, PREVIOUS_REVISION)
                self.assertNotIn(
                    "platform_schema_compatibility",
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
