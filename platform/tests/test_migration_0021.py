import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0021_audit_archive_index"
PREVIOUS_REVISION = "0020_audit_event_subject_binding"
INDEX_NAME = "ix_audit_events_tenant_created_at_id"


class AuditArchiveIndexMigrationTests(unittest.TestCase):
    def test_upgrade_adds_keyset_index_and_downgrade_removes_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "audit-archive-index.db"
            url = f"sqlite+pysqlite:///{database.as_posix()}"
            engine = create_engine(url)
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "CREATE TABLE audit_events ("
                        "id VARCHAR(36) NOT NULL PRIMARY KEY, "
                        "tenant_id VARCHAR(64) NOT NULL, "
                        "created_at DATETIME NOT NULL)"
                    )
                )
                connection.execute(
                    text(
                        "CREATE TABLE alembic_version "
                        "(version_num VARCHAR(64) NOT NULL PRIMARY KEY)"
                    )
                )
                connection.execute(
                    text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
                    {"revision": PREVIOUS_REVISION},
                )

            previous = os.environ.get("ALEMBIC_DATABASE_URL")
            os.environ["ALEMBIC_DATABASE_URL"] = url
            try:
                config = Config(str(ROOT / "alembic.ini"))
                command.upgrade(config, REVISION)
                indexes = {
                    item["name"]: item for item in inspect(engine).get_indexes("audit_events")
                }
                self.assertIn(INDEX_NAME, indexes)
                self.assertEqual(
                    indexes[INDEX_NAME]["column_names"],
                    ["tenant_id", "created_at", "id"],
                )
                self.assertFalse(indexes[INDEX_NAME]["unique"])

                command.downgrade(config, PREVIOUS_REVISION)
                index_names = {
                    item["name"] for item in inspect(engine).get_indexes("audit_events")
                }
                self.assertNotIn(INDEX_NAME, index_names)
            finally:
                if previous is None:
                    os.environ.pop("ALEMBIC_DATABASE_URL", None)
                else:
                    os.environ["ALEMBIC_DATABASE_URL"] = previous
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
