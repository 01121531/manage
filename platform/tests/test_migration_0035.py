import io
import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0035_pool_list_pagination"
PREVIOUS_REVISION = "0034_secure_pool_import_receipts"


class PoolListPaginationMigrationTests(unittest.TestCase):
    def test_postgresql_offline_sql_is_expand_only(self) -> None:
        output = io.StringIO()
        config = Config(str(ROOT / "alembic.ini"), output_buffer=output)
        config.cmd_opts = type("Options", (), {"x": [
            "db_url=postgresql+psycopg://placeholder:placeholder@localhost/db"
        ]})()
        command.upgrade(config, f"{PREVIOUS_REVISION}:{REVISION}", sql=True)
        sql = output.getvalue()
        self.assertIn("CREATE INDEX ix_cards_tenant_created_at_id", sql)
        self.assertIn("CREATE INDEX ix_mailboxes_tenant_created_at_id", sql)
        self.assertIn("CREATE INDEX ix_active_mail_sessions_tenant_mailbox_expires", sql)
        self.assertNotIn("DROP INDEX", sql)
        self.assertNotIn("ALTER TABLE", sql)

    def test_upgrade_adds_exact_non_unique_pagination_indexes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "pool-list-pagination.db"
            url = f"sqlite+pysqlite:///{database.as_posix()}"
            previous = os.environ.get("ALEMBIC_DATABASE_URL")
            os.environ["ALEMBIC_DATABASE_URL"] = url
            engine = create_engine(url)
            try:
                with engine.begin() as connection:
                    connection.execute(text(
                        "CREATE TABLE alembic_version (version_num VARCHAR(255) NOT NULL PRIMARY KEY)"
                    ))
                    connection.execute(text(
                        "INSERT INTO alembic_version VALUES (:revision)"
                    ), {"revision": PREVIOUS_REVISION})
                    connection.execute(text(
                        "CREATE TABLE cards (id VARCHAR(36) NOT NULL PRIMARY KEY, "
                        "tenant_id VARCHAR(64) NOT NULL, created_at DATETIME NOT NULL)"
                    ))
                    connection.execute(text(
                        "CREATE TABLE mailboxes (id VARCHAR(36) NOT NULL PRIMARY KEY, "
                        "tenant_id VARCHAR(64) NOT NULL, created_at DATETIME NOT NULL)"
                    ))
                    connection.execute(text(
                        "CREATE TABLE mail_sessions (id VARCHAR(36) NOT NULL PRIMARY KEY, "
                        "tenant_id VARCHAR(64) NOT NULL, mailbox_id VARCHAR(36) NOT NULL, "
                        "expires_at DATETIME NOT NULL, status VARCHAR(32) NOT NULL)"
                    ))
                config = Config(str(ROOT / "alembic.ini"))
                command.upgrade(config, REVISION)
                inspector = inspect(engine)
                for table_name, index_name in (
                    ("cards", "ix_cards_tenant_created_at_id"),
                    ("mailboxes", "ix_mailboxes_tenant_created_at_id"),
                ):
                    indexes = {
                        item["name"]: item for item in inspector.get_indexes(table_name)
                    }
                    self.assertEqual(
                        indexes[index_name]["column_names"],
                        ["tenant_id", "created_at", "id"],
                    )
                    self.assertFalse(indexes[index_name]["unique"])
                session_indexes = {
                    item["name"]: item
                    for item in inspector.get_indexes("mail_sessions")
                }
                self.assertEqual(
                    session_indexes[
                        "ix_active_mail_sessions_tenant_mailbox_expires"
                    ]["column_names"],
                    ["tenant_id", "mailbox_id", "expires_at"],
                )
                self.assertFalse(session_indexes[
                    "ix_active_mail_sessions_tenant_mailbox_expires"
                ]["unique"])
            finally:
                if previous is None:
                    os.environ.pop("ALEMBIC_DATABASE_URL", None)
                else:
                    os.environ["ALEMBIC_DATABASE_URL"] = previous
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
