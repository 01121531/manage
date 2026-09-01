import io
import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0036_pool_import_contexts"
PREVIOUS_REVISION = "0035_pool_list_pagination"


class PoolImportContextMigrationTests(unittest.TestCase):
    def test_postgresql_offline_sql_is_expand_only(self) -> None:
        output = io.StringIO()
        config = Config(str(ROOT / "alembic.ini"), output_buffer=output)
        config.cmd_opts = type("Options", (), {"x": [
            "db_url=postgresql+psycopg://placeholder:placeholder@localhost/db"
        ]})()
        command.upgrade(config, f"{PREVIOUS_REVISION}:{REVISION}", sql=True)
        sql = output.getvalue()
        self.assertIn("CREATE TABLE pool_import_contexts", sql)
        self.assertIn("CREATE INDEX ix_pool_import_contexts_tenant_id", sql)
        self.assertIn("CREATE INDEX ix_pool_import_contexts_expires_at", sql)
        self.assertNotIn("DROP TABLE", sql)
        self.assertNotIn("ALTER TABLE", sql)

    def test_upgrade_adds_secret_free_context_table(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "pool-import-context.db"
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
                        "CREATE TABLE users (id VARCHAR(36) NOT NULL PRIMARY KEY)"
                    ))
                    connection.execute(text(
                        "CREATE TABLE devices (id VARCHAR(36) NOT NULL PRIMARY KEY)"
                    ))
                    connection.execute(text(
                        "CREATE TABLE pool_import_receipts (id VARCHAR(36) NOT NULL PRIMARY KEY)"
                    ))
                config = Config(str(ROOT / "alembic.ini"))
                command.upgrade(config, REVISION)
                inspector = inspect(engine)
                columns = {
                    column["name"]: column
                    for column in inspector.get_columns("pool_import_contexts")
                }
                self.assertEqual(set(columns), {
                    "id", "context_token_hash", "tenant_id", "audience",
                    "pool_type", "ordered_manifest_digest", "item_count",
                    "created_by", "device_id", "trace_id", "created_at",
                    "expires_at", "consumed_at", "pool_import_receipt_id",
                })
                self.assertFalse(columns["context_token_hash"]["nullable"])
                self.assertTrue(columns["consumed_at"]["nullable"])
                uniques = {
                    item["name"] for item in inspector.get_unique_constraints(
                        "pool_import_contexts"
                    )
                }
                self.assertEqual(uniques, {
                    "uq_pool_import_contexts_token_hash",
                    "uq_pool_import_contexts_local_receipt",
                })
            finally:
                if previous is None:
                    os.environ.pop("ALEMBIC_DATABASE_URL", None)
                else:
                    os.environ["ALEMBIC_DATABASE_URL"] = previous
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
