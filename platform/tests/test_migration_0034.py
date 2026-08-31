import io
import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0034_secure_pool_import_receipts"
PREVIOUS_REVISION = "0033_pool_import_receipts"


class SecurePoolImportReceiptMigrationTests(unittest.TestCase):
    def test_postgresql_offline_sql_is_expand_only(self) -> None:
        output = io.StringIO()
        config = Config(str(ROOT / "alembic.ini"), output_buffer=output)
        config.cmd_opts = type("Options", (), {"x": [
            "db_url=postgresql+psycopg://placeholder:placeholder@localhost/db"
        ]})()
        command.upgrade(config, f"{PREVIOUS_REVISION}:{REVISION}", sql=True)
        sql = output.getvalue()
        self.assertIn("CREATE TABLE secure_pool_import_consumptions", sql)
        self.assertIn("uq_secure_pool_import_consumptions_local_receipt", sql)
        self.assertNotIn("DROP COLUMN", sql)

    def test_upgrade_adds_nullable_legacy_safe_columns_and_unique_constraint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "secure-pool-import.db"
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
                        "CREATE TABLE pool_import_receipts ("
                        "id VARCHAR(36) NOT NULL PRIMARY KEY, "
                        "tenant_id VARCHAR(64) NOT NULL, pool_type VARCHAR(16) NOT NULL, "
                        "idempotency_key VARCHAR(160) NOT NULL, request_digest VARCHAR(64) NOT NULL, "
                        "item_count INTEGER NOT NULL, created_by VARCHAR(36) NOT NULL, "
                        "device_id VARCHAR(36) NOT NULL, trace_id VARCHAR(36) NOT NULL, "
                        "created_at DATETIME NOT NULL, "
                        "CONSTRAINT uq_pool_import_receipts_tenant_pool_key "
                        "UNIQUE (tenant_id, pool_type, idempotency_key))"
                    ))
                config = Config(str(ROOT / "alembic.ini"))
                command.upgrade(config, REVISION)
                inspector = inspect(engine)
                self.assertIn("secure_pool_import_consumptions", inspector.get_table_names())
                columns = {
                    item["name"]: item
                    for item in inspector.get_columns("secure_pool_import_consumptions")
                }
                self.assertEqual(set(columns), {
                    "receipt_id", "pool_import_receipt_id", "issued_at",
                    "expires_at", "key_version", "consumed_at",
                })
                self.assertTrue(all(not item["nullable"] for item in columns.values()))
                unique_names = {
                    item["name"]
                    for item in inspector.get_unique_constraints("secure_pool_import_consumptions")
                }
                self.assertIn("uq_secure_pool_import_consumptions_local_receipt", unique_names)
            finally:
                if previous is None:
                    os.environ.pop("ALEMBIC_DATABASE_URL", None)
                else:
                    os.environ["ALEMBIC_DATABASE_URL"] = previous
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
