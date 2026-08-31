import io
import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0033_pool_import_receipts"
PREVIOUS_REVISION = "0032_upload_phase_tracking"


class PoolImportReceiptMigrationTests(unittest.TestCase):
    def test_postgresql_offline_sql_creates_only_the_receipt_table(self) -> None:
        output = io.StringIO()
        config = Config(str(ROOT / "alembic.ini"), output_buffer=output)
        config.cmd_opts = type(
            "Options",
            (),
            {
                "x": [
                    "db_url=postgresql+psycopg://placeholder:placeholder@localhost/db"
                ]
            },
        )()

        command.upgrade(config, f"{PREVIOUS_REVISION}:{REVISION}", sql=True)

        sql = output.getvalue()
        self.assertIn("CREATE TABLE pool_import_receipts", sql)
        self.assertNotIn("ALTER TABLE cards", sql)
        self.assertNotIn("ALTER TABLE mailboxes", sql)
        self.assertNotIn("platform_schema_compatibility", sql)

    def test_upgrade_and_downgrade_create_the_bounded_receipt_table(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "pool-import-receipts.db"
            url = f"sqlite+pysqlite:///{database.as_posix()}"
            previous = os.environ.get("ALEMBIC_DATABASE_URL")
            os.environ["ALEMBIC_DATABASE_URL"] = url
            engine = create_engine(url)
            try:
                with engine.begin() as connection:
                    connection.execute(
                        text(
                            "CREATE TABLE alembic_version ("
                            "version_num VARCHAR(255) NOT NULL PRIMARY KEY)"
                        )
                    )
                    connection.execute(
                        text("INSERT INTO alembic_version VALUES (:revision)"),
                        {"revision": PREVIOUS_REVISION},
                    )
                config = Config(str(ROOT / "alembic.ini"))
                command.upgrade(config, REVISION)
                inspector = inspect(engine)
                self.assertIn("pool_import_receipts", inspector.get_table_names())
                columns = {
                    item["name"]: item
                    for item in inspector.get_columns("pool_import_receipts")
                }
                self.assertEqual(
                    set(columns),
                    {
                        "id",
                        "tenant_id",
                        "pool_type",
                        "idempotency_key",
                        "request_digest",
                        "item_count",
                        "created_by",
                        "device_id",
                        "trace_id",
                        "created_at",
                    },
                )
                self.assertTrue(all(not item["nullable"] for item in columns.values()))
                unique_names = {
                    item["name"]
                    for item in inspector.get_unique_constraints("pool_import_receipts")
                }
                self.assertIn("uq_pool_import_receipts_tenant_pool_key", unique_names)
                foreign_keys = {
                    tuple(item["constrained_columns"]): item["referred_table"]
                    for item in inspector.get_foreign_keys("pool_import_receipts")
                }
                self.assertEqual(foreign_keys[("created_by",)], "users")
                self.assertEqual(foreign_keys[("device_id",)], "devices")
                check_names = {
                    item["name"]
                    for item in inspector.get_check_constraints("pool_import_receipts")
                }
                self.assertEqual(
                    check_names,
                    {
                        "ck_pool_import_receipts_item_count",
                        "ck_pool_import_receipts_pool_type",
                    },
                )

                command.downgrade(config, PREVIOUS_REVISION)
                self.assertNotIn("pool_import_receipts", inspect(engine).get_table_names())
            finally:
                if previous is None:
                    os.environ.pop("ALEMBIC_DATABASE_URL", None)
                else:
                    os.environ["ALEMBIC_DATABASE_URL"] = previous
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
