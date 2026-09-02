import io
import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0045_pool_import_receipt_append_only"
PREVIOUS_REVISION = "0044_pool_context_consumption_terminal"

MUTATIONS = {
    "id": "'local-rewritten'",
    "tenant_id": "'tenant-b'",
    "pool_type": "'mailbox'",
    "idempotency_key": "'spi:receipt-rewritten'",
    "request_digest": "'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'",
    "item_count": "2",
    "created_by": "'user-b'",
    "device_id": "'device-b'",
    "trace_id": "'trace-b'",
    "created_at": "'2026-01-01 00:01:00'",
}


class PoolImportReceiptAppendOnlyMigrationTests(unittest.TestCase):
    @staticmethod
    def _create_previous_schema(engine) -> None:
        with engine.begin() as connection:
            connection.execute(text(
                "CREATE TABLE alembic_version ("
                "version_num VARCHAR(255) NOT NULL PRIMARY KEY)"
            ))
            connection.execute(
                text("INSERT INTO alembic_version VALUES (:revision)"),
                {"revision": PREVIOUS_REVISION},
            )
            connection.execute(text(
                "CREATE TABLE pool_import_receipts ("
                "id VARCHAR(36) NOT NULL PRIMARY KEY, "
                "tenant_id VARCHAR(64) NOT NULL, "
                "pool_type VARCHAR(16) NOT NULL, "
                "idempotency_key VARCHAR(160) NOT NULL, "
                "request_digest VARCHAR(64) NOT NULL, "
                "item_count INTEGER NOT NULL, "
                "created_by VARCHAR(36) NOT NULL, "
                "device_id VARCHAR(36) NOT NULL, "
                "trace_id VARCHAR(36) NOT NULL, "
                "created_at DATETIME NOT NULL)"
            ))
            connection.execute(text(
                "INSERT INTO pool_import_receipts ("
                "id, tenant_id, pool_type, idempotency_key, request_digest, "
                "item_count, created_by, device_id, trace_id, created_at) "
                "VALUES ('local-a', 'tenant-a', 'card', 'spi:receipt-a', "
                "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', "
                "1, 'user-a', 'device-a', 'trace-a', "
                "'2026-01-01 00:00:00')"
            ))

    @contextmanager
    def _database(self, database: Path):
        url = f"sqlite+pysqlite:///{database.as_posix()}"
        previous = os.environ.get("ALEMBIC_DATABASE_URL")
        os.environ["ALEMBIC_DATABASE_URL"] = url
        engine = create_engine(url)
        try:
            yield engine, Config(str(ROOT / "alembic.ini"))
        finally:
            engine.dispose()
            if previous is None:
                os.environ.pop("ALEMBIC_DATABASE_URL", None)
            else:
                os.environ["ALEMBIC_DATABASE_URL"] = previous

    def test_postgresql_offline_sql_installs_exact_append_only_guard(self) -> None:
        output = io.StringIO()
        config = Config(str(ROOT / "alembic.ini"), output_buffer=output)
        config.cmd_opts = type("Options", (), {"x": [
            "db_url=postgresql+psycopg://placeholder:placeholder@localhost/db"
        ]})()

        command.upgrade(config, f"{PREVIOUS_REVISION}:{REVISION}", sql=True)

        sql = " ".join(output.getvalue().split())
        self.assertIn(
            "CREATE FUNCTION pool_import_receipts_prevent_mutation()",
            sql,
        )
        self.assertIn(
            "CREATE TRIGGER pool_import_receipts_append_only BEFORE UPDATE OR "
            "DELETE ON pool_import_receipts",
            sql,
        )

    def test_receipt_is_append_only_and_downgrade_removes_guard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "pool-import-receipt-append-only.db"
            with self._database(database) as (engine, config):
                self._create_previous_schema(engine)

                command.upgrade(config, REVISION)

                for column, replacement in MUTATIONS.items():
                    statement = (
                        "UPDATE pool_import_receipts SET "
                        f"{column} = {replacement} WHERE id = 'local-a'"
                    )
                    with self.subTest(column=column), self.assertRaises(
                        IntegrityError
                    ), engine.begin() as connection:
                        connection.execute(text(statement))
                with self.assertRaises(IntegrityError), engine.begin() as connection:
                    connection.execute(text(
                        "DELETE FROM pool_import_receipts WHERE id = 'local-a'"
                    ))

                with engine.begin() as connection:
                    connection.execute(text(
                        "INSERT INTO pool_import_receipts ("
                        "id, tenant_id, pool_type, idempotency_key, "
                        "request_digest, item_count, created_by, device_id, "
                        "trace_id, created_at) VALUES ("
                        "'local-b', 'tenant-a', 'mailbox', 'spi:receipt-b', "
                        "'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', "
                        "1, 'user-a', 'device-a', 'trace-b', "
                        "'2026-01-01 00:01:00')"
                    ))

                command.downgrade(config, PREVIOUS_REVISION)
                with engine.begin() as connection:
                    connection.execute(text(
                        "UPDATE pool_import_receipts SET trace_id = 'trace-c' "
                        "WHERE id = 'local-a'"
                    ))
                    connection.execute(text(
                        "DELETE FROM pool_import_receipts WHERE id = 'local-a'"
                    ))
                    remaining = connection.scalar(text(
                        "SELECT COUNT(*) FROM pool_import_receipts"
                    ))
                self.assertEqual(remaining, 1)


if __name__ == "__main__":
    unittest.main()
