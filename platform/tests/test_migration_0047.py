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
REVISION = "0047_pool_import_receipt_context_binding"
PREVIOUS_REVISION = "0046_pool_import_context_delete_guard"


class PoolImportReceiptContextBindingMigrationTests(unittest.TestCase):
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
                "CREATE TABLE pool_import_contexts ("
                "id VARCHAR(36) NOT NULL PRIMARY KEY, "
                "tenant_id VARCHAR(64) NOT NULL, "
                "pool_type VARCHAR(16) NOT NULL, "
                "ordered_manifest_digest VARCHAR(64) NOT NULL, "
                "item_count INTEGER NOT NULL, "
                "created_by VARCHAR(36) NOT NULL, "
                "device_id VARCHAR(36) NOT NULL, "
                "consumed_at DATETIME NULL, "
                "pool_import_receipt_id VARCHAR(36) NULL)"
            ))
            connection.execute(text(
                "INSERT INTO pool_import_receipts VALUES ("
                "'legacy-local', 'tenant-a', 'mailbox', 'legacy-key', "
                "'legacy-digest', 1, 'user-a', 'device-a', 'trace-legacy', "
                "'2026-01-01 00:00:00')"
            ))
            connection.execute(text(
                "INSERT INTO pool_import_contexts VALUES "
                "('11111111-1111-4111-8111-111111111111', 'tenant-a', "
                "'card', 'digest-card', 2, 'user-a', 'device-a', NULL, NULL), "
                "('22222222-2222-4222-8222-222222222222', 'tenant-a', "
                "'mailbox', 'digest-mailbox', 1, 'user-a', 'device-a', "
                "NULL, NULL), "
                "('33333333-3333-4333-8333-333333333333', 'tenant-a', "
                "'mailbox', 'digest-consumed', 1, 'user-a', 'device-a', "
                "'2026-01-01 00:01:00', 'local-consumed')"
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

    def test_postgresql_offline_sql_installs_exact_insert_guard(self) -> None:
        output = io.StringIO()
        config = Config(str(ROOT / "alembic.ini"), output_buffer=output)
        config.cmd_opts = type("Options", (), {"x": [
            "db_url=postgresql+psycopg://placeholder:placeholder@localhost/db"
        ]})()

        command.upgrade(config, f"{PREVIOUS_REVISION}:{REVISION}", sql=True)

        sql = " ".join(output.getvalue().split())
        self.assertIn(
            "CREATE FUNCTION pool_import_receipts_validate_context_binding()",
            sql,
        )
        self.assertIn(
            "CREATE TRIGGER pool_import_receipts_context_binding BEFORE INSERT "
            "ON pool_import_receipts",
            sql,
        )
        self.assertIn("FOR KEY SHARE", sql)

    def test_new_receipts_require_exact_unconsumed_context_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "receipt-context-binding.db"
            with self._database(database) as (engine, config):
                self._create_previous_schema(engine)

                command.upgrade(config, REVISION)

                valid_rows = (
                    (
                        "local-card",
                        "tenant-a",
                        "card",
                        "spi:11111111-1111-4111-8111-111111111111",
                        "digest-card",
                        2,
                        "user-a",
                        "device-a",
                    ),
                    (
                        "local-mailbox",
                        "tenant-a",
                        "mailbox",
                        "spi:22222222-2222-4222-8222-222222222222",
                        "digest-mailbox",
                        1,
                        "user-a",
                        "device-a",
                    ),
                )
                with engine.begin() as connection:
                    for row in valid_rows:
                        connection.execute(
                            text(
                                "INSERT INTO pool_import_receipts VALUES ("
                                ":id, :tenant_id, :pool_type, :key, :digest, "
                                ":count, :user_id, :device_id, :trace_id, "
                                "'2026-01-01 00:02:00')"
                            ),
                            {
                                "id": row[0],
                                "tenant_id": row[1],
                                "pool_type": row[2],
                                "key": row[3],
                                "digest": row[4],
                                "count": row[5],
                                "user_id": row[6],
                                "device_id": row[7],
                                "trace_id": f"trace-{row[0]}",
                            },
                        )

                invalid_rows = (
                    ("wrong-prefix", "tenant-a", "card", "bad:11111111-1111-4111-8111-111111111111", "digest-card", 2, "user-a", "device-a"),
                    ("wrong-context", "tenant-a", "card", "spi:99999999-9999-4999-8999-999999999999", "digest-card", 2, "user-a", "device-a"),
                    ("wrong-tenant", "tenant-b", "card", "spi:11111111-1111-4111-8111-111111111111", "digest-card", 2, "user-a", "device-a"),
                    ("wrong-pool", "tenant-a", "mailbox", "spi:11111111-1111-4111-8111-111111111111", "digest-card", 2, "user-a", "device-a"),
                    ("wrong-digest", "tenant-a", "card", "spi:11111111-1111-4111-8111-111111111111", "digest-other", 2, "user-a", "device-a"),
                    ("wrong-count", "tenant-a", "card", "spi:11111111-1111-4111-8111-111111111111", "digest-card", 1, "user-a", "device-a"),
                    ("wrong-user", "tenant-a", "card", "spi:11111111-1111-4111-8111-111111111111", "digest-card", 2, "user-b", "device-a"),
                    ("wrong-device", "tenant-a", "card", "spi:11111111-1111-4111-8111-111111111111", "digest-card", 2, "user-a", "device-b"),
                    ("consumed", "tenant-a", "mailbox", "spi:33333333-3333-4333-8333-333333333333", "digest-consumed", 1, "user-a", "device-a"),
                )
                for row in invalid_rows:
                    with self.subTest(row=row[0]), self.assertRaises(
                        IntegrityError
                    ), engine.begin() as connection:
                        connection.execute(
                            text(
                                "INSERT INTO pool_import_receipts VALUES ("
                                ":id, :tenant_id, :pool_type, :key, :digest, "
                                ":count, :user_id, :device_id, :trace_id, "
                                "'2026-01-01 00:02:00')"
                            ),
                            {
                                "id": row[0],
                                "tenant_id": row[1],
                                "pool_type": row[2],
                                "key": row[3],
                                "digest": row[4],
                                "count": row[5],
                                "user_id": row[6],
                                "device_id": row[7],
                                "trace_id": f"trace-{row[0]}",
                            },
                        )

                with engine.connect() as connection:
                    legacy_count = connection.scalar(text(
                        "SELECT COUNT(*) FROM pool_import_receipts "
                        "WHERE id = 'legacy-local'"
                    ))
                self.assertEqual(legacy_count, 1)

                command.downgrade(config, PREVIOUS_REVISION)
                with engine.begin() as connection:
                    connection.execute(text(
                        "INSERT INTO pool_import_receipts VALUES ("
                        "'after-downgrade', 'tenant-b', 'card', 'free-key', "
                        "'free-digest', 1, 'user-b', 'device-b', "
                        "'trace-free', '2026-01-01 00:03:00')"
                    ))


if __name__ == "__main__":
    unittest.main()
