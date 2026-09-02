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
REVISION = "0042_pool_context_identity_lock"
PREVIOUS_REVISION = "0041_card_claim_mutation_ledger"

IDENTITY_UPDATES = {
    "id": "'context-rewritten'",
    "context_token_hash": "'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'",
    "tenant_id": "'tenant-b'",
    "audience": "'email-platform:pool-import:other'",
    "pool_type": "'mailbox'",
    "ordered_manifest_digest": (
        "'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'"
    ),
    "item_count": "2",
    "created_by": "'user-b'",
    "device_id": "'device-b'",
    "trace_id": "'trace-b'",
    "created_at": "'2026-01-02 00:00:00'",
}


class PoolImportContextIdentityMigrationTests(unittest.TestCase):
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
                "CREATE TABLE pool_import_contexts ("
                "id VARCHAR(36) NOT NULL PRIMARY KEY, "
                "context_token_hash VARCHAR(64) NOT NULL, "
                "tenant_id VARCHAR(64) NOT NULL, "
                "audience VARCHAR(160) NOT NULL, "
                "pool_type VARCHAR(16) NOT NULL, "
                "ordered_manifest_digest VARCHAR(64) NOT NULL, "
                "item_count INTEGER NOT NULL, "
                "created_by VARCHAR(36) NOT NULL, "
                "device_id VARCHAR(36) NOT NULL, "
                "trace_id VARCHAR(36) NOT NULL, "
                "created_at DATETIME NOT NULL, "
                "expires_at DATETIME NOT NULL, "
                "consumed_at DATETIME, "
                "pool_import_receipt_id VARCHAR(36))"
            ))
            connection.execute(text(
                "INSERT INTO pool_import_contexts ("
                "id, context_token_hash, tenant_id, audience, pool_type, "
                "ordered_manifest_digest, item_count, created_by, device_id, "
                "trace_id, created_at, expires_at, consumed_at, "
                "pool_import_receipt_id) VALUES ("
                "'context-a', "
                "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', "
                "'tenant-a', 'email-platform:pool-import:test', 'card', "
                "'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', "
                "1, 'user-a', 'device-a', 'trace-a', "
                "'2026-01-01 00:00:00', '2026-01-01 00:15:00', NULL, NULL)"
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

    def test_postgresql_offline_sql_installs_exact_identity_guard(self) -> None:
        output = io.StringIO()
        config = Config(str(ROOT / "alembic.ini"), output_buffer=output)
        config.cmd_opts = type("Options", (), {"x": [
            "db_url=postgresql+psycopg://placeholder:placeholder@localhost/db"
        ]})()

        command.upgrade(config, f"{PREVIOUS_REVISION}:{REVISION}", sql=True)

        sql = " ".join(output.getvalue().split())
        self.assertIn(
            "CREATE FUNCTION pool_import_contexts_prevent_identity_change()",
            sql,
        )
        self.assertIn(
            "CREATE TRIGGER pool_import_contexts_identity_immutable BEFORE "
            "UPDATE OF id, context_token_hash, tenant_id, audience, pool_type, "
            "ordered_manifest_digest, item_count, created_by, device_id, "
            "trace_id, created_at ON pool_import_contexts",
            sql,
        )

    def test_identity_is_immutable_but_lifecycle_fields_remain_mutable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "pool-context-identity.db"
            with self._database(database) as (engine, config):
                self._create_previous_schema(engine)

                command.upgrade(config, REVISION)

                for column, replacement in IDENTITY_UPDATES.items():
                    statement = (
                        f"UPDATE pool_import_contexts SET {column} = {replacement} "
                        "WHERE id = 'context-a'"
                    )
                    with self.subTest(column=column), self.assertRaises(
                        IntegrityError
                    ), engine.begin() as connection:
                        connection.execute(text(statement))

                with engine.begin() as connection:
                    connection.execute(text(
                        "UPDATE pool_import_contexts SET "
                        "expires_at = '2026-01-01 00:30:00', "
                        "consumed_at = '2026-01-01 00:20:00', "
                        "pool_import_receipt_id = 'receipt-a' "
                        "WHERE id = 'context-a'"
                    ))
                    lifecycle = connection.execute(text(
                        "SELECT expires_at, consumed_at, pool_import_receipt_id "
                        "FROM pool_import_contexts WHERE id = 'context-a'"
                    )).one()
                self.assertEqual(lifecycle[2], "receipt-a")
                self.assertIsNotNone(lifecycle[0])
                self.assertIsNotNone(lifecycle[1])

                command.downgrade(config, PREVIOUS_REVISION)
                with engine.begin() as connection:
                    connection.execute(text(
                        "UPDATE pool_import_contexts SET trace_id = 'trace-b' "
                        "WHERE id = 'context-a'"
                    ))
                    self.assertEqual(
                        connection.scalar(text(
                            "SELECT trace_id FROM pool_import_contexts "
                            "WHERE id = 'context-a'"
                        )),
                        "trace-b",
                    )


if __name__ == "__main__":
    unittest.main()
