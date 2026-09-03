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
REVISION = "0046_pool_import_context_delete_guard"
PREVIOUS_REVISION = "0045_pool_import_receipt_append_only"


class PoolImportContextDeleteGuardMigrationTests(unittest.TestCase):
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
                "consumed_at DATETIME NULL, "
                "pool_import_receipt_id VARCHAR(36) NULL)"
            ))
            connection.execute(text(
                "INSERT INTO pool_import_contexts ("
                "id, context_token_hash, tenant_id, audience, pool_type, "
                "ordered_manifest_digest, item_count, created_by, device_id, "
                "trace_id, created_at, expires_at, consumed_at, "
                "pool_import_receipt_id) VALUES "
                "('context-card', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', "
                "'tenant-a', 'audience-a', 'card', "
                "'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', "
                "1, 'user-a', 'device-a', 'trace-card', "
                "'2026-01-01 00:00:00', '2026-01-01 00:05:00', NULL, NULL), "
                "('context-mailbox', 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', "
                "'tenant-a', 'audience-a', 'mailbox', "
                "'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd', "
                "1, 'user-a', 'device-a', 'trace-mailbox', "
                "'2026-01-01 00:00:00', '2026-01-01 00:05:00', "
                "'2026-01-01 00:01:00', 'local-mailbox')"
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

    def test_postgresql_offline_sql_installs_exact_delete_guard(self) -> None:
        output = io.StringIO()
        config = Config(str(ROOT / "alembic.ini"), output_buffer=output)
        config.cmd_opts = type("Options", (), {"x": [
            "db_url=postgresql+psycopg://placeholder:placeholder@localhost/db"
        ]})()

        command.upgrade(config, f"{PREVIOUS_REVISION}:{REVISION}", sql=True)

        sql = " ".join(output.getvalue().split())
        self.assertIn(
            "CREATE FUNCTION pool_import_contexts_prevent_delete()",
            sql,
        )
        self.assertIn(
            "CREATE TRIGGER pool_import_contexts_no_delete BEFORE DELETE ON "
            "pool_import_contexts",
            sql,
        )

    def test_both_pool_contexts_reject_delete_and_downgrade_removes_guard(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "pool-import-context-delete-guard.db"
            with self._database(database) as (engine, config):
                self._create_previous_schema(engine)

                command.upgrade(config, REVISION)

                for context_id in ("context-card", "context-mailbox"):
                    with self.subTest(context_id=context_id), self.assertRaises(
                        IntegrityError
                    ), engine.begin() as connection:
                        connection.execute(
                            text("DELETE FROM pool_import_contexts WHERE id = :id"),
                            {"id": context_id},
                        )

                with engine.begin() as connection:
                    connection.execute(text(
                        "UPDATE pool_import_contexts SET "
                        "expires_at = '2026-01-01 00:10:00' "
                        "WHERE id = 'context-card'"
                    ))
                    connection.execute(text(
                        "INSERT INTO pool_import_contexts ("
                        "id, context_token_hash, tenant_id, audience, pool_type, "
                        "ordered_manifest_digest, item_count, created_by, "
                        "device_id, trace_id, created_at, expires_at, "
                        "consumed_at, pool_import_receipt_id) VALUES ("
                        "'context-new', "
                        "'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', "
                        "'tenant-a', 'audience-a', 'mailbox', "
                        "'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', "
                        "1, 'user-a', 'device-a', 'trace-new', "
                        "'2026-01-01 00:00:00', '2026-01-01 00:05:00', "
                        "NULL, NULL)"
                    ))

                command.downgrade(config, PREVIOUS_REVISION)
                with engine.begin() as connection:
                    connection.execute(text("DELETE FROM pool_import_contexts"))
                    remaining = connection.scalar(text(
                        "SELECT COUNT(*) FROM pool_import_contexts"
                    ))
                self.assertEqual(remaining, 0)


if __name__ == "__main__":
    unittest.main()
