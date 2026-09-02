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
REVISION = "0044_pool_context_consumption_terminal"
PREVIOUS_REVISION = "0043_secure_consumption_lock"


class PoolContextConsumptionTerminalMigrationTests(unittest.TestCase):
    @staticmethod
    def _create_previous_schema(engine, *, invalid_history: str | None = None) -> None:
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
                "request_digest VARCHAR(64) NOT NULL, "
                "item_count INTEGER NOT NULL, "
                "created_by VARCHAR(36) NOT NULL, "
                "device_id VARCHAR(36) NOT NULL)"
            ))
            connection.execute(text(
                "CREATE TABLE secure_pool_import_consumptions ("
                "receipt_id VARCHAR(36) NOT NULL PRIMARY KEY, "
                "pool_import_receipt_id VARCHAR(36) NOT NULL UNIQUE)"
            ))
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
                "'context-a', 'hash-a', 'tenant-a', 'audience-a', 'card', "
                "'digest-a', 1, 'user-a', 'device-a', 'trace-a', "
                "'2026-01-01 00:00:00', '2026-01-01 00:10:00', NULL, NULL)"
            ))
            connection.execute(text(
                "INSERT INTO pool_import_receipts ("
                "id, tenant_id, pool_type, request_digest, item_count, "
                "created_by, device_id) VALUES "
                "('local-good', 'tenant-a', 'card', 'digest-a', 1, "
                "'user-a', 'device-a'), "
                "('local-missing', 'tenant-a', 'card', 'digest-a', 1, "
                "'user-a', 'device-a'), "
                "('local-preconsumed', 'tenant-a', 'mailbox', 'digest-b', 1, "
                "'user-a', 'device-a')"
            ))
            connection.execute(text(
                "INSERT INTO secure_pool_import_consumptions "
                "(receipt_id, pool_import_receipt_id) VALUES "
                "('context-a', 'local-good'), "
                "('context-b', 'local-preconsumed')"
            ))
            if invalid_history == "partial":
                connection.execute(text(
                    "UPDATE pool_import_contexts SET "
                    "consumed_at = '2026-01-01 00:01:00' "
                    "WHERE id = 'context-a'"
                ))
            elif invalid_history == "unbound":
                connection.execute(text(
                    "UPDATE pool_import_contexts SET "
                    "consumed_at = '2026-01-01 00:01:00', "
                    "pool_import_receipt_id = 'local-missing' "
                    "WHERE id = 'context-a'"
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

    def test_postgresql_offline_sql_preflights_and_installs_guards(self) -> None:
        output = io.StringIO()
        config = Config(str(ROOT / "alembic.ini"), output_buffer=output)
        config.cmd_opts = type("Options", (), {"x": [
            "db_url=postgresql+psycopg://placeholder:placeholder@localhost/db"
        ]})()

        command.upgrade(config, f"{PREVIOUS_REVISION}:{REVISION}", sql=True)

        sql = " ".join(output.getvalue().split())
        self.assertIn("pool_context_consumption_lifecycle_valid", sql)
        self.assertIn(
            "CREATE FUNCTION pool_import_contexts_validate_consumption_lifecycle()",
            sql,
        )
        self.assertIn(
            "CREATE TRIGGER pool_import_contexts_consumption_lifecycle BEFORE "
            "INSERT OR UPDATE OF expires_at, consumed_at, "
            "pool_import_receipt_id ON pool_import_contexts",
            sql,
        )

    def test_invalid_existing_lifecycle_aborts_before_trigger_installation(
        self,
    ) -> None:
        for invalid_history in ("partial", "unbound"):
            with self.subTest(invalid_history=invalid_history), tempfile.TemporaryDirectory() as directory:
                database = Path(directory) / "invalid-context-lifecycle.db"
                with self._database(database) as (engine, config):
                    self._create_previous_schema(
                        engine,
                        invalid_history=invalid_history,
                    )

                    with self.assertRaises(RuntimeError):
                        command.upgrade(config, REVISION)

                    with engine.connect() as connection:
                        head = connection.scalar(text(
                            "SELECT version_num FROM alembic_version"
                        ))
                        trigger_count = connection.scalar(text(
                            "SELECT COUNT(*) FROM sqlite_master "
                            "WHERE type = 'trigger'"
                        ))
                    self.assertEqual(head, PREVIOUS_REVISION)
                    self.assertEqual(trigger_count, 0)

    def test_consumption_transition_is_exact_one_way_and_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "context-consumption-terminal.db"
            with self._database(database) as (engine, config):
                self._create_previous_schema(engine)
                command.upgrade(config, REVISION)

                with engine.begin() as connection:
                    connection.execute(text(
                        "UPDATE pool_import_contexts SET "
                        "expires_at = '2026-01-01 00:20:00' "
                        "WHERE id = 'context-a'"
                    ))

                invalid_transitions = (
                    "consumed_at = '2026-01-01 00:01:00'",
                    "pool_import_receipt_id = 'local-good'",
                    "consumed_at = '2026-01-01 00:01:00', "
                    "pool_import_receipt_id = 'local-missing'",
                )
                for mutation in invalid_transitions:
                    with self.subTest(mutation=mutation), self.assertRaises(
                        IntegrityError
                    ), engine.begin() as connection:
                        connection.execute(text(
                            "UPDATE pool_import_contexts SET " + mutation +
                            " WHERE id = 'context-a'"
                        ))

                with engine.begin() as connection:
                    connection.execute(text(
                        "UPDATE pool_import_contexts SET "
                        "consumed_at = '2026-01-01 00:01:00', "
                        "pool_import_receipt_id = 'local-good' "
                        "WHERE id = 'context-a'"
                    ))

                terminal_mutations = (
                    "expires_at = '2026-01-01 00:30:00'",
                    "consumed_at = '2026-01-01 00:02:00'",
                    "pool_import_receipt_id = 'local-missing'",
                    "consumed_at = NULL, pool_import_receipt_id = NULL",
                )
                for mutation in terminal_mutations:
                    with self.subTest(mutation=mutation), self.assertRaises(
                        IntegrityError
                    ), engine.begin() as connection:
                        connection.execute(text(
                            "UPDATE pool_import_contexts SET " + mutation +
                            " WHERE id = 'context-a'"
                        ))

                with self.assertRaises(IntegrityError), engine.begin() as connection:
                    connection.execute(text(
                        "INSERT INTO pool_import_contexts ("
                        "id, context_token_hash, tenant_id, audience, pool_type, "
                        "ordered_manifest_digest, item_count, created_by, "
                        "device_id, trace_id, created_at, expires_at, "
                        "consumed_at, pool_import_receipt_id) VALUES ("
                        "'context-b', 'hash-b', 'tenant-a', 'audience-a', "
                        "'mailbox', 'digest-b', 1, 'user-a', 'device-a', "
                        "'trace-b', '2026-01-01 00:00:00', "
                        "'2026-01-01 00:10:00', '2026-01-01 00:01:00', "
                        "'local-preconsumed')"
                    ))

                with engine.begin() as connection:
                    connection.execute(text(
                        "INSERT INTO pool_import_contexts ("
                        "id, context_token_hash, tenant_id, audience, pool_type, "
                        "ordered_manifest_digest, item_count, created_by, "
                        "device_id, trace_id, created_at, expires_at, "
                        "consumed_at, pool_import_receipt_id) VALUES ("
                        "'context-c', 'hash-c', 'tenant-a', 'audience-a', "
                        "'mailbox', 'digest-c', 1, 'user-a', 'device-a', "
                        "'trace-c', '2026-01-01 00:00:00', "
                        "'2026-01-01 00:10:00', NULL, NULL)"
                    ))

                command.downgrade(config, PREVIOUS_REVISION)
                with engine.begin() as connection:
                    connection.execute(text(
                        "UPDATE pool_import_contexts SET consumed_at = NULL, "
                        "pool_import_receipt_id = NULL WHERE id = 'context-a'"
                    ))
                    lifecycle = connection.execute(text(
                        "SELECT consumed_at, pool_import_receipt_id "
                        "FROM pool_import_contexts WHERE id = 'context-a'"
                    )).one()
                self.assertEqual(tuple(lifecycle), (None, None))


if __name__ == "__main__":
    unittest.main()
