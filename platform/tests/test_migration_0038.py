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
REVISION = "0038_card_claim_context_binding"
PREVIOUS_REVISION = "0037_pool_import_card_identity_claims"


class CardClaimContextBindingMigrationTests(unittest.TestCase):
    @staticmethod
    def _create_previous_schema(engine, *, claim_tenant: str = "tenant-a") -> None:
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
                "tenant_id VARCHAR(64) NOT NULL, "
                "pool_type VARCHAR(16) NOT NULL)"
            ))
            connection.execute(text(
                "CREATE TABLE pool_import_card_identity_claims ("
                "context_id VARCHAR(36) NOT NULL, "
                "position INTEGER NOT NULL, "
                "tenant_id VARCHAR(64) NOT NULL, "
                "provider_ref VARCHAR(160) NOT NULL, "
                "PRIMARY KEY (context_id, position))"
            ))
            connection.execute(text(
                "INSERT INTO pool_import_contexts "
                "(id, tenant_id, pool_type) VALUES "
                "('context-a', 'tenant-a', 'card')"
            ))
            connection.execute(
                text(
                    "INSERT INTO pool_import_card_identity_claims "
                    "(context_id, position, tenant_id, provider_ref) VALUES "
                    "('context-a', 0, :tenant_id, 'provider-a')"
                ),
                {"tenant_id": claim_tenant},
            )

    @contextmanager
    def _upgrade(self, database: Path):
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

    def test_postgresql_offline_sql_preflights_and_installs_both_guards(
        self,
    ) -> None:
        output = io.StringIO()
        config = Config(str(ROOT / "alembic.ini"), output_buffer=output)
        config.cmd_opts = type("Options", (), {"x": [
            "db_url=postgresql+psycopg://placeholder:placeholder@localhost/db"
        ]})()

        command.upgrade(config, f"{PREVIOUS_REVISION}:{REVISION}", sql=True)

        sql = output.getvalue()
        self.assertIn("card_claim_context_bindings_valid", sql)
        self.assertIn("FOR KEY SHARE", sql)
        self.assertIn(
            "CREATE TRIGGER pool_import_card_identity_claims_context_binding",
            sql,
        )
        self.assertIn(
            "CREATE TRIGGER pool_import_contexts_card_claim_binding",
            sql,
        )

    def test_upgrade_blocks_claim_and_context_tenant_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "card-claim-context-binding.db"
            with self._upgrade(database) as (engine, config):
                self._create_previous_schema(engine)

                command.upgrade(config, REVISION)

                with engine.connect() as connection:
                    trigger_names = set(connection.scalars(text(
                        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                    )))
                self.assertEqual(trigger_names, {
                    "pool_import_card_identity_claims_context_binding_insert",
                    "pool_import_card_identity_claims_context_binding_update",
                    "pool_import_contexts_card_claim_binding",
                })
                invalid_statements = (
                    "UPDATE pool_import_card_identity_claims "
                    "SET tenant_id = 'tenant-b' WHERE context_id = 'context-a'",
                    "INSERT INTO pool_import_card_identity_claims "
                    "(context_id, position, tenant_id, provider_ref) VALUES "
                    "('context-a', 1, 'tenant-b', 'provider-b')",
                    "UPDATE pool_import_contexts SET tenant_id = 'tenant-b' "
                    "WHERE id = 'context-a'",
                    "UPDATE pool_import_contexts SET pool_type = 'mailbox' "
                    "WHERE id = 'context-a'",
                )
                for statement in invalid_statements:
                    with self.subTest(statement=statement), self.assertRaises(
                        IntegrityError
                    ), engine.begin() as connection:
                        connection.execute(text(statement))

                with engine.begin() as connection:
                    connection.execute(text(
                        "INSERT INTO pool_import_card_identity_claims "
                        "(context_id, position, tenant_id, provider_ref) VALUES "
                        "('context-a', 1, 'tenant-a', 'provider-b')"
                    ))

    def test_invalid_existing_binding_aborts_before_trigger_installation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "invalid-card-claim-binding.db"
            with self._upgrade(database) as (engine, config):
                self._create_previous_schema(engine, claim_tenant="tenant-b")

                with self.assertRaises(RuntimeError):
                    command.upgrade(config, REVISION)

                with engine.connect() as connection:
                    head = connection.scalar(text(
                        "SELECT version_num FROM alembic_version"
                    ))
                    trigger_count = connection.scalar(text(
                        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger'"
                    ))
                self.assertEqual(head, PREVIOUS_REVISION)
                self.assertEqual(trigger_count, 0)


if __name__ == "__main__":
    unittest.main()
