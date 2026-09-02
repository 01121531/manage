import io
import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0041_card_claim_mutation_ledger"
PREVIOUS_REVISION = "0040_card_claim_identity_immutable"


class CardClaimMutationLedgerMigrationTests(unittest.TestCase):
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
                "tenant_id VARCHAR(64) NOT NULL, "
                "pool_type VARCHAR(16) NOT NULL, "
                "trace_id VARCHAR(36) NOT NULL)"
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
                "(id, tenant_id, pool_type, trace_id) VALUES "
                "('context-old', 'tenant-a', 'card', 'trace-old'), "
                "('context-new', 'tenant-a', 'card', 'trace-new')"
            ))
            connection.execute(text(
                "INSERT INTO pool_import_card_identity_claims "
                "(context_id, position, tenant_id, provider_ref) VALUES "
                "('context-old', 0, 'tenant-a', 'provider-secret-free-id')"
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

    def test_postgresql_offline_sql_installs_exact_append_only_ledger(self) -> None:
        output = io.StringIO()
        config = Config(str(ROOT / "alembic.ini"), output_buffer=output)
        config.cmd_opts = type("Options", (), {"x": [
            "db_url=postgresql+psycopg://placeholder:placeholder@localhost/db"
        ]})()

        command.upgrade(config, f"{PREVIOUS_REVISION}:{REVISION}", sql=True)

        sql = " ".join(output.getvalue().split())
        self.assertIn("CREATE TABLE pool_import_card_claim_mutations", sql)
        self.assertIn(
            "CREATE FUNCTION pool_import_card_claim_mutations_record()",
            sql,
        )
        self.assertIn(
            "CREATE TRIGGER pool_import_card_claim_mutations_record "
            "AFTER UPDATE OF context_id, position ON "
            "pool_import_card_identity_claims",
            sql,
        )
        self.assertIn(
            "CREATE TRIGGER pool_import_card_claim_mutations_no_update "
            "BEFORE UPDATE ON pool_import_card_claim_mutations",
            sql,
        )
        self.assertIn(
            "CREATE TRIGGER pool_import_card_claim_mutations_no_delete "
            "BEFORE DELETE ON pool_import_card_claim_mutations",
            sql,
        )

    def test_context_or_position_change_creates_secret_free_append_only_row(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "card-claim-mutation-ledger.db"
            with self._database(database) as (engine, config):
                self._create_previous_schema(engine)

                command.upgrade(config, REVISION)

                with engine.begin() as connection:
                    connection.execute(text(
                        "UPDATE pool_import_card_identity_claims "
                        "SET context_id = 'context-new', position = 7 "
                        "WHERE provider_ref = 'provider-secret-free-id'"
                    ))
                    mutation = connection.execute(text(
                        "SELECT tenant_id, source_context_id, source_position, "
                        "destination_context_id, destination_position, "
                        "destination_trace_id FROM "
                        "pool_import_card_claim_mutations"
                    )).one()
                self.assertEqual(
                    mutation,
                    (
                        "tenant-a",
                        "context-old",
                        0,
                        "context-new",
                        7,
                        "trace-new",
                    ),
                )
                columns = {
                    column["name"]
                    for column in inspect(engine).get_columns(
                        "pool_import_card_claim_mutations"
                    )
                }
                self.assertNotIn("provider_ref", columns)
                self.assertNotIn("card_secret", columns)

                with self.assertRaises(IntegrityError), engine.begin() as connection:
                    connection.execute(text(
                        "UPDATE pool_import_card_claim_mutations "
                        "SET source_position = 8"
                    ))
                with self.assertRaises(IntegrityError), engine.begin() as connection:
                    connection.execute(text(
                        "DELETE FROM pool_import_card_claim_mutations"
                    ))

                command.downgrade(config, PREVIOUS_REVISION)
                with engine.begin() as connection:
                    connection.execute(text(
                        "UPDATE pool_import_card_identity_claims "
                        "SET context_id = 'context-old', position = 0 "
                        "WHERE provider_ref = 'provider-secret-free-id'"
                    ))
                self.assertNotIn(
                    "pool_import_card_claim_mutations",
                    inspect(engine).get_table_names(),
                )


if __name__ == "__main__":
    unittest.main()
