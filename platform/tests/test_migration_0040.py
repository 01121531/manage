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
REVISION = "0040_card_claim_identity_immutable"
PREVIOUS_REVISION = "0039_card_claim_delete_guard"


class CardClaimIdentityImmutableMigrationTests(unittest.TestCase):
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
                "('context-a', 'tenant-a', 'card'), "
                "('context-replacement', 'tenant-a', 'card'), "
                "('context-tenant-b', 'tenant-b', 'card')"
            ))
            connection.execute(text(
                "INSERT INTO pool_import_card_identity_claims "
                "(context_id, position, tenant_id, provider_ref) VALUES "
                "('context-a', 0, 'tenant-a', 'provider-a')"
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

        sql = output.getvalue()
        self.assertIn(
            "CREATE FUNCTION pool_import_card_identity_claims_prevent_identity_change()",
            sql,
        )
        self.assertIn(
            "CREATE TRIGGER pool_import_card_identity_claims_identity_immutable",
            sql,
        )
        self.assertIn(
            "BEFORE UPDATE OF tenant_id, provider_ref ON "
            "pool_import_card_identity_claims",
            " ".join(sql.split()),
        )

    def test_identity_is_immutable_while_reclamation_fields_remain_transferable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "card-claim-identity-immutable.db"
            with self._database(database) as (engine, config):
                self._create_previous_schema(engine)

                command.upgrade(config, REVISION)

                with self.assertRaises(IntegrityError), engine.begin() as connection:
                    connection.execute(text(
                        "UPDATE pool_import_card_identity_claims "
                        "SET provider_ref = 'provider-rewritten' "
                        "WHERE provider_ref = 'provider-a'"
                    ))
                with self.assertRaises(IntegrityError), engine.begin() as connection:
                    connection.execute(text(
                        "UPDATE pool_import_card_identity_claims "
                        "SET context_id = 'context-tenant-b', tenant_id = 'tenant-b' "
                        "WHERE provider_ref = 'provider-a'"
                    ))
                with engine.begin() as connection:
                    connection.execute(text(
                        "UPDATE pool_import_card_identity_claims "
                        "SET context_id = 'context-replacement', position = 3 "
                        "WHERE provider_ref = 'provider-a'"
                    ))
                    identity = connection.execute(text(
                        "SELECT context_id, position, tenant_id, provider_ref "
                        "FROM pool_import_card_identity_claims "
                        "WHERE provider_ref = 'provider-a'"
                    )).one()
                self.assertEqual(
                    identity,
                    ("context-replacement", 3, "tenant-a", "provider-a"),
                )

                command.downgrade(config, PREVIOUS_REVISION)
                with engine.begin() as connection:
                    connection.execute(text(
                        "UPDATE pool_import_card_identity_claims "
                        "SET provider_ref = 'provider-rewritten' "
                        "WHERE provider_ref = 'provider-a'"
                    ))
                    provider_ref = connection.scalar(text(
                        "SELECT provider_ref "
                        "FROM pool_import_card_identity_claims"
                    ))
                self.assertEqual(provider_ref, "provider-rewritten")


if __name__ == "__main__":
    unittest.main()
