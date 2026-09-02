import io
import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0037_pool_import_card_identity_claims"
PREVIOUS_REVISION = "0036_pool_import_contexts"


class PoolImportCardIdentityClaimMigrationTests(unittest.TestCase):
    def test_postgresql_offline_sql_is_expand_only(self) -> None:
        output = io.StringIO()
        config = Config(str(ROOT / "alembic.ini"), output_buffer=output)
        config.cmd_opts = type("Options", (), {"x": [
            "db_url=postgresql+psycopg://placeholder:placeholder@localhost/db"
        ]})()
        command.upgrade(config, f"{PREVIOUS_REVISION}:{REVISION}", sql=True)
        sql = output.getvalue()
        self.assertIn("CREATE TABLE pool_import_card_identity_claims", sql)
        self.assertIn(
            "CREATE INDEX ix_pool_import_card_identity_claims_tenant_id", sql
        )
        self.assertNotIn("DROP TABLE", sql)
        self.assertNotIn("ALTER TABLE", sql)

    def test_upgrade_adds_secret_free_identity_claim_table(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "pool-import-card-identity-claim.db"
            url = f"sqlite+pysqlite:///{database.as_posix()}"
            previous = os.environ.get("ALEMBIC_DATABASE_URL")
            os.environ["ALEMBIC_DATABASE_URL"] = url
            engine = create_engine(url)
            try:
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
                        "id VARCHAR(36) NOT NULL PRIMARY KEY)"
                    ))
                config = Config(str(ROOT / "alembic.ini"))
                command.upgrade(config, REVISION)
                inspector = inspect(engine)
                columns = {
                    column["name"]: column
                    for column in inspector.get_columns(
                        "pool_import_card_identity_claims"
                    )
                }
                self.assertEqual(set(columns), {
                    "context_id", "position", "tenant_id", "provider_ref"
                })
                self.assertTrue(all(not column["nullable"] for column in columns.values()))
                self.assertEqual(
                    inspector.get_pk_constraint(
                        "pool_import_card_identity_claims"
                    )["constrained_columns"],
                    ["context_id", "position"],
                )
                uniques = {
                    item["name"] for item in inspector.get_unique_constraints(
                        "pool_import_card_identity_claims"
                    )
                }
                self.assertEqual(uniques, {
                    "uq_pool_import_card_identity_claims_tenant_provider"
                })
            finally:
                if previous is None:
                    os.environ.pop("ALEMBIC_DATABASE_URL", None)
                else:
                    os.environ["ALEMBIC_DATABASE_URL"] = previous
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
