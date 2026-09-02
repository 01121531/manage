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
REVISION = "0039_card_claim_delete_guard"
PREVIOUS_REVISION = "0038_card_claim_context_binding"


class CardClaimDeleteGuardMigrationTests(unittest.TestCase):
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
                "CREATE TABLE pool_import_card_identity_claims ("
                "context_id VARCHAR(36) NOT NULL, "
                "position INTEGER NOT NULL, "
                "tenant_id VARCHAR(64) NOT NULL, "
                "provider_ref VARCHAR(160) NOT NULL, "
                "PRIMARY KEY (context_id, position))"
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

    def test_postgresql_offline_sql_installs_exact_delete_guard(self) -> None:
        output = io.StringIO()
        config = Config(str(ROOT / "alembic.ini"), output_buffer=output)
        config.cmd_opts = type("Options", (), {"x": [
            "db_url=postgresql+psycopg://placeholder:placeholder@localhost/db"
        ]})()

        command.upgrade(config, f"{PREVIOUS_REVISION}:{REVISION}", sql=True)

        sql = output.getvalue()
        self.assertIn(
            "CREATE FUNCTION pool_import_card_identity_claims_prevent_delete()",
            sql,
        )
        self.assertIn(
            "CREATE TRIGGER pool_import_card_identity_claims_no_delete",
            sql,
        )
        self.assertIn(
            "BEFORE DELETE ON pool_import_card_identity_claims",
            sql,
        )

    def test_upgrade_blocks_delete_and_downgrade_removes_guard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "card-claim-delete-guard.db"
            with self._database(database) as (engine, config):
                self._create_previous_schema(engine)

                command.upgrade(config, REVISION)

                with self.assertRaises(IntegrityError), engine.begin() as connection:
                    connection.execute(text(
                        "DELETE FROM pool_import_card_identity_claims"
                    ))

                command.downgrade(config, PREVIOUS_REVISION)
                with engine.begin() as connection:
                    connection.execute(text(
                        "DELETE FROM pool_import_card_identity_claims"
                    ))
                    count = connection.scalar(text(
                        "SELECT COUNT(*) FROM pool_import_card_identity_claims"
                    ))
                self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
