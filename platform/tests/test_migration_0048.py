import io
import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0048_pool_import_receipt_completion_guard"
PREVIOUS_REVISION = "0047_pool_import_receipt_context_binding"


class PoolImportReceiptCompletionGuardMigrationTests(unittest.TestCase):
    @contextmanager
    def _sqlite_database(self, database: Path):
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

    def test_postgresql_offline_sql_installs_deferred_completion_guard(self) -> None:
        output = io.StringIO()
        config = Config(str(ROOT / "alembic.ini"), output_buffer=output)
        config.cmd_opts = type("Options", (), {"x": [
            "db_url=postgresql+psycopg://placeholder:placeholder@localhost/db"
        ]})()

        command.upgrade(config, f"{PREVIOUS_REVISION}:{REVISION}", sql=True)

        sql = " ".join(output.getvalue().split())
        self.assertIn(
            "CREATE FUNCTION pool_import_receipts_validate_completion()",
            sql,
        )
        self.assertIn(
            "CREATE CONSTRAINT TRIGGER pool_import_receipts_completion_guard "
            "AFTER INSERT ON pool_import_receipts DEFERRABLE INITIALLY DEFERRED",
            sql,
        )
        self.assertIn(
            "JOIN secure_pool_import_consumptions AS secure_consumption",
            sql,
        )
        self.assertIn("bound_context.pool_import_receipt_id = NEW.id", sql)
        self.assertIn("bound_context.consumed_at IS NOT NULL", sql)
        self.assertIn("FOR KEY SHARE OF bound_context, secure_consumption", sql)

    def test_sqlite_revision_is_an_explicit_no_op(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "receipt-completion.db"
            with self._sqlite_database(database) as (engine, config):
                with engine.begin() as connection:
                    connection.execute(text(
                        "CREATE TABLE alembic_version ("
                        "version_num VARCHAR(255) NOT NULL PRIMARY KEY)"
                    ))
                    connection.execute(
                        text("INSERT INTO alembic_version VALUES (:revision)"),
                        {"revision": PREVIOUS_REVISION},
                    )

                command.upgrade(config, REVISION)
                with engine.connect() as connection:
                    self.assertEqual(
                        connection.scalar(text(
                            "SELECT version_num FROM alembic_version"
                        )),
                        REVISION,
                    )

                command.downgrade(config, PREVIOUS_REVISION)


if __name__ == "__main__":
    unittest.main()
