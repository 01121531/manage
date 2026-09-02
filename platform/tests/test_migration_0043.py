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
REVISION = "0043_secure_consumption_lock"
PREVIOUS_REVISION = "0042_pool_context_identity_lock"

MUTATIONS = {
    "receipt_id": "'receipt-rewritten'",
    "pool_import_receipt_id": "'local-b'",
    "issued_at": "'2026-01-01 00:01:00'",
    "expires_at": "'2026-01-01 00:20:00'",
    "key_version": "2",
    "consumed_at": "'2026-01-01 00:02:00'",
}


class SecureConsumptionLockMigrationTests(unittest.TestCase):
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
                "id VARCHAR(36) NOT NULL PRIMARY KEY)"
            ))
            connection.execute(text(
                "CREATE TABLE secure_pool_import_consumptions ("
                "receipt_id VARCHAR(36) NOT NULL PRIMARY KEY, "
                "pool_import_receipt_id VARCHAR(36) NOT NULL UNIQUE, "
                "issued_at DATETIME NOT NULL, "
                "expires_at DATETIME NOT NULL, "
                "key_version INTEGER NOT NULL, "
                "consumed_at DATETIME NOT NULL, "
                "FOREIGN KEY(pool_import_receipt_id) "
                "REFERENCES pool_import_receipts(id))"
            ))
            connection.execute(text(
                "INSERT INTO pool_import_receipts (id) "
                "VALUES ('local-a'), ('local-b')"
            ))
            connection.execute(text(
                "INSERT INTO secure_pool_import_consumptions ("
                "receipt_id, pool_import_receipt_id, issued_at, expires_at, "
                "key_version, consumed_at) VALUES ("
                "'receipt-a', 'local-a', '2026-01-01 00:00:00', "
                "'2026-01-01 00:10:00', 1, '2026-01-01 00:00:30')"
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

    def test_postgresql_offline_sql_installs_exact_append_only_guard(self) -> None:
        output = io.StringIO()
        config = Config(str(ROOT / "alembic.ini"), output_buffer=output)
        config.cmd_opts = type("Options", (), {"x": [
            "db_url=postgresql+psycopg://placeholder:placeholder@localhost/db"
        ]})()

        command.upgrade(config, f"{PREVIOUS_REVISION}:{REVISION}", sql=True)

        sql = " ".join(output.getvalue().split())
        self.assertIn(
            "CREATE FUNCTION secure_pool_import_consumptions_prevent_mutation()",
            sql,
        )
        self.assertIn(
            "CREATE TRIGGER secure_pool_import_consumptions_append_only BEFORE "
            "UPDATE OR DELETE ON secure_pool_import_consumptions",
            sql,
        )

    def test_consumption_is_append_only_and_downgrade_removes_guard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "secure-consumption-lock.db"
            with self._database(database) as (engine, config):
                self._create_previous_schema(engine)

                command.upgrade(config, REVISION)

                for column, replacement in MUTATIONS.items():
                    statement = (
                        "UPDATE secure_pool_import_consumptions SET "
                        f"{column} = {replacement} WHERE receipt_id = 'receipt-a'"
                    )
                    with self.subTest(column=column), self.assertRaises(
                        IntegrityError
                    ), engine.begin() as connection:
                        connection.execute(text(statement))
                with self.assertRaises(IntegrityError), engine.begin() as connection:
                    connection.execute(text(
                        "DELETE FROM secure_pool_import_consumptions "
                        "WHERE receipt_id = 'receipt-a'"
                    ))

                with engine.begin() as connection:
                    connection.execute(text(
                        "INSERT INTO secure_pool_import_consumptions ("
                        "receipt_id, pool_import_receipt_id, issued_at, "
                        "expires_at, key_version, consumed_at) VALUES ("
                        "'receipt-b', 'local-b', '2026-01-01 00:00:00', "
                        "'2026-01-01 00:10:00', 1, "
                        "'2026-01-01 00:00:30')"
                    ))

                command.downgrade(config, PREVIOUS_REVISION)
                with engine.begin() as connection:
                    connection.execute(text(
                        "UPDATE secure_pool_import_consumptions SET "
                        "key_version = 2 WHERE receipt_id = 'receipt-a'"
                    ))
                    connection.execute(text(
                        "DELETE FROM secure_pool_import_consumptions "
                        "WHERE receipt_id = 'receipt-a'"
                    ))
                    remaining = connection.scalar(text(
                        "SELECT COUNT(*) FROM secure_pool_import_consumptions"
                    ))
                self.assertEqual(remaining, 1)


if __name__ == "__main__":
    unittest.main()
