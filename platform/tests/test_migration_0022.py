import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0022_card_quarantine"
PREVIOUS_REVISION = "0021_audit_archive_index"


class CardQuarantineMigrationTests(unittest.TestCase):
    def test_upgrade_is_additive_and_downgrade_preserves_disabled_barrier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "card-quarantine.db"
            url = f"sqlite+pysqlite:///{database.as_posix()}"
            engine = create_engine(url)
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "CREATE TABLE cards ("
                        "id VARCHAR(36) NOT NULL PRIMARY KEY, "
                        "is_active BOOLEAN NOT NULL)"
                    )
                )
                connection.execute(
                    text(
                        "INSERT INTO cards (id, is_active) VALUES "
                        "('active-card', 1), ('disabled-card', 0)"
                    )
                )
                connection.execute(
                    text(
                        "CREATE TABLE alembic_version "
                        "(version_num VARCHAR(64) NOT NULL PRIMARY KEY)"
                    )
                )
                connection.execute(
                    text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
                    {"revision": PREVIOUS_REVISION},
                )

            previous = os.environ.get("ALEMBIC_DATABASE_URL")
            os.environ["ALEMBIC_DATABASE_URL"] = url
            try:
                config = Config(str(ROOT / "alembic.ini"))
                command.upgrade(config, REVISION)
                columns = {item["name"]: item for item in inspect(engine).get_columns("cards")}
                self.assertTrue(columns["quarantined_at"]["nullable"])
                self.assertTrue(columns["quarantine_reason_code"]["nullable"])

                with engine.begin() as connection:
                    rows = connection.execute(
                        text(
                            "SELECT id, is_active, quarantined_at, "
                            "quarantine_reason_code FROM cards ORDER BY id"
                        )
                    ).mappings().all()
                    self.assertEqual(
                        [(row["id"], bool(row["is_active"])) for row in rows],
                        [("active-card", True), ("disabled-card", False)],
                    )
                    self.assertTrue(
                        all(
                            row["quarantined_at"] is None
                            and row["quarantine_reason_code"] is None
                            for row in rows
                        )
                    )
                    connection.execute(
                        text("INSERT INTO cards (id, is_active) VALUES ('old-writer', 1)")
                    )
                    connection.execute(
                        text(
                            "UPDATE cards SET is_active = 0, "
                            "quarantined_at = '2026-08-24T00:00:00Z', "
                            "quarantine_reason_code = 'suspected_compromise' "
                            "WHERE id = 'active-card'"
                        )
                    )

                command.downgrade(config, PREVIOUS_REVISION)
                column_names = {
                    item["name"] for item in inspect(engine).get_columns("cards")
                }
                self.assertNotIn("quarantined_at", column_names)
                self.assertNotIn("quarantine_reason_code", column_names)
                with engine.connect() as connection:
                    self.assertEqual(
                        connection.execute(
                            text("SELECT is_active FROM cards WHERE id = 'active-card'")
                        ).scalar_one(),
                        0,
                    )
            finally:
                if previous is None:
                    os.environ.pop("ALEMBIC_DATABASE_URL", None)
                else:
                    os.environ["ALEMBIC_DATABASE_URL"] = previous
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
