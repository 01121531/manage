import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0017_mail_token_hash_unique"
PREVIOUS_REVISION = "0016_device_last_seen"
CONSTRAINT = "uq_mail_sessions_session_token_hash"


class MailSessionTokenHashMigrationTests(unittest.TestCase):
    def _database(self, directory: str, *, duplicate: bool = False):
        database = Path(directory) / "mail-token-unique.db"
        url = f"sqlite+pysqlite:///{database.as_posix()}"
        engine = create_engine(url)
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE mail_sessions ("
                    "id VARCHAR(36) PRIMARY KEY, "
                    "session_token_hash VARCHAR(64) NOT NULL)"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO mail_sessions (id, session_token_hash) "
                    "VALUES ('session-1', :token_hash)"
                ),
                {"token_hash": "a" * 64},
            )
            if duplicate:
                connection.execute(
                    text(
                        "INSERT INTO mail_sessions (id, session_token_hash) "
                        "VALUES ('session-2', :token_hash)"
                    ),
                    {"token_hash": "a" * 64},
                )
            connection.execute(
                text(
                    "CREATE TABLE alembic_version "
                    "(version_num VARCHAR(64) NOT NULL PRIMARY KEY)"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO alembic_version (version_num) VALUES (:revision)"
                ),
                {"revision": PREVIOUS_REVISION},
            )
        return engine, url

    def _with_url(self, url: str):
        previous = os.environ.get("ALEMBIC_DATABASE_URL")
        os.environ["ALEMBIC_DATABASE_URL"] = url
        return previous

    @staticmethod
    def _restore_url(previous: str | None) -> None:
        if previous is None:
            os.environ.pop("ALEMBIC_DATABASE_URL", None)
        else:
            os.environ["ALEMBIC_DATABASE_URL"] = previous

    def test_unique_data_upgrades_and_downgrades(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine, url = self._database(directory)
            previous = self._with_url(url)
            try:
                config = Config(str(ROOT / "alembic.ini"))
                command.upgrade(config, REVISION)
                constraints = {
                    item["name"]
                    for item in inspect(engine).get_unique_constraints("mail_sessions")
                }
                self.assertIn(CONSTRAINT, constraints)
                with engine.connect() as connection:
                    self.assertEqual(
                        connection.execute(
                            text("SELECT version_num FROM alembic_version")
                        ).scalar_one(),
                        REVISION,
                    )
                command.downgrade(config, PREVIOUS_REVISION)
                constraints = {
                    item["name"]
                    for item in inspect(engine).get_unique_constraints("mail_sessions")
                }
                self.assertNotIn(CONSTRAINT, constraints)
            finally:
                self._restore_url(previous)
                engine.dispose()

    def test_duplicate_history_fails_before_schema_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine, url = self._database(directory, duplicate=True)
            previous = self._with_url(url)
            try:
                config = Config(str(ROOT / "alembic.ini"))
                with self.assertRaisesRegex(
                    RuntimeError, "Duplicate mail-session token hashes"
                ):
                    command.upgrade(config, REVISION)
                self.assertEqual(
                    inspect(engine).get_unique_constraints("mail_sessions"), []
                )
                with engine.connect() as connection:
                    self.assertEqual(
                        connection.execute(
                            text("SELECT version_num FROM alembic_version")
                        ).scalar_one(),
                        PREVIOUS_REVISION,
                    )
            finally:
                self._restore_url(previous)
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
