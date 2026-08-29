import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0018_access_token_revocations"
PREVIOUS_REVISION = "0017_mail_token_hash_unique"


class AccessTokenRevocationMigrationTests(unittest.TestCase):
    def test_upgrade_creates_denylist_and_downgrade_removes_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "access-token-revocations.db"
            url = f"sqlite+pysqlite:///{database.as_posix()}"
            engine = create_engine(url)
            with engine.begin() as connection:
                connection.execute(text("CREATE TABLE users (id VARCHAR(36) PRIMARY KEY)"))
                connection.execute(text("CREATE TABLE devices (id VARCHAR(36) PRIMARY KEY)"))
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

            previous = os.environ.get("ALEMBIC_DATABASE_URL")
            os.environ["ALEMBIC_DATABASE_URL"] = url
            try:
                config = Config(str(ROOT / "alembic.ini"))
                command.upgrade(config, REVISION)
                inspector = inspect(engine)
                self.assertIn("revoked_access_tokens", inspector.get_table_names())
                columns = {
                    item["name"]: item
                    for item in inspector.get_columns("revoked_access_tokens")
                }
                self.assertFalse(columns["token_hash"]["nullable"])
                self.assertFalse(columns["expires_at"]["nullable"])
                indexes = {
                    item["name"]
                    for item in inspector.get_indexes("revoked_access_tokens")
                }
                self.assertIn("ix_revoked_access_tokens_expires_at", indexes)

                command.downgrade(config, PREVIOUS_REVISION)
                self.assertNotIn(
                    "revoked_access_tokens", inspect(engine).get_table_names()
                )
            finally:
                if previous is None:
                    os.environ.pop("ALEMBIC_DATABASE_URL", None)
                else:
                    os.environ["ALEMBIC_DATABASE_URL"] = previous
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
