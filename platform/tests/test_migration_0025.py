import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0025_oidc_session_revocations"
PREVIOUS_REVISION = "0024_schema_compatibility"


class OidcSessionRevocationMigrationTests(unittest.TestCase):
    def test_upgrade_adds_nullable_session_denylist_without_raising_floor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "oidc-session-revocations.db"
            url = f"sqlite+pysqlite:///{database.as_posix()}"
            engine = create_engine(url)
            with engine.begin() as connection:
                connection.execute(text("CREATE TABLE users (id VARCHAR(36) PRIMARY KEY)"))
                connection.execute(text("CREATE TABLE devices (id VARCHAR(36) PRIMARY KEY)"))
                connection.execute(
                    text(
                        "CREATE TABLE platform_schema_compatibility ("
                        "singleton_id INTEGER NOT NULL PRIMARY KEY, "
                        "minimum_app_revision VARCHAR(255) NOT NULL)"
                    )
                )
                connection.execute(
                    text(
                        "INSERT INTO platform_schema_compatibility "
                        "(singleton_id, minimum_app_revision) VALUES (1, :revision)"
                    ),
                    {"revision": PREVIOUS_REVISION},
                )
                connection.execute(
                    text(
                        "CREATE TABLE alembic_version "
                        "(version_num VARCHAR(255) NOT NULL PRIMARY KEY)"
                    )
                )
                connection.execute(
                    text("INSERT INTO alembic_version(version_num) VALUES (:revision)"),
                    {"revision": PREVIOUS_REVISION},
                )

            previous = os.environ.get("ALEMBIC_DATABASE_URL")
            os.environ["ALEMBIC_DATABASE_URL"] = url
            try:
                config = Config(str(ROOT / "alembic.ini"))
                command.upgrade(config, REVISION)
                inspector = inspect(engine)
                self.assertIn("revoked_oidc_sessions", inspector.get_table_names())
                columns = {
                    item["name"]: item
                    for item in inspector.get_columns("revoked_oidc_sessions")
                }
                self.assertEqual(
                    set(columns),
                    {
                        "session_hash",
                        "tenant_id",
                        "user_id",
                        "device_id",
                        "revoked_at",
                        "expires_at",
                        "reason",
                    },
                )
                self.assertEqual(
                    {name: column["nullable"] for name, column in columns.items()},
                    {
                        "session_hash": False,
                        "tenant_id": False,
                        "user_id": False,
                        "device_id": False,
                        "revoked_at": False,
                        "expires_at": True,
                        "reason": False,
                    },
                )
                self.assertEqual(
                    inspector.get_pk_constraint("revoked_oidc_sessions")[
                        "constrained_columns"
                    ],
                    ["session_hash"],
                )
                indexes = {
                    item["name"]: item
                    for item in inspector.get_indexes("revoked_oidc_sessions")
                }
                self.assertEqual(
                    set(indexes),
                    {
                        "ix_revoked_oidc_sessions_tenant_id",
                        "ix_revoked_oidc_sessions_user_id",
                        "ix_revoked_oidc_sessions_device_id",
                        "ix_revoked_oidc_sessions_expires_at",
                    },
                )
                self.assertTrue(
                    all(not bool(index["unique"]) for index in indexes.values())
                )
                foreign_keys = {
                    tuple(item["constrained_columns"]): item["referred_table"]
                    for item in inspector.get_foreign_keys("revoked_oidc_sessions")
                }
                self.assertEqual(
                    foreign_keys,
                    {("user_id",): "users", ("device_id",): "devices"},
                )
                with engine.connect() as connection:
                    floor = connection.execute(
                        text(
                            "SELECT minimum_app_revision "
                            "FROM platform_schema_compatibility WHERE singleton_id = 1"
                        )
                    ).scalar_one()
                    database_head = connection.execute(
                        text("SELECT version_num FROM alembic_version")
                    ).scalar_one()
                self.assertEqual(floor, PREVIOUS_REVISION)
                self.assertEqual(database_head, REVISION)

                command.downgrade(config, PREVIOUS_REVISION)
                downgraded = inspect(engine)
                self.assertNotIn("revoked_oidc_sessions", downgraded.get_table_names())
                self.assertIn(
                    "platform_schema_compatibility", downgraded.get_table_names()
                )
                with engine.connect() as connection:
                    self.assertEqual(
                        connection.execute(
                            text(
                                "SELECT minimum_app_revision "
                                "FROM platform_schema_compatibility "
                                "WHERE singleton_id = 1"
                            )
                        ).scalar_one(),
                        PREVIOUS_REVISION,
                    )
                    self.assertEqual(
                        connection.execute(
                            text("SELECT version_num FROM alembic_version")
                        ).scalar_one(),
                        PREVIOUS_REVISION,
                    )
            finally:
                if previous is None:
                    os.environ.pop("ALEMBIC_DATABASE_URL", None)
                else:
                    os.environ["ALEMBIC_DATABASE_URL"] = previous
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
