import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0030_mailbox_task_routing"
PREVIOUS_REVISION = "0029_card_replacement"
COMPATIBILITY_FLOOR = "0024_schema_compatibility"


class MailboxTaskRoutingMigrationTests(unittest.TestCase):
    def test_upgrade_backfills_default_route_and_downgrade_removes_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "mailbox-task-routing.db"
            url = f"sqlite+pysqlite:///{database.as_posix()}"
            engine = create_engine(url)
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "CREATE TABLE mailboxes ("
                        "id VARCHAR(36) NOT NULL PRIMARY KEY, "
                        "tenant_id VARCHAR(64) NOT NULL, "
                        "email_masked VARCHAR(320) NOT NULL, "
                        "connector_type VARCHAR(80) NOT NULL, "
                        "secret_ref VARCHAR(512) NOT NULL, "
                        "is_active BOOLEAN NOT NULL)"
                    )
                )
                connection.execute(
                    text(
                        "INSERT INTO mailboxes "
                        "(id, tenant_id, email_masked, connector_type, secret_ref, is_active) "
                        "VALUES ('mailbox-1', 'tenant-a', 'm***@example.test', "
                        "'http', 'vault://mailboxes/one', 1)"
                    )
                )
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
                    {"revision": COMPATIBILITY_FLOOR},
                )
                connection.execute(
                    text(
                        "CREATE TABLE alembic_version "
                        "(version_num VARCHAR(255) NOT NULL PRIMARY KEY)"
                    )
                )
                connection.execute(
                    text(
                        "INSERT INTO alembic_version(version_num) VALUES (:revision)"
                    ),
                    {"revision": PREVIOUS_REVISION},
                )

            previous = os.environ.get("ALEMBIC_DATABASE_URL")
            os.environ["ALEMBIC_DATABASE_URL"] = url
            try:
                config = Config(str(ROOT / "alembic.ini"))
                command.upgrade(config, REVISION)
                columns = {
                    item["name"]: item
                    for item in inspect(engine).get_columns("mailboxes")
                }
                self.assertFalse(columns["task_type"]["nullable"])
                self.assertEqual(columns["task_type"]["type"].length, 80)
                with engine.begin() as connection:
                    self.assertEqual(
                        connection.execute(
                            text("SELECT task_type FROM mailboxes WHERE id='mailbox-1'")
                        ).scalar_one(),
                        "mail_code",
                    )
                    connection.execute(
                        text(
                            "INSERT INTO mailboxes "
                            "(id, tenant_id, email_masked, connector_type, task_type, "
                            "secret_ref, is_active) VALUES "
                            "('mailbox-2', 'tenant-a', 'r***@example.test', 'http', "
                            "'password_reset', 'vault://mailboxes/two', 1)"
                        )
                    )
                    self.assertEqual(
                        connection.execute(
                            text("SELECT task_type FROM mailboxes WHERE id='mailbox-2'")
                        ).scalar_one(),
                        "password_reset",
                    )
                    self.assertEqual(
                        connection.execute(
                            text(
                                "SELECT minimum_app_revision "
                                "FROM platform_schema_compatibility WHERE singleton_id=1"
                            )
                        ).scalar_one(),
                        COMPATIBILITY_FLOOR,
                    )

                command.downgrade(config, PREVIOUS_REVISION)
                self.assertNotIn(
                    "task_type",
                    {
                        item["name"]
                        for item in inspect(engine).get_columns("mailboxes")
                    },
                )
            finally:
                if previous is None:
                    os.environ.pop("ALEMBIC_DATABASE_URL", None)
                else:
                    os.environ["ALEMBIC_DATABASE_URL"] = previous
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
