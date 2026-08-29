import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0023_card_events"
PREVIOUS_REVISION = "0022_card_quarantine"


class CardEventsMigrationTests(unittest.TestCase):
    def test_upgrade_adds_masked_append_only_history_and_preserves_old_writers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "card-events.db"
            url = f"sqlite+pysqlite:///{database.as_posix()}"
            engine = create_engine(url)
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "CREATE TABLE cards ("
                        "id VARCHAR(36) NOT NULL PRIMARY KEY, "
                        "tenant_id VARCHAR(64) NOT NULL)"
                    )
                )
                connection.execute(
                    text(
                        "CREATE TABLE card_allocations ("
                        "id VARCHAR(36) NOT NULL PRIMARY KEY, "
                        "tenant_id VARCHAR(64) NOT NULL, "
                        "card_id VARCHAR(36) NOT NULL, "
                        "status VARCHAR(32) NOT NULL)"
                    )
                )
                connection.execute(
                    text(
                        "INSERT INTO cards (id, tenant_id) VALUES "
                        "('card-a', 'tenant-a'), ('card-b', 'tenant-b')"
                    )
                )
                connection.execute(
                    text(
                        "INSERT INTO card_allocations (id, tenant_id, card_id, status) "
                        "VALUES ('allocation-a', 'tenant-a', 'card-a', 'active')"
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
                inspector = inspect(engine)
                allocation_columns = {
                    item["name"]: item
                    for item in inspector.get_columns("card_allocations")
                }
                self.assertTrue(allocation_columns["release_reason_code"]["nullable"])
                self.assertIn("card_events", inspector.get_table_names())
                event_columns = {
                    item["name"]: item for item in inspector.get_columns("card_events")
                }
                self.assertEqual(
                    set(event_columns),
                    {
                        "id",
                        "tenant_id",
                        "card_id",
                        "allocation_id",
                        "actor_id",
                        "action",
                        "reason_code",
                        "before_masked",
                        "after_masked",
                        "trace_id",
                        "created_at",
                    },
                )
                self.assertEqual(
                    {item["name"] for item in inspector.get_indexes("card_events")},
                    {
                        "ix_card_events_tenant_created_at_id",
                        "ix_card_events_tenant_card_created_at_id",
                        "ix_card_events_tenant_allocation_created_at_id",
                    },
                )

                with engine.begin() as connection:
                    triggers = {
                        row[0]
                        for row in connection.execute(
                            text(
                                "SELECT name FROM sqlite_master "
                                "WHERE type = 'trigger' AND tbl_name = 'card_events'"
                            )
                        )
                    }
                    self.assertEqual(
                        triggers,
                        {
                            "card_events_no_update",
                            "card_events_no_delete",
                            "card_events_subject_binding",
                        },
                    )
                    connection.execute(
                        text(
                            "INSERT INTO card_allocations "
                            "(id, tenant_id, card_id, status) VALUES "
                            "('old-writer', 'tenant-a', 'card-a', 'active')"
                        )
                    )
                    connection.execute(
                        text(
                            "INSERT INTO card_events "
                            "(id, tenant_id, card_id, allocation_id, actor_id, action, "
                            "reason_code, before_masked, after_masked, trace_id) VALUES "
                            "('event-a', 'tenant-a', 'card-a', 'allocation-a', NULL, "
                            "'allocation.allocated', NULL, '{}', '{}', 'trace-a')"
                        )
                    )

                for statement in (
                    "UPDATE card_events SET action = 'changed' WHERE id = 'event-a'",
                    "DELETE FROM card_events WHERE id = 'event-a'",
                    "INSERT INTO card_events "
                    "(id, tenant_id, card_id, allocation_id, actor_id, action, "
                    "reason_code, before_masked, after_masked, trace_id) VALUES "
                    "('event-cross', 'tenant-a', 'card-b', NULL, NULL, "
                    "'card.created', NULL, '{}', '{}', 'trace-cross')",
                    "INSERT INTO card_events "
                    "(id, tenant_id, card_id, allocation_id, actor_id, action, "
                    "reason_code, before_masked, after_masked, trace_id) VALUES "
                    "('event-mismatch', 'tenant-a', 'card-b', 'allocation-a', NULL, "
                    "'allocation.allocated', NULL, '{}', '{}', 'trace-mismatch')",
                ):
                    with self.assertRaises(IntegrityError):
                        with engine.begin() as connection:
                            connection.execute(text(statement))

                command.downgrade(config, PREVIOUS_REVISION)
                self.assertNotIn("card_events", inspect(engine).get_table_names())
                self.assertNotIn(
                    "release_reason_code",
                    {
                        item["name"]
                        for item in inspect(engine).get_columns("card_allocations")
                    },
                )
                with engine.connect() as connection:
                    self.assertEqual(
                        connection.execute(
                            text("SELECT COUNT(*) FROM card_allocations")
                        ).scalar_one(),
                        2,
                    )
            finally:
                if previous is None:
                    os.environ.pop("ALEMBIC_DATABASE_URL", None)
                else:
                    os.environ["ALEMBIC_DATABASE_URL"] = previous
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
