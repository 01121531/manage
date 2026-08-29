import json
import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0031_card_pool_routing"
PREVIOUS_REVISION = "0030_mailbox_task_routing"


class CardPoolRoutingMigrationTests(unittest.TestCase):
    def test_upgrade_classifies_legacy_rows_and_freezes_legacy_rules(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "card-pool-routing.db"
            url = f"sqlite+pysqlite:///{database.as_posix()}"
            previous = os.environ.get("ALEMBIC_DATABASE_URL")
            os.environ["ALEMBIC_DATABASE_URL"] = url
            engine = create_engine(url)
            try:
                with engine.begin() as connection:
                    connection.execute(
                        text(
                            "CREATE TABLE cards (id VARCHAR(36) PRIMARY KEY, "
                            "tenant_id VARCHAR(64) NOT NULL, provider_ref VARCHAR(160) NOT NULL, "
                            "brand VARCHAR(40) NOT NULL, last4 VARCHAR(4) NOT NULL, "
                            "secret_ref VARCHAR(512) NOT NULL, is_active BOOLEAN NOT NULL, "
                            "created_at DATETIME NOT NULL)"
                        )
                    )
                    connection.execute(
                        text(
                            "CREATE TABLE operational_policy_versions ("
                            "id VARCHAR(36) PRIMARY KEY, tenant_id VARCHAR(64) NOT NULL, "
                            "domain VARCHAR(16) NOT NULL, version VARCHAR(80) NOT NULL)"
                        )
                    )
                    connection.execute(
                        text(
                            "CREATE TABLE card_allocations (id VARCHAR(36) PRIMARY KEY)"
                        )
                    )
                    connection.execute(
                        text(
                            "CREATE TABLE platform_schema_compatibility ("
                            "singleton_id INTEGER PRIMARY KEY, "
                            "minimum_app_revision VARCHAR(255) NOT NULL)"
                        )
                    )
                    connection.execute(
                        text(
                            "INSERT INTO platform_schema_compatibility VALUES "
                            "(1, '0024_schema_compatibility')"
                        )
                    )
                    connection.execute(
                        text(
                            "CREATE TABLE alembic_version ("
                            "version_num VARCHAR(255) NOT NULL PRIMARY KEY)"
                        )
                    )
                    connection.execute(
                        text("INSERT INTO alembic_version VALUES (:revision)"),
                        {"revision": PREVIOUS_REVISION},
                    )
                    connection.execute(
                        text(
                            "INSERT INTO cards VALUES "
                            "('card-1', 'tenant-a', 'provider-1', 'VISA', '1111', "
                            "'vault://cards/one', 1, CURRENT_TIMESTAMP)"
                        )
                    )
                    connection.execute(
                        text(
                            "INSERT INTO operational_policy_versions VALUES "
                            "('policy-1', 'tenant-a', 'card', 'legacy-v1')"
                        )
                    )

                config = Config(str(ROOT / "alembic.ini"))
                command.upgrade(config, REVISION)
                columns = {
                    item["name"] for item in inspect(engine).get_columns("cards")
                }
                self.assertTrue({"pool_key", "region"}.issubset(columns))
                with engine.begin() as connection:
                    card = connection.execute(
                        text("SELECT pool_key, region FROM cards WHERE id='card-1'")
                    ).one()
                    self.assertEqual(tuple(card), ("legacy-unclassified",) * 2)
                    rules = json.loads(
                        connection.execute(
                            text(
                                "SELECT selection_rules_json FROM operational_policy_versions "
                                "WHERE id='policy-1'"
                            )
                        ).scalar_one()
                    )
                    self.assertEqual(rules[0]["task_type"], "card_checkout")
                    self.assertEqual(rules[0]["pool_key"], "legacy-unclassified")
            finally:
                if previous is None:
                    os.environ.pop("ALEMBIC_DATABASE_URL", None)
                else:
                    os.environ["ALEMBIC_DATABASE_URL"] = previous
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
