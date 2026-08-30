import os
from io import StringIO
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0028_operational_policy_governance"
PREVIOUS_REVISION = "0027_card_allocation_reason"
COMPATIBILITY_FLOOR = "0024_schema_compatibility"


class OperationalPolicyGovernanceMigrationTests(unittest.TestCase):
    def test_postgresql_offline_sql_widens_version_table_before_revision(self) -> None:
        url = "postgresql+psycopg://offline:offline@invalid.example/email_platform"
        previous = os.environ.get("ALEMBIC_DATABASE_URL")
        os.environ["ALEMBIC_DATABASE_URL"] = url
        try:
            output = StringIO()
            config = Config(str(ROOT / "alembic.ini"), output_buffer=output)
            command.upgrade(
                config,
                f"{PREVIOUS_REVISION}:{REVISION}",
                sql=True,
            )
            sql = output.getvalue()
        finally:
            if previous is None:
                os.environ.pop("ALEMBIC_DATABASE_URL", None)
            else:
                os.environ["ALEMBIC_DATABASE_URL"] = previous

        expansion = (
            "ALTER TABLE alembic_version "
            "ALTER COLUMN version_num TYPE VARCHAR(255)"
        )
        stamp = f"SET version_num='{REVISION}'"
        self.assertIn(expansion, sql)
        self.assertIn(stamp, sql)
        self.assertLess(sql.index(expansion), sql.index(stamp))
        self.assertNotIn("TYPE VARCHAR(32)", sql)

    def test_upgrade_adds_policy_tables_and_frozen_runtime_columns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "operational-policies.db"
            url = f"sqlite+pysqlite:///{database.as_posix()}"
            engine = create_engine(url)
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "CREATE TABLE users ("
                        "id VARCHAR(36) NOT NULL PRIMARY KEY)"
                    )
                )
                connection.execute(
                    text(
                        "CREATE TABLE mail_sessions ("
                        "id VARCHAR(36) NOT NULL PRIMARY KEY)"
                    )
                )
                connection.execute(
                    text(
                        "CREATE TABLE card_allocations ("
                        "id VARCHAR(36) NOT NULL PRIMARY KEY)"
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
                inspector = inspect(engine)
                tables = set(inspector.get_table_names())
                self.assertIn("operational_policy_versions", tables)
                self.assertIn("operational_policy_deployments", tables)

                mail_columns = {
                    item["name"]: item
                    for item in inspector.get_columns("mail_sessions")
                }
                card_columns = {
                    item["name"]: item
                    for item in inspector.get_columns("card_allocations")
                }
                for name in (
                    "policy_version",
                    "code_ttl_seconds",
                    "poll_interval_seconds",
                ):
                    self.assertIn(name, mail_columns)
                    self.assertFalse(mail_columns[name]["nullable"])
                for name in ("policy_version", "reveal_ttl_seconds"):
                    self.assertIn(name, card_columns)
                    self.assertFalse(card_columns[name]["nullable"])

                version_uniques = {
                    item["name"]
                    for item in inspector.get_unique_constraints(
                        "operational_policy_versions"
                    )
                }
                deployment_uniques = {
                    item["name"]
                    for item in inspector.get_unique_constraints(
                        "operational_policy_deployments"
                    )
                }
                self.assertIn(
                    "uq_operational_policy_versions_tenant_domain_version",
                    version_uniques,
                )
                self.assertIn(
                    "uq_operational_policy_deployments_tenant_domain",
                    deployment_uniques,
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
                        COMPATIBILITY_FLOOR,
                    )

                command.downgrade(config, PREVIOUS_REVISION)
                inspector = inspect(engine)
                self.assertNotIn(
                    "operational_policy_versions", inspector.get_table_names()
                )
                self.assertNotIn(
                    "operational_policy_deployments", inspector.get_table_names()
                )
                self.assertNotIn(
                    "policy_version",
                    {item["name"] for item in inspector.get_columns("mail_sessions")},
                )
                self.assertNotIn(
                    "policy_version",
                    {
                        item["name"]
                        for item in inspector.get_columns("card_allocations")
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
