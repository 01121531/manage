import os
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0019_admin_role_change_approval"
PREVIOUS_REVISION = "0018_access_token_revocations"


class AdminRoleChangeMigrationTests(unittest.TestCase):
    def test_upgrade_enforces_one_pending_request_and_downgrade_removes_table(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "admin-role-change.db"
            url = f"sqlite+pysqlite:///{database.as_posix()}"
            engine = create_engine(url)
            with engine.begin() as connection:
                connection.execute(text("CREATE TABLE users (id VARCHAR(36) PRIMARY KEY)"))
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
                for user_id in ("requester", "approver", "target"):
                    connection.execute(
                        text("INSERT INTO users (id) VALUES (:user_id)"),
                        {"user_id": user_id},
                    )

            previous = os.environ.get("ALEMBIC_DATABASE_URL")
            os.environ["ALEMBIC_DATABASE_URL"] = url
            try:
                config = Config(str(ROOT / "alembic.ini"))
                command.upgrade(config, REVISION)
                inspector = inspect(engine)
                self.assertIn("admin_role_change_requests", inspector.get_table_names())
                indexes = {
                    item["name"]: item
                    for item in inspector.get_indexes("admin_role_change_requests")
                }
                pending_index = indexes[
                    "uq_admin_role_change_requests_pending_target"
                ]
                self.assertTrue(pending_index["unique"])

                insert = text(
                    "INSERT INTO admin_role_change_requests "
                    "(id, tenant_id, target_user_id, expected_old_role, new_role, "
                    "status, requested_by, request_trace_id, created_at, expires_at) "
                    "VALUES (:id, 'tenant-a', 'target', 'operator', "
                    "'security_auditor', 'pending', 'requester', :trace, "
                    "'2026-08-24 00:00:00', '2026-08-24 00:15:00')"
                )
                with engine.begin() as connection:
                    connection.execute(insert, {"id": "request-1", "trace": "trace-1"})
                with self.assertRaises(IntegrityError):
                    with engine.begin() as connection:
                        connection.execute(
                            insert,
                            {"id": "request-2", "trace": "trace-2"},
                        )

                command.downgrade(config, PREVIOUS_REVISION)
                self.assertNotIn(
                    "admin_role_change_requests", inspect(engine).get_table_names()
                )
            finally:
                if previous is None:
                    os.environ.pop("ALEMBIC_DATABASE_URL", None)
                else:
                    os.environ["ALEMBIC_DATABASE_URL"] = previous
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
