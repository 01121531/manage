import os
from io import StringIO
import tempfile
import unittest
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError


ROOT = Path(__file__).resolve().parents[2]
REVISION = "0020_audit_event_subject_binding"
PREVIOUS_REVISION = "0019_admin_role_change_approval"


class AuditEventSubjectBindingMigrationTests(unittest.TestCase):
    def _database(self, directory: str, *, invalid_history: bool = False):
        database = Path(directory) / "audit-event-subject-binding.db"
        url = f"sqlite+pysqlite:///{database.as_posix()}"
        engine = create_engine(url)
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE users (id VARCHAR(36) PRIMARY KEY, "
                    "tenant_id VARCHAR(64) NOT NULL)"
                )
            )
            connection.execute(
                text(
                    "CREATE TABLE devices (id VARCHAR(36) PRIMARY KEY, "
                    "tenant_id VARCHAR(64) NOT NULL, user_id VARCHAR(36) NOT NULL)"
                )
            )
            connection.execute(
                text(
                    "CREATE TABLE audit_events (id VARCHAR(36) PRIMARY KEY, "
                    "tenant_id VARCHAR(64) NOT NULL, user_id VARCHAR(36), "
                    "device_id VARCHAR(36))"
                )
            )
            connection.execute(
                text(
                    "CREATE TRIGGER audit_events_no_update "
                    "BEFORE UPDATE ON audit_events "
                    "BEGIN SELECT RAISE(ABORT, 'audit_events are append-only'); END"
                )
            )
            connection.execute(
                text(
                    "CREATE TRIGGER audit_events_no_delete "
                    "BEFORE DELETE ON audit_events "
                    "BEGIN SELECT RAISE(ABORT, 'audit_events are append-only'); END"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO users (id, tenant_id) VALUES "
                    "('user-a', 'tenant-a'), ('other-user-a', 'tenant-a'), "
                    "('user-b', 'tenant-b')"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO devices (id, tenant_id, user_id) VALUES "
                    "('device-a', 'tenant-a', 'user-a'), "
                    "('other-device-a', 'tenant-a', 'other-user-a'), "
                    "('device-b', 'tenant-b', 'user-b')"
                )
            )
            if invalid_history:
                connection.execute(
                    text(
                        "INSERT INTO audit_events (id, tenant_id, user_id, device_id) "
                        "VALUES ('bad-history', 'tenant-a', 'user-b', 'device-b')"
                    )
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

    @staticmethod
    def _set_url(url: str) -> str | None:
        previous = os.environ.get("ALEMBIC_DATABASE_URL")
        os.environ["ALEMBIC_DATABASE_URL"] = url
        return previous

    @staticmethod
    def _restore_url(previous: str | None) -> None:
        if previous is None:
            os.environ.pop("ALEMBIC_DATABASE_URL", None)
        else:
            os.environ["ALEMBIC_DATABASE_URL"] = previous

    def test_upgrade_enforces_bindings_and_preserves_append_only_guards(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine, url = self._database(directory)
            previous = self._set_url(url)
            try:
                config = Config(str(ROOT / "alembic.ini"))
                command.upgrade(config, REVISION)
                with engine.begin() as connection:
                    trigger_names = set(
                        connection.execute(
                            text(
                                "SELECT name FROM sqlite_master "
                                "WHERE type = 'trigger' AND tbl_name = 'audit_events'"
                            )
                        ).scalars()
                    )
                self.assertEqual(
                    trigger_names,
                    {
                        "audit_events_no_update",
                        "audit_events_no_delete",
                        "audit_events_subject_binding",
                    },
                )

                valid_rows = (
                    ("valid-system", "tenant-a", None, None),
                    ("valid-subject", "tenant-a", "user-a", "device-a"),
                )
                with engine.begin() as connection:
                    for row in valid_rows:
                        connection.execute(
                            text(
                                "INSERT INTO audit_events "
                                "(id, tenant_id, user_id, device_id) "
                                "VALUES (:id, :tenant_id, :user_id, :device_id)"
                            ),
                            dict(zip(("id", "tenant_id", "user_id", "device_id"), row)),
                        )

                invalid_rows = (
                    ("device-without-user", "tenant-a", None, "device-a"),
                    ("cross-tenant", "tenant-a", "user-b", "device-b"),
                    ("wrong-owner", "tenant-a", "user-a", "other-device-a"),
                )
                for row in invalid_rows:
                    with self.subTest(row=row), self.assertRaisesRegex(
                        IntegrityError, "audit_events subject binding invalid"
                    ):
                        with engine.begin() as connection:
                            connection.execute(
                                text(
                                    "INSERT INTO audit_events "
                                    "(id, tenant_id, user_id, device_id) "
                                    "VALUES (:id, :tenant_id, :user_id, :device_id)"
                                ),
                                dict(
                                    zip(
                                        ("id", "tenant_id", "user_id", "device_id"),
                                        row,
                                    )
                                ),
                            )

                command.downgrade(config, PREVIOUS_REVISION)
                with engine.begin() as connection:
                    trigger_names = set(
                        connection.execute(
                            text(
                                "SELECT name FROM sqlite_master "
                                "WHERE type = 'trigger' AND tbl_name = 'audit_events'"
                            )
                        ).scalars()
                    )
                self.assertEqual(
                    trigger_names,
                    {"audit_events_no_update", "audit_events_no_delete"},
                )
            finally:
                self._restore_url(previous)
                engine.dispose()

    def test_invalid_history_fails_before_trigger_installation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engine, url = self._database(directory, invalid_history=True)
            previous = self._set_url(url)
            try:
                config = Config(str(ROOT / "alembic.ini"))
                with self.assertRaisesRegex(
                    RuntimeError,
                    "Invalid audit event subject bindings must be remediated",
                ):
                    command.upgrade(config, REVISION)
                with engine.begin() as connection:
                    trigger_names = set(
                        connection.execute(
                            text(
                                "SELECT name FROM sqlite_master "
                                "WHERE type = 'trigger' AND tbl_name = 'audit_events'"
                            )
                        ).scalars()
                    )
                    current_revision = connection.execute(
                        text("SELECT version_num FROM alembic_version")
                    ).scalar_one()
                self.assertNotIn("audit_events_subject_binding", trigger_names)
                self.assertEqual(current_revision, PREVIOUS_REVISION)
            finally:
                self._restore_url(previous)
                engine.dispose()

    def test_postgresql_offline_sql_contains_preflight_and_insert_trigger(self) -> None:
        url = "postgresql+psycopg://offline:offline@invalid.example/email_platform"
        previous = self._set_url(url)
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
            self._restore_url(previous)

        for required in (
            "SELECT CASE WHEN EXISTS",
            "THEN 1 / 0 ELSE 1 END AS audit_event_subject_bindings_valid",
            "CREATE FUNCTION audit_events_validate_subject_binding()",
            "RAISE EXCEPTION 'audit_events subject binding invalid'",
            "USING ERRCODE = '23503'",
            "CREATE TRIGGER audit_events_subject_binding",
            "BEFORE INSERT ON audit_events",
        ):
            with self.subTest(required=required):
                self.assertIn(required, sql)

        preflight_start = sql.index("SELECT CASE WHEN EXISTS")
        trigger_function_start = sql.index(
            "CREATE FUNCTION audit_events_validate_subject_binding()"
        )
        self.assertLess(preflight_start, trigger_function_start)
        preflight_sql = sql[preflight_start:trigger_function_start]
        for forbidden in ("DO $$", "EXECUTE ", "CALL "):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, preflight_sql)


if __name__ == "__main__":
    unittest.main()
