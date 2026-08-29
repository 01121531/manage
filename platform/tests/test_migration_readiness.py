import unittest
from types import SimpleNamespace
from unittest import mock

from alembic.util.exc import CommandError
from sqlalchemy import create_engine, text

from platform.database import database_schema_is_current


CURRENT = "0032_upload_phase_tracking"


class MigrationReadinessTests(unittest.TestCase):
    def engine_with_heads(
        self,
        *heads: str,
        minimum_app_revision: str | None = None,
    ):
        engine = create_engine("sqlite+pysqlite:///:memory:")
        with engine.begin() as connection:
            connection.execute(
                text("CREATE TABLE alembic_version (version_num VARCHAR(255) NOT NULL)")
            )
            for head in heads:
                connection.execute(
                    text("INSERT INTO alembic_version(version_num) VALUES (:head)"),
                    {"head": head},
                )
            if minimum_app_revision is not None:
                connection.execute(
                    text(
                        "CREATE TABLE platform_schema_compatibility ("
                        "singleton_id INTEGER PRIMARY KEY, "
                        "minimum_app_revision VARCHAR(255) NOT NULL)"
                    )
                )
                connection.execute(
                    text(
                        "INSERT INTO platform_schema_compatibility "
                        "(singleton_id, minimum_app_revision) VALUES (1, :minimum)"
                    ),
                    {"minimum": minimum_app_revision},
                )
        self.addCleanup(engine.dispose)
        return engine

    def test_exact_repository_head_is_ready(self) -> None:
        self.assertTrue(database_schema_is_current(self.engine_with_heads(CURRENT)))

    def test_release_n_remains_ready_on_a_future_expand_head(self) -> None:
        engine = self.engine_with_heads(
            "0026_future_expand",
            minimum_app_revision=CURRENT,
        )
        self.assertTrue(database_schema_is_current(engine))

    def test_current_release_rejects_a_known_older_database_even_with_floor(self) -> None:
        engine = self.engine_with_heads(
            "0024_schema_compatibility",
            minimum_app_revision="0024_schema_compatibility",
        )
        self.assertFalse(database_schema_is_current(engine))

    def test_previous_release_accepts_unknown_new_expand_head_with_its_floor(self) -> None:
        class PreviousReleaseScript:
            @staticmethod
            def get_heads() -> list[str]:
                return ["0024_schema_compatibility"]

            @staticmethod
            def get_revision(revision: str):
                if revision == CURRENT:
                    raise CommandError("unknown future revision")
                if revision == "0024_schema_compatibility":
                    return SimpleNamespace(down_revision="0023_card_events")
                return None

        engine = self.engine_with_heads(
            CURRENT,
            minimum_app_revision="0024_schema_compatibility",
        )
        with mock.patch(
            "platform.database.ScriptDirectory",
            return_value=PreviousReleaseScript(),
        ):
            self.assertTrue(database_schema_is_current(engine))

    def test_future_contract_floor_rejects_the_old_release(self) -> None:
        engine = self.engine_with_heads(
            "0026_future_contract",
            minimum_app_revision="0026_future_contract",
        )
        self.assertFalse(database_schema_is_current(engine))

    def test_behind_or_branched_database_is_not_ready(self) -> None:
        self.assertFalse(
            database_schema_is_current(self.engine_with_heads("0023_card_events"))
        )
        self.assertFalse(
            database_schema_is_current(
                self.engine_with_heads(
                    CURRENT,
                    "0026_unreviewed_branch",
                    minimum_app_revision=CURRENT,
                )
            )
        )


if __name__ == "__main__":
    unittest.main()
