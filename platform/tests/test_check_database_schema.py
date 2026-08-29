import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sqlalchemy import create_engine, text

from infra import check_database_schema
from platform.config import Settings


class DatabaseSchemaCheckTests(unittest.TestCase):
    def test_current_database_succeeds_without_printing_the_url(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database_url = f"sqlite+pysqlite:///{Path(directory, 'schema.db').as_posix()}"
            engine = create_engine(database_url)
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "CREATE TABLE alembic_version "
                        "(version_num VARCHAR(255) NOT NULL PRIMARY KEY)"
                    )
                )
                connection.execute(
                    text(
                        "INSERT INTO alembic_version(version_num) "
                        "VALUES ('0032_upload_phase_tracking')"
                    )
                )
            engine.dispose()
            settings = Settings(environment="test", database_url=database_url)
            with (
                mock.patch.object(check_database_schema, "Settings", return_value=settings),
                mock.patch("builtins.print") as output,
            ):
                self.assertEqual(check_database_schema.main(), 0)
            output.assert_called_once_with("database-schema-current")
            self.assertNotIn(database_url, str(output.call_args_list))

    def test_unavailable_database_fails_closed(self) -> None:
        settings = Settings(
            environment="production",
            database_url_file="missing-database-url-file",
        )
        with (
            mock.patch.object(check_database_schema, "Settings", return_value=settings),
            mock.patch("builtins.print") as output,
        ):
            self.assertEqual(check_database_schema.main(), 1)
        output.assert_called_once_with("database-schema-check-failed")

    def test_older_database_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database_url = f"sqlite+pysqlite:///{Path(directory, 'old.db').as_posix()}"
            engine = create_engine(database_url)
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "CREATE TABLE alembic_version "
                        "(version_num VARCHAR(255) NOT NULL PRIMARY KEY)"
                    )
                )
                connection.execute(
                    text(
                        "INSERT INTO alembic_version(version_num) "
                        "VALUES ('0027_card_allocation_reason')"
                    )
                )
            engine.dispose()
            settings = Settings(environment="test", database_url=database_url)
            with (
                mock.patch.object(check_database_schema, "Settings", return_value=settings),
                mock.patch("builtins.print") as output,
            ):
                self.assertEqual(check_database_schema.main(), 1)
            output.assert_called_once_with("database-schema-not-current")


if __name__ == "__main__":
    unittest.main()
