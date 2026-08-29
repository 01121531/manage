"""Fail closed unless the configured database is compatible with this release."""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError

from platform.config import Settings
from platform.database import database_schema_is_current


def main() -> int:
    settings = Settings()
    managed = settings.environment.strip().lower() not in {"development", "test"}
    try:
        database_url = settings.resolved_database_url(require_file=managed)
        engine = create_engine(database_url, pool_pre_ping=True)
        try:
            current = database_schema_is_current(engine)
        finally:
            engine.dispose()
    except (OSError, RuntimeError, SQLAlchemyError):
        print("database-schema-check-failed")
        return 1
    if not current:
        print("database-schema-not-current")
        return 1
    print("database-schema-current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
