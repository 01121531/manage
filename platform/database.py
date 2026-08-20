"""SQLAlchemy setup kept local to each FastAPI application instance."""

from collections.abc import Generator
from typing import Any

from fastapi import Request
from sqlalchemy import Engine, event
from sqlalchemy import create_engine as sqlalchemy_create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


def create_engine(database_url: str) -> Engine:
    """Create an engine suitable for the configured SQLite development DB."""

    options: dict[str, Any] = {}
    if database_url.startswith("sqlite"):
        options["connect_args"] = {"check_same_thread": False}
        if ":memory:" in database_url:
            options["poolclass"] = StaticPool

    engine = sqlalchemy_create_engine(database_url, **options)
    if database_url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def enable_foreign_keys(dbapi_connection: Any, _: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def _install_audit_append_only_constraints(engine: Engine) -> None:
    """Block UPDATE/DELETE mutations on audit events at the database layer."""

    dialect = engine.dialect.name
    with engine.begin() as connection:
        if dialect == "sqlite":
            connection.exec_driver_sql(
                """
                CREATE TRIGGER IF NOT EXISTS audit_events_no_update
                BEFORE UPDATE ON audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'audit_events are append-only');
                END;
                """
            )
            connection.exec_driver_sql(
                """
                CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
                BEFORE DELETE ON audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'audit_events are append-only');
                END;
                """
            )
            return
        if dialect == "postgresql":
            connection.exec_driver_sql(
                """
                CREATE OR REPLACE FUNCTION audit_events_prevent_mutation()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $$
                BEGIN
                    RAISE EXCEPTION 'audit_events are append-only';
                END;
                $$;
                """
            )
            connection.exec_driver_sql(
                """
                DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
                """
            )
            connection.exec_driver_sql(
                """
                DROP TRIGGER IF EXISTS audit_events_no_delete ON audit_events;
                """
            )
            connection.exec_driver_sql(
                """
                CREATE TRIGGER audit_events_no_update
                BEFORE UPDATE ON audit_events
                FOR EACH ROW EXECUTE FUNCTION audit_events_prevent_mutation();
                """
            )
            connection.exec_driver_sql(
                """
                CREATE TRIGGER audit_events_no_delete
                BEFORE DELETE ON audit_events
                FOR EACH ROW EXECUTE FUNCTION audit_events_prevent_mutation();
                """
            )


def initialize_database(
    database_url: str,
) -> tuple[Engine, sessionmaker[Session]]:
    """Create the development schema and return its session factory."""

    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    _install_audit_append_only_constraints(engine)
    return engine, sessionmaker(bind=engine, expire_on_commit=False)


def get_db(request: Request) -> Generator[Session, None, None]:
    session: Session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()
