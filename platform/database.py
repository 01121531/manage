"""SQLAlchemy setup kept local to each FastAPI application instance."""

from collections.abc import Generator
from pathlib import Path
from typing import Any

from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.util.exc import CommandError
from fastapi import Request
from sqlalchemy import Engine, event, text
from sqlalchemy import create_engine as sqlalchemy_create_engine
from sqlalchemy.exc import SQLAlchemyError
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
    """Protect audit immutability and tenant-scoped subject bindings."""

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
            connection.exec_driver_sql(
                """
                CREATE TRIGGER IF NOT EXISTS audit_events_subject_binding
                BEFORE INSERT ON audit_events
                WHEN
                    (NEW.user_id IS NOT NULL AND NOT EXISTS (
                        SELECT 1 FROM users
                        WHERE users.id = NEW.user_id
                          AND users.tenant_id = NEW.tenant_id
                    ))
                    OR
                    (NEW.device_id IS NOT NULL AND (
                        NEW.user_id IS NULL OR NOT EXISTS (
                            SELECT 1 FROM devices
                            WHERE devices.id = NEW.device_id
                              AND devices.tenant_id = NEW.tenant_id
                              AND devices.user_id = NEW.user_id
                        )
                    ))
                BEGIN
                    SELECT RAISE(ABORT, 'audit_events subject binding invalid');
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
            connection.exec_driver_sql(
                """
                CREATE OR REPLACE FUNCTION audit_events_validate_subject_binding()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $$
                BEGIN
                    IF
                        (NEW.user_id IS NOT NULL AND NOT EXISTS (
                            SELECT 1 FROM users
                            WHERE users.id = NEW.user_id
                              AND users.tenant_id = NEW.tenant_id
                        ))
                        OR
                        (NEW.device_id IS NOT NULL AND (
                            NEW.user_id IS NULL OR NOT EXISTS (
                                SELECT 1 FROM devices
                                WHERE devices.id = NEW.device_id
                                  AND devices.tenant_id = NEW.tenant_id
                                  AND devices.user_id = NEW.user_id
                            )
                        ))
                    THEN
                        RAISE EXCEPTION 'audit_events subject binding invalid'
                            USING ERRCODE = '23503';
                    END IF;
                    RETURN NEW;
                END;
                $$;
                """
            )
            connection.exec_driver_sql(
                "DROP TRIGGER IF EXISTS audit_events_subject_binding ON audit_events;"
            )
            connection.exec_driver_sql(
                """
                CREATE TRIGGER audit_events_subject_binding
                BEFORE INSERT ON audit_events
                FOR EACH ROW EXECUTE FUNCTION audit_events_validate_subject_binding();
                """
            )


def _install_card_event_append_only_constraints(engine: Engine) -> None:
    """Protect masked card history from mutation and cross-tenant binding."""

    dialect = engine.dialect.name
    with engine.begin() as connection:
        if dialect == "sqlite":
            connection.exec_driver_sql(
                """
                CREATE TRIGGER IF NOT EXISTS card_events_no_update
                BEFORE UPDATE ON card_events
                BEGIN
                    SELECT RAISE(ABORT, 'card_events are append-only');
                END;
                """
            )
            connection.exec_driver_sql(
                """
                CREATE TRIGGER IF NOT EXISTS card_events_no_delete
                BEFORE DELETE ON card_events
                BEGIN
                    SELECT RAISE(ABORT, 'card_events are append-only');
                END;
                """
            )
            connection.exec_driver_sql(
                """
                CREATE TRIGGER IF NOT EXISTS card_events_subject_binding
                BEFORE INSERT ON card_events
                WHEN
                    NOT EXISTS (
                        SELECT 1 FROM cards
                        WHERE cards.id = NEW.card_id
                          AND cards.tenant_id = NEW.tenant_id
                    )
                    OR (
                        NEW.allocation_id IS NOT NULL
                        AND NOT EXISTS (
                            SELECT 1 FROM card_allocations
                            WHERE card_allocations.id = NEW.allocation_id
                              AND card_allocations.tenant_id = NEW.tenant_id
                              AND card_allocations.card_id = NEW.card_id
                        )
                    )
                BEGIN
                    SELECT RAISE(ABORT, 'card_events subject binding invalid');
                END;
                """
            )
            return
        if dialect == "postgresql":
            connection.exec_driver_sql(
                """
                CREATE OR REPLACE FUNCTION card_events_prevent_mutation()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $$
                BEGIN
                    RAISE EXCEPTION 'card_events are append-only';
                END;
                $$;
                """
            )
            connection.exec_driver_sql(
                """
                CREATE OR REPLACE FUNCTION card_events_validate_subject_binding()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $$
                BEGIN
                    IF
                        NOT EXISTS (
                            SELECT 1 FROM cards
                            WHERE cards.id = NEW.card_id
                              AND cards.tenant_id = NEW.tenant_id
                        )
                        OR (
                            NEW.allocation_id IS NOT NULL
                            AND NOT EXISTS (
                                SELECT 1 FROM card_allocations
                                WHERE card_allocations.id = NEW.allocation_id
                                  AND card_allocations.tenant_id = NEW.tenant_id
                                  AND card_allocations.card_id = NEW.card_id
                            )
                        )
                    THEN
                        RAISE EXCEPTION 'card_events subject binding invalid'
                            USING ERRCODE = '23503';
                    END IF;
                    RETURN NEW;
                END;
                $$;
                """
            )
            for trigger in (
                "card_events_no_update",
                "card_events_no_delete",
                "card_events_subject_binding",
            ):
                connection.exec_driver_sql(
                    f"DROP TRIGGER IF EXISTS {trigger} ON card_events"
                )
            connection.exec_driver_sql(
                """
                CREATE TRIGGER card_events_no_update
                BEFORE UPDATE ON card_events
                FOR EACH ROW EXECUTE FUNCTION card_events_prevent_mutation();
                """
            )
            connection.exec_driver_sql(
                """
                CREATE TRIGGER card_events_no_delete
                BEFORE DELETE ON card_events
                FOR EACH ROW EXECUTE FUNCTION card_events_prevent_mutation();
                """
            )
            connection.exec_driver_sql(
                """
                CREATE TRIGGER card_events_subject_binding
                BEFORE INSERT ON card_events
                FOR EACH ROW EXECUTE FUNCTION card_events_validate_subject_binding();
                """
            )


def _install_card_claim_mutation_ledger_constraints(engine: Engine) -> None:
    """Mirror the migration-backed claim mutation ledger in local SQLite."""

    if engine.dialect.name != "sqlite":
        return
    with engine.begin() as connection:
        connection.exec_driver_sql(
            """
            CREATE TRIGGER IF NOT EXISTS pool_import_card_claim_mutations_record
            AFTER UPDATE OF context_id, position
            ON pool_import_card_identity_claims
            WHEN NEW.context_id IS NOT OLD.context_id
              OR NEW.position IS NOT OLD.position
            BEGIN
                INSERT INTO pool_import_card_claim_mutations (
                    tenant_id,
                    source_context_id,
                    source_position,
                    destination_context_id,
                    destination_position,
                    destination_trace_id,
                    created_at
                ) VALUES (
                    NEW.tenant_id,
                    OLD.context_id,
                    OLD.position,
                    NEW.context_id,
                    NEW.position,
                    (
                        SELECT trace_id
                        FROM pool_import_contexts
                        WHERE id = NEW.context_id
                          AND tenant_id = NEW.tenant_id
                          AND pool_type = 'card'
                    ),
                    CURRENT_TIMESTAMP
                );
            END;
            """
        )
        connection.exec_driver_sql(
            """
            CREATE TRIGGER IF NOT EXISTS
            pool_import_card_claim_mutations_no_update
            BEFORE UPDATE ON pool_import_card_claim_mutations
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'card claim mutation ledger is append-only'
                );
            END;
            """
        )
        connection.exec_driver_sql(
            """
            CREATE TRIGGER IF NOT EXISTS
            pool_import_card_claim_mutations_no_delete
            BEFORE DELETE ON pool_import_card_claim_mutations
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'card claim mutation ledger is append-only'
                );
            END;
            """
        )


def _install_pool_import_context_identity_constraints(engine: Engine) -> None:
    """Mirror the migration-backed context identity guard in local SQLite."""

    if engine.dialect.name != "sqlite":
        return
    with engine.begin() as connection:
        connection.exec_driver_sql(
            """
            CREATE TRIGGER IF NOT EXISTS pool_import_contexts_identity_immutable
            BEFORE UPDATE OF id, context_token_hash, tenant_id, audience,
                pool_type, ordered_manifest_digest, item_count, created_by,
                device_id, trace_id, created_at
            ON pool_import_contexts
            WHEN NEW.id IS NOT OLD.id
              OR NEW.context_token_hash IS NOT OLD.context_token_hash
              OR NEW.tenant_id IS NOT OLD.tenant_id
              OR NEW.audience IS NOT OLD.audience
              OR NEW.pool_type IS NOT OLD.pool_type
              OR NEW.ordered_manifest_digest IS NOT OLD.ordered_manifest_digest
              OR NEW.item_count IS NOT OLD.item_count
              OR NEW.created_by IS NOT OLD.created_by
              OR NEW.device_id IS NOT OLD.device_id
              OR NEW.trace_id IS NOT OLD.trace_id
              OR NEW.created_at IS NOT OLD.created_at
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'pool import context identity is immutable'
                );
            END;
            """
        )


def _install_secure_pool_import_consumption_constraints(engine: Engine) -> None:
    """Mirror the migration-backed consumption guards in local SQLite."""

    if engine.dialect.name != "sqlite":
        return
    with engine.begin() as connection:
        connection.exec_driver_sql(
            """
            CREATE TRIGGER IF NOT EXISTS
            secure_pool_import_consumptions_update_forbidden
            BEFORE UPDATE ON secure_pool_import_consumptions
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'secure pool import consumption is append-only'
                );
            END;
            """
        )
        connection.exec_driver_sql(
            """
            CREATE TRIGGER IF NOT EXISTS
            secure_pool_import_consumptions_delete_forbidden
            BEFORE DELETE ON secure_pool_import_consumptions
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'secure pool import consumption is append-only'
                );
            END;
            """
        )


def _install_pool_import_receipt_constraints(engine: Engine) -> None:
    """Mirror the migration-backed local receipt guards in SQLite."""

    if engine.dialect.name != "sqlite":
        return
    with engine.begin() as connection:
        connection.exec_driver_sql(
            """
            CREATE TRIGGER IF NOT EXISTS pool_import_receipts_update_forbidden
            BEFORE UPDATE ON pool_import_receipts
            BEGIN
                SELECT RAISE(ABORT, 'pool import receipt is append-only');
            END;
            """
        )
        connection.exec_driver_sql(
            """
            CREATE TRIGGER IF NOT EXISTS pool_import_receipts_delete_forbidden
            BEFORE DELETE ON pool_import_receipts
            BEGIN
                SELECT RAISE(ABORT, 'pool import receipt is append-only');
            END;
            """
        )


def _install_pool_import_context_consumption_constraints(engine: Engine) -> None:
    """Mirror the migration-backed context lifecycle guards in local SQLite."""

    if engine.dialect.name != "sqlite":
        return
    with engine.begin() as connection:
        connection.exec_driver_sql(
            """
            CREATE TRIGGER IF NOT EXISTS
            pool_import_contexts_consumption_lifecycle_insert
            BEFORE INSERT ON pool_import_contexts
            WHEN NEW.consumed_at IS NOT NULL
              OR NEW.pool_import_receipt_id IS NOT NULL
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'pool import context must start unconsumed'
                );
            END;
            """
        )
        connection.exec_driver_sql(
            """
            CREATE TRIGGER IF NOT EXISTS
            pool_import_contexts_consumption_lifecycle_update
            BEFORE UPDATE OF expires_at, consumed_at, pool_import_receipt_id
            ON pool_import_contexts
            WHEN
                (NEW.consumed_at IS NULL)
                    <> (NEW.pool_import_receipt_id IS NULL)
                OR (
                    (OLD.consumed_at IS NOT NULL
                     OR OLD.pool_import_receipt_id IS NOT NULL)
                    AND (
                        NEW.expires_at IS NOT OLD.expires_at
                        OR NEW.consumed_at IS NOT OLD.consumed_at
                        OR NEW.pool_import_receipt_id
                            IS NOT OLD.pool_import_receipt_id
                    )
                )
                OR (
                    OLD.consumed_at IS NULL
                    AND OLD.pool_import_receipt_id IS NULL
                    AND NEW.consumed_at IS NOT NULL
                    AND NEW.pool_import_receipt_id IS NOT NULL
                    AND (
                        NEW.expires_at IS NOT OLD.expires_at
                        OR NOT EXISTS (
                            SELECT 1
                            FROM pool_import_receipts
                            JOIN secure_pool_import_consumptions
                              ON secure_pool_import_consumptions.pool_import_receipt_id
                                 = pool_import_receipts.id
                            WHERE pool_import_receipts.id
                                    = NEW.pool_import_receipt_id
                              AND secure_pool_import_consumptions.receipt_id
                                    = NEW.id
                              AND pool_import_receipts.tenant_id = NEW.tenant_id
                              AND pool_import_receipts.pool_type = NEW.pool_type
                              AND pool_import_receipts.request_digest
                                    = NEW.ordered_manifest_digest
                              AND pool_import_receipts.item_count
                                    = NEW.item_count
                              AND pool_import_receipts.created_by = NEW.created_by
                              AND pool_import_receipts.device_id = NEW.device_id
                        )
                    )
                )
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'pool import context consumption lifecycle invalid'
                );
            END;
            """
        )


def initialize_database(
    database_url: str,
    *,
    create_schema: bool = True,
) -> tuple[Engine, sessionmaker[Session]]:
    """Return a session factory, optionally creating a local development schema."""

    engine = create_engine(database_url)
    if create_schema:
        Base.metadata.create_all(engine)
        _install_audit_append_only_constraints(engine)
        _install_card_event_append_only_constraints(engine)
        _install_card_claim_mutation_ledger_constraints(engine)
        _install_pool_import_context_identity_constraints(engine)
        _install_pool_import_receipt_constraints(engine)
        _install_secure_pool_import_consumption_constraints(engine)
        _install_pool_import_context_consumption_constraints(engine)
    return engine, sessionmaker(bind=engine, expire_on_commit=False)


def database_schema_is_current(engine: Engine) -> bool:
    """Return whether this release can safely serve the current database schema.

    Exact head equality remains the bootstrap rule.  Once the compatibility
    marker exists, a newer expand-only database head is accepted only when its
    declared minimum application revision is present in this release's
    reviewed Alembic ancestry.
    """

    try:
        script_location = Path(__file__).resolve().parent / "migrations"
        script = ScriptDirectory(str(script_location))
        expected_heads = frozenset(script.get_heads())
        with engine.connect() as connection:
            current_heads = frozenset(
                MigrationContext.configure(connection).get_current_heads()
            )
            if not expected_heads or not current_heads:
                return False
            if current_heads == expected_heads:
                return True
            if len(expected_heads) != 1 or len(current_heads) != 1:
                return False
            current_revision = next(iter(current_heads))
            try:
                known_current_revision = script.get_revision(current_revision)
            except CommandError:
                # A future expand-only head is intentionally absent from an
                # older release's migration graph. Its compatibility floor is
                # the only safe signal available to that release.
                known_current_revision = None
            if known_current_revision is not None:
                # A non-head revision already known to this release is behind
                # (or otherwise not the expected single head), never ahead.
                return False
            minimum_revision = connection.execute(
                text(
                    "SELECT minimum_app_revision "
                    "FROM platform_schema_compatibility WHERE singleton_id = 1"
                )
            ).scalar_one_or_none()
        if not isinstance(minimum_revision, str) or not minimum_revision:
            return False
        expected_revision = next(iter(expected_heads))
        cursor: str | None = expected_revision
        visited: set[str] = set()
        while cursor is not None and cursor not in visited:
            if cursor == minimum_revision:
                return True
            visited.add(cursor)
            revision = script.get_revision(cursor)
            if revision is None or not isinstance(
                revision.down_revision, (str, type(None))
            ):
                return False
            cursor = revision.down_revision
        return False
    except (CommandError, OSError, RuntimeError, SQLAlchemyError):
        return False


def get_db(request: Request) -> Generator[Session, None, None]:
    session: Session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()
