"""Alembic environment for the platform schema.

Production reads its URL from ``ALEMBIC_DATABASE_URL_FILE``. Development may
also use ``-x db_url=...`` or ``ALEMBIC_DATABASE_URL`` for local tooling.
"""

from __future__ import annotations

from logging.config import fileConfig
import os
from pathlib import Path
import sys

from alembic import context
from sqlalchemy import engine_from_config, pool

# ``platform`` is also a Python standard-library module.  The Alembic console
# script starts with its Scripts directory on ``sys.path`` and may have loaded
# that module before applying ``prepend_sys_path``.  Make the repository
# package deterministic while preserving its standard-library API shim.
_repo_root = Path(__file__).resolve().parents[2]
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))
_loaded_platform = sys.modules.get("platform")
if _loaded_platform is not None and not hasattr(_loaded_platform, "__path__"):
    del sys.modules["platform"]

from platform.config import Settings
from platform.database import Base
from platform import models as _models  # noqa: F401 - register metadata


config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    cli_url = context.get_x_argument(as_dictionary=True).get("db_url")
    file_path = os.getenv("ALEMBIC_DATABASE_URL_FILE")
    environment = os.getenv("PLATFORM_ENVIRONMENT", "development").strip().lower()
    managed_environment = environment not in {"development", "test"}
    if managed_environment:
        if os.getenv("ALEMBIC_DATABASE_URL") or cli_url:
            raise RuntimeError(
                "Production Alembic forbids inline database URLs; use "
                "ALEMBIC_DATABASE_URL_FILE"
            )
        return Settings._read_runtime_secret(file_path, "ALEMBIC_DATABASE_URL")
    if file_path:
        return Settings._read_runtime_secret(file_path, "ALEMBIC_DATABASE_URL")
    url = cli_url or os.getenv("ALEMBIC_DATABASE_URL") or Settings().database_url
    if not url:
        raise RuntimeError(
            "Database URL is required; set ALEMBIC_DATABASE_URL or use -x db_url=..."
        )
    return url


def run_migrations_offline() -> None:
    """Emit SQL without connecting to a database."""

    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = _database_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
