"""
Alembic environment configuration for async PostgreSQL.

The database URL is injected from app Settings so it is always sourced from
environment variables — never from alembic.ini.

Usage
-----
  # Apply all pending migrations:
  alembic upgrade head

  # Generate a new migration (autogenerate from model changes):
  alembic revision --autogenerate -m "describe_change"

  # Roll back one step:
  alembic downgrade -1
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

# Import Base and all models so Alembic's autogenerate can detect schema changes.
from backend.app.config import get_settings
from backend.app.db.base import Base
import backend.app.db.models  # noqa: F401 — registers all mapped classes

# Alembic Config object providing access to alembic.ini values.
config = context.config

# Wire up Python logging from alembic.ini [loggers] section.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _get_url() -> str:
    return get_settings().database_url


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode.

    Generates SQL without a live DB connection.  Useful for reviewing
    changes or deploying to environments where direct DB access is restricted.
    """
    context.configure(
        url=_get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: object) -> None:
    context.configure(
        connection=connection,  # type: ignore[arg-type]
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    configuration = dict(config.get_section(config.config_ini_section) or {})
    configuration["sqlalchemy.url"] = _get_url()

    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
