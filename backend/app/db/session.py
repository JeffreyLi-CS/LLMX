"""
SQLAlchemy async engine and session factory lifecycle.

init_engine() must be called once at startup (via the FastAPI lifespan hook).
close_engine() must be called at shutdown.

get_session_factory() returns the module-level factory, which is used by the
get_db() FastAPI dependency in app/dependencies.py.
"""

from __future__ import annotations

import structlog
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from backend.app.config import Settings

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


async def init_engine(settings: Settings) -> None:
    global _engine, _session_factory

    _engine = create_async_engine(
        settings.database_url,
        echo=settings.debug,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_pre_ping=True,
    )
    _session_factory = async_sessionmaker(
        _engine,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
        class_=AsyncSession,
    )
    logger.info("db.engine.initialised", pool_size=settings.db_pool_size)


async def close_engine() -> None:
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None
        logger.info("db.engine.disposed")


def get_session_factory(settings: Settings | None = None) -> async_sessionmaker[AsyncSession]:
    if _session_factory is None:
        raise RuntimeError(
            "Database session factory has not been initialised. "
            "Ensure init_engine() was called during application startup."
        )
    return _session_factory
