"""
FastAPI dependency providers shared across routes.
"""

from __future__ import annotations

import hmac
from typing import Annotated, AsyncGenerator

import structlog
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config import Settings, get_settings
from backend.app.db.session import get_session_factory

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


# ── Settings ──────────────────────────────────────────────────────────────────


def get_settings_dep() -> Settings:
    return get_settings()


SettingsDep = Annotated[Settings, Depends(get_settings_dep)]


# ── Database session ──────────────────────────────────────────────────────────


async def get_db(
    settings: SettingsDep,
) -> AsyncGenerator[AsyncSession, None]:
    factory = get_session_factory(settings)
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


DBSession = Annotated[AsyncSession, Depends(get_db)]


# ── API key authentication ────────────────────────────────────────────────────


async def require_api_key(
    settings: SettingsDep,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> None:
    """
    Validates the X-API-Key header using a constant-time comparison to
    prevent timing-based side-channel attacks.

    Raises HTTP 401 for any authentication failure without leaking whether
    the key was absent or incorrect.
    """
    if x_api_key is None:
        logger.warning("auth.missing_api_key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
        )
    valid = hmac.compare_digest(
        x_api_key.encode("utf-8"),
        settings.ingestion_api_key.encode("utf-8"),
    )
    if not valid:
        logger.warning("auth.invalid_api_key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )


RequireAPIKey = Depends(require_api_key)
