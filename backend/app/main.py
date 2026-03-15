"""
FastAPI application factory.

Import and call create_app() to get the ASGI application instance.
The module-level `app` variable is used by uvicorn.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.v1.router import api_v1_router
from backend.app.config import get_settings
from backend.app.db.session import close_engine, init_engine
from backend.app.logging_config import configure_logging
from backend.app.middleware import RequestIDMiddleware

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    settings = get_settings()
    configure_logging(settings)

    logger.info(
        "application.starting",
        app=settings.app_name,
        version=settings.app_version,
        env=settings.app_env,
    )

    await init_engine(settings)

    yield

    logger.info("application.stopping")
    await close_engine()


def create_app() -> FastAPI:
    settings = get_settings()

    application = FastAPI(
        title="LLMX Backend",
        description="Prompt injection defense platform — ingestion and normalization API",
        version=settings.app_version,
        debug=settings.debug,
        lifespan=lifespan,
        # Disable automatic redirect for trailing slashes to avoid leaking
        # information about route existence.
        redirect_slashes=False,
    )

    # ── Middleware (order matters: outermost is applied first/last) ────────────
    # CORS — restrictive by default; tighten origins before production.
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["chrome-extension://*"] if settings.app_env == "production" else ["*"],
        allow_methods=["GET", "POST"],
        allow_headers=["X-API-Key", "X-Request-ID", "Content-Type"],
    )
    application.add_middleware(RequestIDMiddleware)

    # ── Routes ────────────────────────────────────────────────────────────────
    application.include_router(api_v1_router, prefix="/api/v1")

    return application


app = create_app()
