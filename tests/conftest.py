"""
Pytest configuration and shared fixtures.

Test database strategy
----------------------
Integration tests require a live PostgreSQL instance.  Set TEST_DATABASE_URL
in the environment (or .env.test) to point at a throwaway database.  If the
variable is absent, integration tests are skipped automatically.

Unit tests (normalization logic) have no database dependency.
"""

from __future__ import annotations

import os
from typing import AsyncGenerator
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://llmx:changeme@localhost:5432/llmx_test",
)

# Marker used to skip integration tests when no DB is available.
pytest.register_mark = lambda *a, **kw: None  # suppress unknown-mark warnings


# ---------------------------------------------------------------------------
# Fixtures: database
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="session")
async def db_engine():
    """Create the test database schema once per session."""
    from backend.app.db.base import Base
    import backend.app.db.models  # noqa: F401 — register all models

    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    """Yield a session wrapped in a savepoint that rolls back after the test."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False, autoflush=False)
    async with factory() as session:
        async with session.begin():
            yield session
            await session.rollback()


# ---------------------------------------------------------------------------
# Fixtures: FastAPI test client
# ---------------------------------------------------------------------------

TEST_API_KEY = "test-api-key-for-integration-tests-only"


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """
    AsyncClient wired to the FastAPI app with the test DB session injected.

    The app's lifespan is bypassed so we control the DB session directly.
    """
    import backend.app.db.session as db_session_module
    from backend.app.config import get_settings
    from backend.app.main import create_app

    # Patch the module-level session factory used by get_db().
    test_factory = async_sessionmaker(
        db_session.get_bind(),  # type: ignore[arg-type]
        expire_on_commit=False,
        autoflush=False,
        class_=AsyncSession,
    )
    original_factory = db_session_module._session_factory
    db_session_module._session_factory = test_factory

    # Override settings to inject the test API key.
    os.environ.setdefault("DATABASE_URL", TEST_DATABASE_URL)
    os.environ["INGESTION_API_KEY"] = TEST_API_KEY

    get_settings.cache_clear()

    app = create_app()

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={"X-API-Key": TEST_API_KEY},
    ) as ac:
        yield ac

    # Restore state.
    db_session_module._session_factory = original_factory
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def minimal_ingest_payload(
    page_html: str = "<html><body><p>Hello world</p></body></html>",
    selected_text: str | None = None,
) -> dict:
    """Return a minimal valid ingest request body."""
    return {
        "page_html": page_html,
        "selected_text": selected_text,
        "dom_metadata": {
            "url": "https://example.com/page",
            "title": "Test Page",
            "frame_depth": 0,
            "origin": "https://example.com",
        },
        "hidden_content_indicators": [],
        "extension_version": "1.0.0",
        "captured_at": "2026-03-15T12:00:00Z",
    }


# ---------------------------------------------------------------------------
# Fixtures wrapping helpers (for tests that receive them via pytest injection)
# ---------------------------------------------------------------------------


@pytest.fixture
def minimal_ingest_payload_fixture():
    """Pytest fixture version of minimal_ingest_payload."""
    return minimal_ingest_payload
