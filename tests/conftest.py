"""
Pytest configuration and shared fixtures.

Test database strategy
----------------------
Integration tests require a live PostgreSQL instance.  Set TEST_DATABASE_URL
in the environment (or .env.test) to point at a throwaway database.  If the
variable is absent, integration tests are skipped automatically.

Unit tests (normalization logic) have no database dependency and always run.

Integration test isolation
--------------------------
Each test that writes to the database runs inside its own connection with
a nested transaction (SAVEPOINT).  The outer connection is rolled back after
every test so no data persists between tests.  This means:

  - The db_session fixture provides the outer connection/savepoint.
  - The client fixture patches the app's session factory to yield sessions
    on the SAME connection, so their writes are also rolled back.
"""

from __future__ import annotations

import asyncio
import os
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://llmx:changeme@localhost:5432/llmx_test",
)

TEST_API_KEY = "test-api-key-for-integration-tests-only"


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "integration: mark test as requiring a live database (skipped when TEST_DATABASE_URL absent)",
    )


# ---------------------------------------------------------------------------
# Fixtures: database (session-scoped engine, function-scoped isolation)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def db_engine() -> AsyncEngine:
    """
    Create the test database schema once per session, tear it down at the end.

    Synchronous fixture to avoid pytest-asyncio scope-mismatch errors when a
    session-scoped fixture is requested from a function-scoped event-loop runner.
    The async setup/teardown runs in dedicated short-lived event loops so the
    engine object can be safely passed to function-scoped async fixtures.
    """
    from backend.app.db.base import Base
    import backend.app.db.models  # noqa: F401 — register all models

    # NullPool prevents asyncpg from caching connections across event loops.
    # Without it, connections created in the setup loop are reused in test loops,
    # causing "Future attached to a different loop" errors.
    engine = create_async_engine(TEST_DATABASE_URL, echo=False, poolclass=NullPool)

    async def _setup() -> None:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    async def _teardown() -> None:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await engine.dispose()

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(_setup())
    finally:
        loop.close()

    yield engine

    loop2 = asyncio.new_event_loop()
    try:
        loop2.run_until_complete(_teardown())
    finally:
        loop2.close()


@pytest_asyncio.fixture
async def db_connection(db_engine) -> AsyncGenerator[AsyncConnection, None]:
    """
    Yield a single connection with an open transaction.
    Rolls back after the test — nothing is committed to the database.
    """
    async with db_engine.connect() as conn:
        await conn.begin()
        yield conn
        await conn.rollback()


@pytest_asyncio.fixture
async def db_session(db_connection: AsyncConnection) -> AsyncGenerator[AsyncSession, None]:
    """
    Yield an AsyncSession bound to the test's rolled-back connection.
    """
    session = AsyncSession(bind=db_connection, expire_on_commit=False)
    yield session
    await session.close()


# ---------------------------------------------------------------------------
# Fixtures: FastAPI test client
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def client(db_connection: AsyncConnection) -> AsyncGenerator[AsyncClient, None]:
    """
    AsyncClient wired to the FastAPI app.

    The app's get_db dependency is patched to yield sessions that share the
    test connection, so all writes are rolled back after the test.
    """
    import backend.app.db.session as db_session_module
    from backend.app.config import get_settings
    from backend.app.main import create_app

    # Build a factory that always creates sessions on the test connection.
    # Each call yields a new AsyncSession on the same underlying connection,
    # so all requests within the test share the rolled-back transaction.
    def make_test_factory() -> async_sessionmaker[AsyncSession]:
        return async_sessionmaker(
            bind=db_connection,
            expire_on_commit=False,
            autoflush=False,
            class_=AsyncSession,
        )

    original_factory = db_session_module._session_factory
    db_session_module._session_factory = make_test_factory()

    # Inject test config values.
    original_db_url = os.environ.get("DATABASE_URL")
    original_api_key = os.environ.get("INGESTION_API_KEY")
    os.environ["DATABASE_URL"] = TEST_DATABASE_URL
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

    # ── Teardown: restore original state ─────────────────────────────────────
    db_session_module._session_factory = original_factory
    if original_db_url is None:
        os.environ.pop("DATABASE_URL", None)
    else:
        os.environ["DATABASE_URL"] = original_db_url
    if original_api_key is None:
        os.environ.pop("INGESTION_API_KEY", None)
    else:
        os.environ["INGESTION_API_KEY"] = original_api_key
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Helpers (plain functions, not fixtures)
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
