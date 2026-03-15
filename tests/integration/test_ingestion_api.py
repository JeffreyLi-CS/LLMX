"""
Integration tests for POST /api/v1/ingest.

Requires a live PostgreSQL database at TEST_DATABASE_URL.
"""

from __future__ import annotations

import os

import pytest
from tests.conftest import minimal_ingest_payload

pytestmark = pytest.mark.skipif(
    not os.environ.get("TEST_DATABASE_URL"),
    reason="TEST_DATABASE_URL not set — skipping integration tests",
)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_returns_201(client):
    response = await client.post("/api/v1/ingest", json=minimal_ingest_payload())
    assert response.status_code == 201


@pytest.mark.asyncio
async def test_ingest_returns_ingestion_id(client):
    response = await client.post("/api/v1/ingest", json=minimal_ingest_payload())
    data = response.json()
    assert "ingestion_id" in data
    assert data["status"] == "received"


@pytest.mark.asyncio
async def test_ingest_with_selected_text(client):
    payload = minimal_ingest_payload(selected_text="I selected this text")
    response = await client.post("/api/v1/ingest", json=payload)
    assert response.status_code == 201


@pytest.mark.asyncio
async def test_ingest_with_hidden_indicators(client):
    payload = minimal_ingest_payload()
    payload["hidden_content_indicators"] = [
        {
            "element_type": "div",
            "indicator_type": "display_none",
            "raw_content_preview": "secret content",
        }
    ]
    response = await client.post("/api/v1/ingest", json=payload)
    assert response.status_code == 201


@pytest.mark.asyncio
async def test_ingest_response_has_x_request_id_header(client):
    response = await client.post("/api/v1/ingest", json=minimal_ingest_payload())
    assert "x-request-id" in response.headers


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_missing_api_key_returns_401(client):
    from httpx import AsyncClient, ASGITransport
    from backend.app.main import create_app

    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as no_key_client:
        response = await no_key_client.post("/api/v1/ingest", json=minimal_ingest_payload())
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_ingest_wrong_api_key_returns_401(client):
    from httpx import AsyncClient, ASGITransport
    from backend.app.main import create_app

    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={"X-API-Key": "definitely-wrong-key"},
    ) as bad_key_client:
        response = await bad_key_client.post("/api/v1/ingest", json=minimal_ingest_payload())
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_missing_page_html_returns_422(client):
    payload = {
        "dom_metadata": {
            "url": "https://example.com",
            "frame_depth": 0,
            "origin": "https://example.com",
        },
        "extension_version": "1.0.0",
        "captured_at": "2026-03-15T12:00:00Z",
    }
    response = await client.post("/api/v1/ingest", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_ingest_missing_dom_metadata_returns_422(client):
    payload = {
        "page_html": "<html><body></body></html>",
        "extension_version": "1.0.0",
        "captured_at": "2026-03-15T12:00:00Z",
    }
    response = await client.post("/api/v1/ingest", json=payload)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_ingest_whitespace_only_selected_text_normalised(client):
    payload = minimal_ingest_payload(selected_text="   ")
    response = await client.post("/api/v1/ingest", json=payload)
    assert response.status_code == 201


# ---------------------------------------------------------------------------
# Health check (no auth required)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_endpoint(client):
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
