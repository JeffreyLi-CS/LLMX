"""
Integration tests for POST /api/v1/normalize/{ingestion_id}.

Requires a live PostgreSQL database at TEST_DATABASE_URL.
"""

from __future__ import annotations

import os
import uuid

import pytest
from tests.conftest import minimal_ingest_payload

pytestmark = pytest.mark.skipif(
    not os.environ.get("TEST_DATABASE_URL"),
    reason="TEST_DATABASE_URL not set — skipping integration tests",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def ingest(client, page_html: str, selected_text: str | None = None) -> str:
    """Ingest a page and return the ingestion_id."""
    payload = minimal_ingest_payload(page_html=page_html, selected_text=selected_text)
    resp = await client.post("/api/v1/ingest", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()["ingestion_id"]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_normalize_returns_200(client):
    iid = await ingest(client, "<html><body><p>Hello world</p></body></html>")
    response = await client.post(f"/api/v1/normalize/{iid}")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_normalize_returns_segments(client):
    iid = await ingest(client, "<html><body><p>Hello world</p></body></html>")
    response = await client.post(f"/api/v1/normalize/{iid}")
    data = response.json()
    assert "segments" in data
    assert isinstance(data["segments"], list)
    assert len(data["segments"]) > 0


@pytest.mark.asyncio
async def test_normalize_result_contains_ingestion_id(client):
    iid = await ingest(client, "<html><body><p>text</p></body></html>")
    response = await client.post(f"/api/v1/normalize/{iid}")
    assert response.json()["ingestion_id"] == iid


@pytest.mark.asyncio
async def test_normalize_with_selected_text(client):
    iid = await ingest(
        client,
        "<html><body><p>page content</p></body></html>",
        selected_text="selected portion",
    )
    response = await client.post(f"/api/v1/normalize/{iid}")
    data = response.json()
    segments = data["segments"]
    sel = [s for s in segments if s["provenance"] == "selected_text"]
    assert len(sel) == 1
    assert "selected portion" in sel[0]["raw_text"]


@pytest.mark.asyncio
async def test_normalize_hidden_element_flagged(client):
    html = '<html><body><div style="display:none">hidden payload</div><p>visible</p></body></html>'
    iid = await ingest(client, html)
    response = await client.post(f"/api/v1/normalize/{iid}")
    segments = response.json()["segments"]
    hidden_segs = [s for s in segments if s["hidden"] is True]
    assert len(hidden_segs) >= 1
    assert any("hidden payload" in s["raw_text"] for s in hidden_segs)


@pytest.mark.asyncio
async def test_normalize_suspicious_indicators_present(client):
    # Zero-width space inside visible text should produce an indicator.
    html = "<html><body><p>Normal\u200b text with zwsp</p></body></html>"
    iid = await ingest(client, html)
    response = await client.post(f"/api/v1/normalize/{iid}")
    segments = response.json()["segments"]
    all_indicators = [i for s in segments for i in s.get("suspicious_indicators", [])]
    assert any(i["indicator_type"] == "unicode_control" for i in all_indicators)


@pytest.mark.asyncio
async def test_normalize_updates_segment_counts(client):
    html = '<html><body><div hidden>h</div><p>v1</p><p>v2</p></body></html>'
    iid = await ingest(client, html)
    response = await client.post(f"/api/v1/normalize/{iid}")
    data = response.json()
    assert data["segment_count"] == len(data["segments"])
    assert data["hidden_segment_count"] >= 1


@pytest.mark.asyncio
async def test_normalize_segment_indices_sequential(client):
    iid = await ingest(client, "<html><body><p>a</p><p>b</p></body></html>")
    response = await client.post(f"/api/v1/normalize/{iid}")
    segments = response.json()["segments"]
    indices = [s["segment_index"] for s in segments]
    assert indices == list(range(len(indices)))


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_normalize_unknown_id_returns_404(client):
    fake_id = str(uuid.uuid4())
    response = await client.post(f"/api/v1/normalize/{fake_id}")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_normalize_already_normalized_returns_409(client):
    iid = await ingest(client, "<html><body><p>once</p></body></html>")
    first = await client.post(f"/api/v1/normalize/{iid}")
    assert first.status_code == 200
    second = await client.post(f"/api/v1/normalize/{iid}")
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_normalize_invalid_uuid_returns_422(client):
    response = await client.post("/api/v1/normalize/not-a-uuid")
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Retry endpoint
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_retry_non_error_state_returns_409(client):
    """Retrying a freshly-ingested (received) record must return 409."""
    iid = await ingest(client, "<html><body><p>hello</p></body></html>")
    response = await client.post(f"/api/v1/normalize/{iid}/retry")
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_retry_already_normalized_returns_409(client):
    """Retrying a successfully-normalized record must return 409."""
    iid = await ingest(client, "<html><body><p>hello</p></body></html>")
    first = await client.post(f"/api/v1/normalize/{iid}")
    assert first.status_code == 200
    retry = await client.post(f"/api/v1/normalize/{iid}/retry")
    assert retry.status_code == 409


@pytest.mark.asyncio
async def test_retry_unknown_id_returns_404(client):
    import uuid
    fake_id = str(uuid.uuid4())
    response = await client.post(f"/api/v1/normalize/{fake_id}/retry")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_normalize_missing_api_key_returns_401(client):
    from httpx import AsyncClient, ASGITransport
    from backend.app.main import create_app

    iid = await ingest(client, "<html><body></body></html>")
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as no_key_client:
        response = await no_key_client.post(f"/api/v1/normalize/{iid}")
    assert response.status_code == 401
