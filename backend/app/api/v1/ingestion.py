"""
POST /api/v1/ingest

Receives a raw capture payload from the browser extension, validates it,
and stores it as a new IngestionRecord.

Authentication: X-API-Key header (constant-time comparison, see dependencies.py).
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status

from backend.app.dependencies import DBSession, RequireAPIKey, SettingsDep
from backend.app.ingestion.models import IngestionCreate, IngestionResponse
from backend.app.ingestion.service import IngestionValidationError, create_ingestion

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

router = APIRouter(tags=["ingestion"])


@router.post(
    "/ingest",
    response_model=IngestionResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[RequireAPIKey],
    summary="Ingest a raw browser capture",
    description=(
        "Accepts a structured payload from the browser extension containing "
        "the page HTML, optional selected text, DOM metadata, and any hidden "
        "content indicators pre-identified by the extension. "
        "Returns an ingestion_id for subsequent normalization."
    ),
)
async def ingest(
    request: Request,
    payload: IngestionCreate,
    db: DBSession,
    settings: SettingsDep,
) -> IngestionResponse:
    try:
        record = await create_ingestion(payload=payload, db=db, settings=settings)
    except IngestionValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    return IngestionResponse(
        ingestion_id=record.id,
        status=record.status,
        message="Ingestion received. POST to /api/v1/normalize/{ingestion_id} to normalize.",
    )
