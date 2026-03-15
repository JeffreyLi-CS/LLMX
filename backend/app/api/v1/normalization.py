"""
POST /api/v1/normalize/{ingestion_id}

Triggers the normalization pipeline for a previously ingested payload and
returns the resulting normalized segments.

The endpoint is synchronous for v1 — normalization runs inline within the
request.  A future version can return 202 Accepted and process asynchronously
via a Celery worker without changing the response schema.

Authentication: X-API-Key header.
"""

from __future__ import annotations

import uuid
from typing import Annotated

import structlog
from fastapi import APIRouter, HTTPException, Path, status

from backend.app.dependencies import DBSession, RequireAPIKey, SettingsDep
from backend.app.normalization.models import NormalizationResult
from backend.app.normalization.service import NormalizationError, normalize_ingestion

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

router = APIRouter(tags=["normalization"])

IngestionIDPath = Annotated[uuid.UUID, Path(description="UUID returned by POST /ingest")]


@router.post(
    "/normalize/{ingestion_id}",
    response_model=NormalizationResult,
    status_code=status.HTTP_200_OK,
    dependencies=[RequireAPIKey],
    summary="Normalize an ingested payload",
    description=(
        "Runs the normalization pipeline on a previously stored ingestion: "
        "HTML parsing, whitespace and unicode normalization, "
        "suspicious-character detection, and obfuscation pattern detection. "
        "Returns all normalized segments with provenance and evidence spans."
    ),
)
async def normalize(
    ingestion_id: IngestionIDPath,
    db: DBSession,
    settings: SettingsDep,
) -> NormalizationResult:
    try:
        result = await normalize_ingestion(
            ingestion_id=ingestion_id,
            db=db,
            max_segments=settings.max_segments_per_ingestion,
        )
    except NormalizationError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=msg,
            ) from exc
        if "already" in msg.lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=msg,
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Normalization failed: {msg}",
        ) from exc

    return result
