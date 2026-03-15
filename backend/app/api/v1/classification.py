"""
POST /api/v1/classify/{ingestion_id}

Runs the semantic classifier on a previously normalized ingestion and persists
the result.  Returns 409 if already classified, 503 if the OpenAI key is not
configured.

Authentication: X-API-Key header.
"""

from __future__ import annotations

import uuid
from typing import Annotated

import structlog
from fastapi import APIRouter, HTTPException, Path, status

from backend.app.classification.models import ClassificationResult
from backend.app.classification.service import ClassificationError, classify_ingestion
from backend.app.dependencies import DBSession, RequireAPIKey, SettingsDep

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

router = APIRouter(tags=["classification"])

IngestionIDPath = Annotated[uuid.UUID, Path(description="UUID returned by POST /ingest")]


def _get_provider(settings):
    """
    Instantiate the configured classifier provider.

    Raises HTTP 503 if the required credentials are absent.
    """
    from backend.app.classification.providers.openai import OpenAIClassifierProvider

    if not settings.openai_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Classification is not configured: OPENAI_API_KEY is not set. "
                "Set the environment variable and restart the server."
            ),
        )
    return OpenAIClassifierProvider(
        api_key=settings.openai_api_key,
        model=settings.classifier_model,
        max_tokens=settings.max_classification_tokens,
        timeout=settings.classifier_timeout_s,
    )


@router.post(
    "/classify/{ingestion_id}",
    response_model=ClassificationResult,
    status_code=status.HTTP_200_OK,
    dependencies=[RequireAPIKey],
    summary="Classify a normalized ingestion for prompt injection",
    description=(
        "Runs the semantic classifier on all normalized segments of the given "
        "ingestion.  The ingestion must be in 'normalized' state.  Returns 409 "
        "if already classified, 503 if no OpenAI API key is configured."
    ),
)
async def classify(
    ingestion_id: IngestionIDPath,
    db: DBSession,
    settings: SettingsDep,
) -> ClassificationResult:
    provider = _get_provider(settings)

    try:
        result = await classify_ingestion(
            ingestion_id=ingestion_id,
            db=db,
            provider=provider,
        )
    except ClassificationError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=msg,
            ) from exc
        if "already been classified" in msg.lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=msg,
            ) from exc
        if "cannot be classified" in msg.lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=msg,
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Classification failed: {msg}",
        ) from exc

    return result


@router.get(
    "/classify/{ingestion_id}",
    response_model=ClassificationResult,
    status_code=status.HTTP_200_OK,
    dependencies=[RequireAPIKey],
    summary="Retrieve the classification result for an ingestion",
    description=(
        "Returns the most recent classification result for the given ingestion. "
        "Returns 404 if the ingestion has not been classified yet."
    ),
)
async def get_classification(
    ingestion_id: IngestionIDPath,
    db: DBSession,
) -> ClassificationResult:
    from sqlalchemy import select
    from backend.app.db.models.classification import ClassificationRecord

    result = await db.execute(
        select(ClassificationRecord)
        .where(ClassificationRecord.ingestion_id == ingestion_id)
        .order_by(ClassificationRecord.created_at.desc())
        .limit(1)
    )
    rec = result.scalar_one_or_none()

    if rec is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No classification result found for ingestion {ingestion_id}",
        )

    # Re-load evidence spans as typed models.
    from backend.app.classification.models import EvidenceSpan

    evidence_spans = [EvidenceSpan(**s) for s in (rec.evidence_spans or [])]

    from backend.app.classification.models import InjectionRisk

    return ClassificationResult(
        id=rec.id,
        ingestion_id=rec.ingestion_id,
        classified_at=rec.created_at,
        risk_level=InjectionRisk(rec.risk_level),
        confidence=rec.confidence,
        injection_type=rec.injection_type,
        reasoning=rec.reasoning,
        evidence_spans=evidence_spans,
        model_id=rec.model_id,
        provider=rec.provider,
        raw_response=rec.raw_response or {},
    )
