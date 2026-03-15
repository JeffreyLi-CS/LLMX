"""
Normalization service — orchestrates the pipeline and persists results.

This is the only module that combines pipeline logic with database writes.
Routes should call this service rather than the pipeline directly.
"""

from __future__ import annotations

import uuid

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.db.models.ingestion import IngestionRecord
from backend.app.db.models.normalized_segment import NormalizedSegmentRecord
from backend.app.normalization.models import NormalizationResult
from backend.app.normalization.pipeline import run_normalization_pipeline

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class NormalizationError(Exception):
    """Raised when normalization cannot proceed due to invalid state."""


async def normalize_ingestion(
    ingestion_id: uuid.UUID,
    db: AsyncSession,
    max_segments: int = 2000,
) -> NormalizationResult:
    """
    Run the normalization pipeline for the given ingestion and persist results.

    Raises
    ------
    NormalizationError
        If the ingestion is not found or is in an invalid state for
        normalization.
    """
    # ── Fetch the ingestion (row-level lock to prevent concurrent re-runs) ────
    # with_for_update() acquires a SELECT FOR UPDATE lock so that a second
    # concurrent request for the same ingestion_id waits rather than running
    # the pipeline twice.  The lock is held for the duration of the transaction.
    result = await db.execute(
        select(IngestionRecord)
        .where(IngestionRecord.id == ingestion_id)
        .options(selectinload(IngestionRecord.segments))
        .with_for_update()
    )
    record: IngestionRecord | None = result.scalar_one_or_none()

    if record is None:
        raise NormalizationError(f"Ingestion {ingestion_id} not found")

    if record.status == "normalizing":
        raise NormalizationError(
            f"Ingestion {ingestion_id} is already being normalised"
        )

    if record.status == "normalized":
        raise NormalizationError(
            f"Ingestion {ingestion_id} has already been normalised. "
            "Delete existing segments and reset status to re-run."
        )

    # ── Mark as in-progress ───────────────────────────────────────────────────
    record.status = "normalizing"
    record.normalization_error = None
    await db.flush()

    # ── Run pipeline ──────────────────────────────────────────────────────────
    try:
        norm_result = run_normalization_pipeline(
            ingestion_id=ingestion_id,
            page_html=record.page_html,
            selected_text=record.selected_text,
            max_segments=max_segments,
        )
    except Exception as exc:
        record.status = "error"
        record.normalization_error = str(exc)
        await db.flush()
        logger.error(
            "normalization.pipeline.failed",
            ingestion_id=str(ingestion_id),
            error=str(exc),
            exc_info=True,
        )
        raise NormalizationError(f"Pipeline failed: {exc}") from exc

    # ── Persist segments ──────────────────────────────────────────────────────
    db_segments: list[NormalizedSegmentRecord] = []
    for seg in norm_result.segments:
        db_segments.append(
            NormalizedSegmentRecord(
                id=seg.id,
                ingestion_id=ingestion_id,
                segment_index=seg.segment_index,
                provenance=seg.provenance.value,
                source_element=seg.source_element,
                raw_text=seg.raw_text,
                normalized_text=seg.normalized_text,
                hidden=seg.hidden,
                suspicious_indicators=[
                    ind.model_dump(mode="json") for ind in seg.suspicious_indicators
                ],
            )
        )

    db.add_all(db_segments)

    # ── Mark as complete ──────────────────────────────────────────────────────
    record.status = "normalized"
    await db.flush()

    logger.info(
        "normalization.persisted",
        ingestion_id=str(ingestion_id),
        segment_count=len(db_segments),
    )

    return norm_result
