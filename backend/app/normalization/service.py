"""
Normalization service — orchestrates the pipeline and persists results.

This is the only module that combines pipeline logic with database writes.
Routes should call this service rather than the pipeline directly.
"""

from __future__ import annotations

import uuid

import structlog
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.db.models.ingestion import IngestionRecord
from backend.app.db.models.normalized_segment import NormalizedSegmentRecord
from backend.app.metrics import REGISTRY, timed
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
    REGISTRY.increment("normalize_requests_total")

    # ── Fetch the ingestion (row-level lock to prevent concurrent re-runs) ────
    # with_for_update() acquires a SELECT FOR UPDATE lock so that a second
    # concurrent request for the same ingestion_id waits rather than running
    # the pipeline twice.  The lock is held for the duration of the transaction.
    result = await db.execute(
        select(IngestionRecord)
        .where(IngestionRecord.id == ingestion_id)
        .with_for_update()
    )
    record: IngestionRecord | None = result.scalar_one_or_none()

    if record is None:
        REGISTRY.increment("normalize_errors_total")
        raise NormalizationError(f"Ingestion {ingestion_id} not found")

    if record.status == "normalizing":
        REGISTRY.increment("normalize_errors_total")
        raise NormalizationError(
            f"Ingestion {ingestion_id} is already being normalised"
        )

    if record.status == "normalized":
        REGISTRY.increment("normalize_errors_total")
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
        with timed("normalization_duration_s"):
            norm_result = run_normalization_pipeline(
                ingestion_id=ingestion_id,
                page_html=record.page_html,
                selected_text=record.selected_text,
                max_segments=max_segments,
            )
    except Exception as exc:
        REGISTRY.increment("normalize_errors_total")
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

    REGISTRY.observe("segments_per_ingestion", float(len(db_segments)))

    logger.info(
        "normalization.persisted",
        ingestion_id=str(ingestion_id),
        segment_count=len(db_segments),
    )

    return norm_result


async def retry_normalize_ingestion(
    ingestion_id: uuid.UUID,
    db: AsyncSession,
    max_segments: int = 2000,
) -> NormalizationResult:
    """
    Retry normalization for an ingestion that previously failed with status
    ``error``.

    Before re-running, any partially-written normalized_segments rows for this
    ingestion are deleted.  This guards against duplicate-key errors that would
    occur if the pipeline had flushed some segments before the error was
    recorded.  Only ingestions in ``error`` state are accepted; all other
    states raise ``NormalizationError``.
    """
    REGISTRY.increment("normalize_retry_total")

    result = await db.execute(
        select(IngestionRecord)
        .where(IngestionRecord.id == ingestion_id)
        .with_for_update()
    )
    record: IngestionRecord | None = result.scalar_one_or_none()

    if record is None:
        raise NormalizationError(f"Ingestion {ingestion_id} not found")

    if record.status != "error":
        raise NormalizationError(
            f"Ingestion {ingestion_id} cannot be retried: status is '{record.status}' "
            "(only 'error' state ingestions can be retried)"
        )

    logger.info(
        "normalization.retry.started",
        ingestion_id=str(ingestion_id),
        previous_error=record.normalization_error,
    )

    # ── Defensive cleanup ─────────────────────────────────────────────────────
    # A pipeline crash after partial segment flush leaves orphaned rows in
    # normalized_segments.  DELETE them before resetting status so the main
    # normalization path cannot hit a unique-constraint violation on
    # (ingestion_id, segment_index).
    deleted = await db.execute(
        delete(NormalizedSegmentRecord).where(
            NormalizedSegmentRecord.ingestion_id == ingestion_id
        )
    )
    orphan_count: int = deleted.rowcount  # type: ignore[assignment]
    if orphan_count:
        logger.warning(
            "normalization.retry.orphans_deleted",
            ingestion_id=str(ingestion_id),
            orphan_count=orphan_count,
        )

    record.status = "received"
    record.normalization_error = None
    await db.flush()

    # Delegate to the main normalization function; the record is now in
    # "received" state so it will proceed through the normal path.
    return await normalize_ingestion(
        ingestion_id=ingestion_id,
        db=db,
        max_segments=max_segments,
    )
