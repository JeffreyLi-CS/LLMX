"""
Classification service — orchestrates provider calls and persists results.

Flow for POST /classify/{ingestion_id}:
  1. Fetch the ingestion record; verify status == "normalized".
  2. Load all normalized segments for this ingestion (ordered by segment_index).
  3. Check for an existing classification result and raise ClassificationError
     if one exists (the caller must use the retry endpoint to re-classify).
  4. Call the configured classifier provider.
  5. Map evidence excerpts to character offsets in raw_text.
  6. Persist the ClassificationRecord.
  7. Return the ClassificationResult Pydantic model.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.classification.evidence import map_evidence_spans
from backend.app.classification.models import ClassificationResult, EvidenceSpan
from backend.app.classification.providers.base import (
    AbstractClassifierProvider,
    ClassifierInput,
)
from backend.app.db.models.classification import ClassificationRecord
from backend.app.db.models.ingestion import IngestionRecord
from backend.app.db.models.normalized_segment import NormalizedSegmentRecord
from backend.app.metrics import REGISTRY, timed
from backend.app.normalization.models import (
    NormalizedSegment,
    Provenance,
    SuspiciousIndicator,
    SuspiciousIndicatorType,
)

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class ClassificationError(Exception):
    """Raised when classification cannot proceed."""


async def classify_ingestion(
    ingestion_id: uuid.UUID,
    db: AsyncSession,
    provider: AbstractClassifierProvider,
) -> ClassificationResult:
    """
    Classify a normalized ingestion and persist the result.

    Raises
    ------
    ClassificationError
        If the ingestion is not found, not yet normalized, or has already been
        classified.
    """
    REGISTRY.increment("classify_requests_total")

    # ── 1. Fetch the ingestion ────────────────────────────────────────────────
    ing_result = await db.execute(
        select(IngestionRecord).where(IngestionRecord.id == ingestion_id)
    )
    record: IngestionRecord | None = ing_result.scalar_one_or_none()

    if record is None:
        raise ClassificationError(f"Ingestion {ingestion_id} not found")

    if record.status != "normalized":
        raise ClassificationError(
            f"Ingestion {ingestion_id} cannot be classified: "
            f"status is '{record.status}' (must be 'normalized')"
        )

    # ── 2. Check for existing classification ─────────────────────────────────
    existing = await db.execute(
        select(ClassificationRecord)
        .where(ClassificationRecord.ingestion_id == ingestion_id)
        .limit(1)
    )
    if existing.scalar_one_or_none() is not None:
        raise ClassificationError(
            f"Ingestion {ingestion_id} has already been classified. "
            "Use the retry endpoint to re-classify."
        )

    # ── 3. Load normalized segments ───────────────────────────────────────────
    segs_result = await db.execute(
        select(NormalizedSegmentRecord)
        .where(NormalizedSegmentRecord.ingestion_id == ingestion_id)
        .order_by(NormalizedSegmentRecord.segment_index)
    )
    seg_records = segs_result.scalars().all()

    if not seg_records:
        raise ClassificationError(
            f"Ingestion {ingestion_id} has no normalized segments — cannot classify"
        )

    # Reconstruct Pydantic NormalizedSegment objects for the provider.
    segments: list[NormalizedSegment] = [
        _record_to_segment(r) for r in seg_records
    ]

    # ── 4. Call the provider ──────────────────────────────────────────────────
    inp = ClassifierInput(
        ingestion_id=ingestion_id,
        page_url=record.url,
        page_title=record.page_title,
        segments=segments,
    )

    try:
        with timed("classification_duration_s"):
            output = await provider.classify(inp)
    except Exception as exc:
        REGISTRY.increment("classify_errors_total")
        logger.error(
            "classification.provider.failed",
            ingestion_id=str(ingestion_id),
            provider=provider.provider_name,
            error=str(exc),
            exc_info=True,
        )
        raise ClassificationError(f"Provider error: {exc}") from exc

    # ── 5. Map evidence spans ─────────────────────────────────────────────────
    raw_ev_dicts = [e.model_dump() for e in output.raw_evidence]
    evidence_spans: list[EvidenceSpan] = map_evidence_spans(raw_ev_dicts, segments)

    # ── 6. Persist ────────────────────────────────────────────────────────────
    classified_at = datetime.now(timezone.utc)
    result_id = uuid.uuid4()

    db_record = ClassificationRecord(
        id=result_id,
        ingestion_id=ingestion_id,
        risk_level=output.risk_level.value,
        confidence=output.confidence,
        injection_type=output.injection_type,
        reasoning=output.reasoning,
        evidence_spans=[s.model_dump(mode="json") for s in evidence_spans],
        model_id=provider.model_id,
        provider=provider.provider_name,
        raw_response=output.raw_response,
    )
    db.add(db_record)
    await db.flush()

    logger.info(
        "classification.persisted",
        ingestion_id=str(ingestion_id),
        result_id=str(result_id),
        risk_level=output.risk_level.value,
        confidence=output.confidence,
        evidence_count=len(evidence_spans),
        provider=provider.provider_name,
        model=provider.model_id,
    )

    return ClassificationResult(
        id=result_id,
        ingestion_id=ingestion_id,
        classified_at=classified_at,
        risk_level=output.risk_level,
        confidence=output.confidence,
        injection_type=output.injection_type,
        reasoning=output.reasoning,
        evidence_spans=evidence_spans,
        model_id=provider.model_id,
        provider=provider.provider_name,
        raw_response=output.raw_response,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _record_to_segment(r: NormalizedSegmentRecord) -> NormalizedSegment:
    """Reconstruct a NormalizedSegment Pydantic model from an ORM record."""
    indicators: list[SuspiciousIndicator] = []
    for raw in (r.suspicious_indicators or []):
        try:
            indicators.append(
                SuspiciousIndicator(
                    indicator_type=SuspiciousIndicatorType(raw["indicator_type"]),
                    description=raw.get("description", ""),
                    char_offset_start=raw.get("char_offset_start", 0),
                    char_offset_end=raw.get("char_offset_end", 0),
                    raw_value=raw.get("raw_value", "")[:512],
                )
            )
        except (KeyError, ValueError):
            pass  # Corrupt indicator row — skip rather than crash.

    return NormalizedSegment(
        id=r.id,
        segment_index=r.segment_index,
        provenance=Provenance(r.provenance),
        source_element=r.source_element,
        raw_text=r.raw_text,
        normalized_text=r.normalized_text,
        hidden=r.hidden,
        suspicious_indicators=indicators,
    )
