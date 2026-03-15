"""
Ingestion service — validates and persists raw extension payloads.
"""

from __future__ import annotations

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config import Settings
from backend.app.db.models.ingestion import IngestionRecord
from backend.app.ingestion.models import IngestionCreate

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class IngestionValidationError(Exception):
    """Raised when the payload violates a server-side limit."""


async def create_ingestion(
    payload: IngestionCreate,
    db: AsyncSession,
    settings: Settings,
) -> IngestionRecord:
    """
    Validate *payload* against server-side limits, persist it, and return the
    newly created IngestionRecord.

    Raises
    ------
    IngestionValidationError
        If the payload exceeds configured size limits.
    """
    # ── Server-side size enforcement ──────────────────────────────────────────
    # Pydantic already enforces the hard-coded caps in the model, but we also
    # enforce the operator-configured limits from Settings so they can be
    # tightened without a code change.
    html_bytes = len(payload.page_html.encode("utf-8"))
    if html_bytes > settings.max_html_size_bytes:
        raise IngestionValidationError(
            f"page_html exceeds the configured limit of "
            f"{settings.max_html_size_bytes} bytes (received {html_bytes})"
        )

    if payload.selected_text is not None:
        st_bytes = len(payload.selected_text.encode("utf-8"))
        if st_bytes > settings.max_selected_text_bytes:
            raise IngestionValidationError(
                f"selected_text exceeds the configured limit of "
                f"{settings.max_selected_text_bytes} bytes (received {st_bytes})"
            )

    # ── Persist ───────────────────────────────────────────────────────────────
    record = IngestionRecord(
        url=payload.dom_metadata.url,
        page_title=payload.dom_metadata.title,
        frame_depth=payload.dom_metadata.frame_depth,
        origin=payload.dom_metadata.origin,
        selected_text=payload.selected_text,
        page_html=payload.page_html,
        extension_version=payload.extension_version,
        captured_at=payload.captured_at,
        hidden_indicator_count=len(payload.hidden_content_indicators),
        hidden_indicators=[
            ind.model_dump(mode="json") for ind in payload.hidden_content_indicators
        ],
        status="received",
    )

    db.add(record)
    await db.flush()  # flush to get the generated id without committing

    logger.info(
        "ingestion.created",
        ingestion_id=str(record.id),
        url=payload.dom_metadata.url,
        origin=payload.dom_metadata.origin,
        frame_depth=payload.dom_metadata.frame_depth,
        html_bytes=html_bytes,
        hidden_indicator_count=record.hidden_indicator_count,
    )

    return record
