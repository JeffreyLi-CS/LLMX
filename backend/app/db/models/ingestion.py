"""
ORM model for the `ingestions` table.

Each row represents one raw payload received from the browser extension.
The `status` column tracks the processing lifecycle:

    received    — stored but not yet normalised
    normalizing — normalization is in progress
    normalized  — normalization completed successfully
    error       — normalization failed; see normalization_error for detail
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base

if TYPE_CHECKING:
    from backend.app.db.models.normalized_segment import NormalizedSegmentRecord

VALID_STATUSES = {"received", "normalizing", "normalized", "error"}


class IngestionRecord(Base):
    __tablename__ = "ingestions"

    # ── Primary key ───────────────────────────────────────────────────────────
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # ── Timestamps ────────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # ── Source provenance ─────────────────────────────────────────────────────
    url: Mapped[str] = mapped_column(Text, nullable=False)
    page_title: Mapped[str | None] = mapped_column(Text, nullable=True)
    frame_depth: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    origin: Mapped[str] = mapped_column(Text, nullable=False)

    # ── Raw content ───────────────────────────────────────────────────────────
    # selected_text is optional: the user may not have selected anything.
    selected_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    page_html: Mapped[str] = mapped_column(Text, nullable=False)

    # ── Extension metadata ────────────────────────────────────────────────────
    extension_version: Mapped[str] = mapped_column(String(32), nullable=False)
    # Timestamp reported by the extension (client clock — not authoritative).
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # ── Pre-analysis from extension ───────────────────────────────────────────
    # The extension may pre-identify suspicious hidden content.  We store these
    # as-is; they are NOT authoritative — the normalization pipeline performs
    # its own independent analysis.
    hidden_indicator_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    hidden_indicators: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    # ── Processing state ──────────────────────────────────────────────────────
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="received",
        index=True,
    )
    normalization_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Relationships ─────────────────────────────────────────────────────────
    segments: Mapped[list[NormalizedSegmentRecord]] = relationship(
        "NormalizedSegmentRecord",
        back_populates="ingestion",
        cascade="all, delete-orphan",
        order_by="NormalizedSegmentRecord.segment_index",
    )

    __table_args__ = (
        Index("ix_ingestions_created_at", "created_at"),
        Index("ix_ingestions_origin", "origin"),
    )

    def __repr__(self) -> str:
        return f"<IngestionRecord id={self.id} status={self.status}>"
