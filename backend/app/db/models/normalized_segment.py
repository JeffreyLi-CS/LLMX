"""
ORM model for the `normalized_segments` table.

Each row is one content chunk produced by the normalization pipeline for a
given ingestion.  Segments carry their own provenance, visibility status, and
list of suspicious indicators so that downstream classifiers and policy rules
can reason about each chunk independently.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base

if TYPE_CHECKING:
    from backend.app.db.models.ingestion import IngestionRecord


class NormalizedSegmentRecord(Base):
    __tablename__ = "normalized_segments"

    # ── Primary key ───────────────────────────────────────────────────────────
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # ── Foreign key ───────────────────────────────────────────────────────────
    ingestion_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ingestions.id", ondelete="CASCADE"),
        nullable=False,
    )

    # ── Timestamps ────────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # ── Position within the ingestion ─────────────────────────────────────────
    # Zero-based ordering index — used to reconstruct reading order.
    segment_index: Mapped[int] = mapped_column(Integer, nullable=False)

    # ── Provenance ────────────────────────────────────────────────────────────
    # One of: selected_text | title | meta | html_comment | hidden_element | visible_body
    provenance: Mapped[str] = mapped_column(String(64), nullable=False)

    # Human-readable description of the DOM source, e.g. "h1", "p", "div#nav",
    # "meta[name=description]", "comment@42", "hidden:span.tooltip".
    source_element: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Content ───────────────────────────────────────────────────────────────
    raw_text: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_text: Mapped[str] = mapped_column(Text, nullable=False)

    # ── Visibility ────────────────────────────────────────────────────────────
    # True when the segment originates from a DOM element that is hidden from
    # normal user view (display:none, visibility:hidden, off-screen, etc.).
    hidden: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # ── Suspicious indicator list ─────────────────────────────────────────────
    # JSONB array of SuspiciousIndicator objects (see normalization/models.py).
    # An empty array means no suspicious patterns were detected.
    suspicious_indicators: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    # ── Relationship ──────────────────────────────────────────────────────────
    ingestion: Mapped[IngestionRecord] = relationship(
        "IngestionRecord",
        back_populates="segments",
    )

    __table_args__ = (
        Index("ix_normalized_segments_ingestion_id", "ingestion_id"),
        Index("ix_normalized_segments_provenance", "provenance"),
        Index("ix_normalized_segments_hidden", "hidden"),
    )

    def __repr__(self) -> str:
        return (
            f"<NormalizedSegmentRecord id={self.id} "
            f"ingestion={self.ingestion_id} "
            f"provenance={self.provenance} "
            f"hidden={self.hidden}>"
        )
