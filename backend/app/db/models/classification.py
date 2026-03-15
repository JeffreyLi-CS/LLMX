"""
ORM model for the `classification_results` table.

Each row represents one classifier run on a normalized ingestion.  The
ingestion can be re-classified (e.g. with a different model) producing
multiple rows, ordered by created_at.  The API always returns the most recent
result unless a specific result_id is requested.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base


class ClassificationRecord(Base):
    __tablename__ = "classification_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    ingestion_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ingestions.id", ondelete="CASCADE"),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # ── Classification output ──────────────────────────────────────────────────
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    injection_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reasoning: Mapped[str] = mapped_column(Text, nullable=False)

    # JSONB array of EvidenceSpan objects (serialized from Pydantic models).
    evidence_spans: Mapped[list] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )

    # ── Provider metadata ─────────────────────────────────────────────────────
    model_id: Mapped[str] = mapped_column(String(128), nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)

    # Full provider JSON response for audit purposes.
    raw_response: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )

    __table_args__ = (
        Index("ix_classification_ingestion_id", "ingestion_id"),
        Index("ix_classification_risk_level", "risk_level"),
        Index("ix_classification_created_at", "created_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<ClassificationRecord id={self.id} "
            f"ingestion={self.ingestion_id} "
            f"risk={self.risk_level}>"
        )
