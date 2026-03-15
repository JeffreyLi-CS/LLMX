"""Initial schema: ingestions and normalized_segments tables.

Revision ID: 0001
Revises:
Create Date: 2026-03-15
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── ingestions ────────────────────────────────────────────────────────────
    op.create_table(
        "ingestions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        # Source provenance
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("page_title", sa.Text, nullable=True),
        sa.Column("frame_depth", sa.Integer, nullable=False, server_default="0"),
        sa.Column("origin", sa.Text, nullable=False),
        # Raw content
        sa.Column("selected_text", sa.Text, nullable=True),
        sa.Column("page_html", sa.Text, nullable=False),
        # Extension metadata
        sa.Column("extension_version", sa.String(32), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        # Pre-analysis from extension
        sa.Column(
            "hidden_indicator_count",
            sa.Integer,
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "hidden_indicators",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="'[]'::jsonb",
        ),
        # Processing state
        sa.Column(
            "status",
            sa.String(32),
            nullable=False,
            server_default="received",
        ),
        sa.Column("normalization_error", sa.Text, nullable=True),
    )

    op.create_index("ix_ingestions_created_at", "ingestions", ["created_at"])
    op.create_index("ix_ingestions_origin", "ingestions", ["origin"])
    op.create_index("ix_ingestions_status", "ingestions", ["status"])

    # ── normalized_segments ───────────────────────────────────────────────────
    op.create_table(
        "normalized_segments",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "ingestion_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ingestions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("segment_index", sa.Integer, nullable=False),
        sa.Column("provenance", sa.String(64), nullable=False),
        sa.Column("source_element", sa.Text, nullable=True),
        sa.Column("raw_text", sa.Text, nullable=False),
        sa.Column("normalized_text", sa.Text, nullable=False),
        sa.Column(
            "hidden",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "suspicious_indicators",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="'[]'::jsonb",
        ),
    )

    op.create_index(
        "ix_normalized_segments_ingestion_id",
        "normalized_segments",
        ["ingestion_id"],
    )
    op.create_index(
        "ix_normalized_segments_provenance",
        "normalized_segments",
        ["provenance"],
    )
    op.create_index(
        "ix_normalized_segments_hidden",
        "normalized_segments",
        ["hidden"],
    )


def downgrade() -> None:
    op.drop_index("ix_normalized_segments_hidden", table_name="normalized_segments")
    op.drop_index("ix_normalized_segments_provenance", table_name="normalized_segments")
    op.drop_index("ix_normalized_segments_ingestion_id", table_name="normalized_segments")
    op.drop_table("normalized_segments")

    op.drop_index("ix_ingestions_status", table_name="ingestions")
    op.drop_index("ix_ingestions_origin", table_name="ingestions")
    op.drop_index("ix_ingestions_created_at", table_name="ingestions")
    op.drop_table("ingestions")
