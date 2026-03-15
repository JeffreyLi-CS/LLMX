"""Add classification_results table.

Revision ID: 0002
Revises: 0001
Create Date: 2026-03-15
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "classification_results",
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
        # Classification output
        sa.Column("risk_level", sa.String(16), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False),
        sa.Column("injection_type", sa.String(64), nullable=True),
        sa.Column("reasoning", sa.Text, nullable=False),
        sa.Column(
            "evidence_spans",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        # Provider metadata
        sa.Column("model_id", sa.String(128), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column(
            "raw_response",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )

    op.create_index(
        "ix_classification_ingestion_id",
        "classification_results",
        ["ingestion_id"],
    )
    op.create_index(
        "ix_classification_risk_level",
        "classification_results",
        ["risk_level"],
    )
    op.create_index(
        "ix_classification_created_at",
        "classification_results",
        ["created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_classification_created_at", table_name="classification_results")
    op.drop_index("ix_classification_risk_level", table_name="classification_results")
    op.drop_index("ix_classification_ingestion_id", table_name="classification_results")
    op.drop_table("classification_results")
