"""
ORM model registry.

Importing this package ensures all mapped classes are registered with the
Base metadata, which is required for Alembic autogenerate to work correctly.
"""

from backend.app.db.models.classification import ClassificationRecord  # noqa: F401
from backend.app.db.models.ingestion import IngestionRecord  # noqa: F401
from backend.app.db.models.normalized_segment import NormalizedSegmentRecord  # noqa: F401

__all__ = ["ClassificationRecord", "IngestionRecord", "NormalizedSegmentRecord"]
