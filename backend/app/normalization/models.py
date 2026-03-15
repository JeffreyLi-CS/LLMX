"""
Pydantic models for the normalization layer.

These are the canonical data shapes used between pipeline stages and returned
by the API.  They are distinct from the SQLAlchemy ORM models in db/models/.
"""

from __future__ import annotations

import uuid
from enum import Enum

from pydantic import BaseModel, Field


class Provenance(str, Enum):
    """Origin of a normalized segment within the source document."""

    SELECTED_TEXT = "selected_text"
    TITLE = "title"
    META = "meta"
    HTML_COMMENT = "html_comment"
    HIDDEN_ELEMENT = "hidden_element"
    VISIBLE_BODY = "visible_body"


class SuspiciousIndicatorType(str, Enum):
    """Category of a suspicious pattern found within a text segment."""

    UNICODE_CONTROL = "unicode_control"
    UNICODE_DIRECTIONAL_OVERRIDE = "unicode_directional_override"
    UNICODE_PRIVATE_USE = "unicode_private_use"
    POSSIBLE_BASE64 = "possible_base64"
    POSSIBLE_PERCENT_ENCODING = "possible_percent_encoding"
    POSSIBLE_HEX_ESCAPE = "possible_hex_escape"
    POSSIBLE_UNICODE_ESCAPE = "possible_unicode_escape"
    POSSIBLE_HTML_ENTITY_CLUSTER = "possible_html_entity_cluster"
    POSSIBLE_DATA_URI = "possible_data_uri"


class SuspiciousIndicator(BaseModel):
    """
    A single suspicious pattern located within a text segment.

    char_offset_start / char_offset_end refer to byte-offsets within the
    `raw_text` of the owning NormalizedSegment.

    This model deliberately avoids claiming to have decoded the content.
    The indicator is evidence of a pattern that *could* be an obfuscation
    attempt; classification is deferred to the classification pipeline.
    """

    indicator_type: SuspiciousIndicatorType
    description: str
    char_offset_start: int = Field(ge=0)
    char_offset_end: int = Field(ge=0)
    raw_value: str = Field(max_length=512)  # truncated excerpt of the suspicious span


class NormalizedSegment(BaseModel):
    """
    One normalized content chunk with full provenance.
    Produced by the normalization pipeline; persisted to normalized_segments.
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    segment_index: int = Field(ge=0)
    provenance: Provenance
    source_element: str | None = None

    raw_text: str
    normalized_text: str

    hidden: bool = False
    suspicious_indicators: list[SuspiciousIndicator] = Field(default_factory=list)

    @property
    def char_count(self) -> int:
        return len(self.normalized_text)

    @property
    def has_suspicious_content(self) -> bool:
        return len(self.suspicious_indicators) > 0


class NormalizationResult(BaseModel):
    """
    Complete output of running the normalization pipeline on one ingestion.
    """

    ingestion_id: uuid.UUID
    segment_count: int
    hidden_segment_count: int
    suspicious_segment_count: int
    segments: list[NormalizedSegment]
