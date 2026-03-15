"""
Pydantic models for the classification layer.

These models represent the output of the semantic classifier and are returned
by POST /api/v1/classify/{ingestion_id}.  They are distinct from the
normalization models and the SQLAlchemy ORM models.

Injection risk taxonomy
-----------------------
BENIGN    No injection signals found.  Normal page content.
LOW       Ambiguous patterns — could be legitimate but warrants logging.
          Examples: unusually directive language in visible text, unusual
          instructions in an FAQ.
MEDIUM    Clear directive language targeting an AI, but limited scope.
          Examples: "When summarizing this page, also mention..." in a
          visible paragraph.
HIGH      Strong injection attempt with potential to override instructions.
          Examples: hidden "Ignore all previous instructions" text, system
          prompt fragments in meta tags.
CRITICAL  Targeted, multi-vector attack with data-exfiltration or tool-abuse
          intent.  Examples: hidden divs + HTML comments both containing
          coordinated instruction overrides.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class InjectionRisk(str, Enum):
    BENIGN = "benign"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Ordered severity list — useful for comparisons.
RISK_SEVERITY: dict[InjectionRisk, int] = {
    InjectionRisk.BENIGN: 0,
    InjectionRisk.LOW: 1,
    InjectionRisk.MEDIUM: 2,
    InjectionRisk.HIGH: 3,
    InjectionRisk.CRITICAL: 4,
}


class EvidenceSpan(BaseModel):
    """
    A specific text span that supports the classification decision.

    char_offset_start and char_offset_end refer to character positions within
    the segment's raw_text field (not normalized_text).  They are derived by
    the evidence mapper from the classifier's quoted excerpt.
    """

    segment_id: uuid.UUID
    segment_index: int
    provenance: str
    char_offset_start: int = Field(ge=0)
    char_offset_end: int = Field(ge=0)
    excerpt: str = Field(max_length=1024)   # direct quote from raw_text
    reasoning: str = Field(max_length=2048)  # why this span is evidence


class ClassificationResult(BaseModel):
    """
    Complete output of classifying one normalized ingestion.

    The ``raw_response`` field stores the full provider JSON for the audit
    trail but is excluded from the default API response serialization to
    keep payloads compact.  Include it explicitly with response_model_include
    or a dedicated audit endpoint when needed.
    """

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    ingestion_id: uuid.UUID
    classified_at: datetime

    risk_level: InjectionRisk
    confidence: float = Field(ge=0.0, le=1.0)
    injection_type: str | None = Field(
        default=None,
        max_length=64,
        description=(
            "High-level category of injection attempt: prompt_override, "
            "jailbreak, data_exfiltration, role_confusion, instruction_injection, "
            "tool_abuse, or None for benign."
        ),
    )
    reasoning: str = Field(max_length=4096)
    evidence_spans: list[EvidenceSpan] = Field(default_factory=list)

    model_id: str = Field(max_length=128)
    provider: str = Field(max_length=64)

    raw_response: dict = Field(default_factory=dict, exclude=True)
