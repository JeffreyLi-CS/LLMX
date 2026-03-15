"""
Abstract base class for classifier providers.

Each provider wraps one LLM backend (OpenAI, Anthropic, local Ollama, etc.)
and translates its raw response into the structured ClassificationOutput schema.

The classification service selects a provider based on Settings.classifier_provider
and calls classify().  Adding a new backend only requires implementing this
interface and registering the provider name in the factory.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from pydantic import BaseModel, Field

from backend.app.classification.models import EvidenceSpan, InjectionRisk
from backend.app.normalization.models import NormalizedSegment


class ClassifierInput(BaseModel):
    """All information passed to a classifier provider for one ingestion."""

    ingestion_id: uuid.UUID
    page_url: str = ""
    page_title: str | None = None
    segments: list[NormalizedSegment]


class RawEvidence(BaseModel):
    """
    Evidence item as emitted by the provider, before offset resolution.

    Segment reference is by index (not UUID) because the LLM works with the
    text representation, not database IDs.
    """

    segment_index: int
    excerpt: str = Field(max_length=1024)
    reasoning: str = Field(max_length=2048)


class ClassificationOutput(BaseModel):
    """
    Structured output from a provider classify() call.

    This is an intermediate model.  The classification service combines it with
    evidence-span mapping and DB persistence to produce a ClassificationResult.
    """

    risk_level: InjectionRisk
    confidence: float = Field(ge=0.0, le=1.0)
    injection_type: str | None = None
    raw_evidence: list[RawEvidence] = Field(default_factory=list)
    reasoning: str
    raw_response: dict = Field(default_factory=dict)


class AbstractClassifierProvider(ABC):
    """
    Interface all classifier providers must implement.

    Providers are stateless (no DB access, no request context) and communicate
    exclusively through ClassifierInput / ClassificationOutput.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Identifier string stored in classification_results.provider."""
        ...

    @property
    @abstractmethod
    def model_id(self) -> str:
        """Model identifier string stored in classification_results.model_id."""
        ...

    @abstractmethod
    async def classify(self, inp: ClassifierInput) -> ClassificationOutput:
        """
        Classify the segments in *inp* and return a structured output.

        Must not raise on provider-level errors — instead encode the failure in
        a BENIGN result with a descriptive reasoning string and confidence=0.0,
        so the service layer can decide whether to retry or surface the error.
        """
        ...
