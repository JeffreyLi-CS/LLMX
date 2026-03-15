"""
Pydantic models for the ingestion API layer.

These define the wire format for the POST /api/v1/ingest endpoint.  They are
distinct from the SQLAlchemy ORM models in db/models/ingestion.py.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field, HttpUrl, model_validator


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class DOMMetadata(BaseModel):
    """Structural metadata about the page collected by the extension."""

    url: str = Field(
        description="Full page URL as reported by the browser.",
        max_length=8192,
    )
    title: str | None = Field(default=None, max_length=1024)
    # frame_depth=0 means the content is from the top-level document.
    # frame_depth>0 means it originated from a nested iframe.
    frame_depth: int = Field(default=0, ge=0, le=32)
    origin: str = Field(
        description="The origin (scheme+host+port) of the document.",
        max_length=512,
    )


class HiddenContentIndicator(BaseModel):
    """
    A single hidden-content candidate pre-identified by the extension.

    The extension performs a best-effort scan of the rendered DOM.  These
    indicators are stored as-is and are NOT used as authoritative ground
    truth — the backend performs its own independent analysis.
    """

    element_type: str = Field(max_length=64)
    # One of: display_none | visibility_hidden | opacity_zero | off_screen |
    #         tiny_font | aria_hidden | hidden_attr | class_based
    indicator_type: str = Field(max_length=64)
    # Truncated preview of the element's text content.
    raw_content_preview: str = Field(default="", max_length=512)


class IngestionCreate(BaseModel):
    """
    Payload sent by the browser extension for one capture event.

    Size constraints are validated at the Pydantic layer; the larger
    max_html_size_bytes guard is applied in the route using request body limits.
    """

    selected_text: str | None = Field(
        default=None,
        description="Text the user has selected on the page (optional).",
        max_length=65_536,
    )
    page_html: str = Field(
        description="Full outer HTML of the page as seen by the extension.",
        min_length=1,
        max_length=5_242_880,  # 5 MB hard cap; config-driven in the route
    )
    dom_metadata: DOMMetadata
    hidden_content_indicators: list[HiddenContentIndicator] = Field(
        default_factory=list,
        max_length=500,  # sanity cap
    )
    extension_version: str = Field(max_length=32)
    captured_at: datetime = Field(
        description="Client-reported capture timestamp (UTC preferred)."
    )

    @model_validator(mode="after")
    def _strip_empty_selected_text(self) -> IngestionCreate:
        if self.selected_text is not None and not self.selected_text.strip():
            self.selected_text = None
        return self


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class IngestionResponse(BaseModel):
    """Returned immediately after a successful ingestion."""

    ingestion_id: uuid.UUID
    status: str
    message: str
