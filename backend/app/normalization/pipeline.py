"""
Normalization pipeline.

Orchestrates the full normalization flow for one ingestion payload:

  1. Extract selected text as its own provenance-tagged segment (if present).
  2. Parse the raw HTML via html_processor to extract:
       title, meta, HTML comments, hidden elements, visible text blocks.
  3. For each extracted piece of text:
       a. Whitespace normalisation.
       b. NFKC unicode normalisation (preserves original in raw_text).
       c. Unicode suspicious character detection.
       d. Obfuscation/encoding pattern detection.
  4. Assemble and return a NormalizationResult.

Nothing in this module touches the database — persistence is handled by
normalization/service.py.
"""

from __future__ import annotations

import unicodedata
import uuid
from re import sub as re_sub

import structlog

from backend.app.normalization.html_processor import process_html
from backend.app.normalization.models import (
    NormalizationResult,
    NormalizedSegment,
    Provenance,
    SuspiciousIndicator,
)
from backend.app.normalization.obfuscation_detector import detect_obfuscation
from backend.app.normalization.unicode_detector import detect_suspicious_unicode

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Pipeline entry point
# ---------------------------------------------------------------------------


def run_normalization_pipeline(
    *,
    ingestion_id: uuid.UUID,
    page_html: str,
    selected_text: str | None,
) -> NormalizationResult:
    """
    Run the full normalization pipeline and return a NormalizationResult.

    Parameters
    ----------
    ingestion_id:
        UUID of the parent IngestionRecord — embedded in the result for
        traceability.
    page_html:
        Raw HTML string from the extension.  Treated as adversarial.
    selected_text:
        Optional user-selected text from the extension.  Treated as
        lower-risk than body HTML but still analysed for suspicious content.
    """
    logger.info("normalization.pipeline.start", ingestion_id=str(ingestion_id))

    segments: list[NormalizedSegment] = []
    index = 0

    # ── 1. Selected text ─────────────────────────────────────────────────────
    if selected_text and selected_text.strip():
        seg = _build_segment(
            index=index,
            raw_text=selected_text,
            provenance=Provenance.SELECTED_TEXT,
            source_element="user-selection",
            hidden=False,
        )
        segments.append(seg)
        index += 1

    # ── 2. Parse HTML ─────────────────────────────────────────────────────────
    processed = process_html(page_html)

    # Title
    if processed.title:
        seg = _build_segment(
            index=index,
            raw_text=processed.title,
            provenance=Provenance.TITLE,
            source_element="title",
            hidden=False,
        )
        segments.append(seg)
        index += 1

    # Meta tags
    for i, meta in enumerate(processed.meta_items):
        if meta.content.strip():
            seg = _build_segment(
                index=index,
                raw_text=meta.content,
                provenance=Provenance.META,
                source_element=f"meta[{meta.name}]",
                hidden=False,
            )
            segments.append(seg)
            index += 1

    # HTML comments — always suspicious: flag even if no other indicators fire.
    for i, comment in enumerate(processed.html_comments):
        stripped = comment.strip()
        if stripped:
            seg = _build_segment(
                index=index,
                raw_text=stripped,
                provenance=Provenance.HTML_COMMENT,
                source_element=f"comment@{i}",
                hidden=False,
            )
            segments.append(seg)
            index += 1

    # Hidden elements
    for hidden_el in processed.hidden_elements:
        if hidden_el.text.strip():
            seg = _build_segment(
                index=index,
                raw_text=hidden_el.text,
                provenance=Provenance.HIDDEN_ELEMENT,
                source_element=hidden_el.source_hint,
                hidden=True,
            )
            segments.append(seg)
            index += 1

    # Visible body blocks
    for block in processed.visible_blocks:
        if block.text.strip():
            seg = _build_segment(
                index=index,
                raw_text=block.text,
                provenance=Provenance.VISIBLE_BODY,
                source_element=block.source_hint,
                hidden=False,
            )
            segments.append(seg)
            index += 1

    hidden_count = sum(1 for s in segments if s.hidden)
    suspicious_count = sum(1 for s in segments if s.has_suspicious_content)

    logger.info(
        "normalization.pipeline.complete",
        ingestion_id=str(ingestion_id),
        total_segments=len(segments),
        hidden_segments=hidden_count,
        suspicious_segments=suspicious_count,
    )

    return NormalizationResult(
        ingestion_id=ingestion_id,
        segment_count=len(segments),
        hidden_segment_count=hidden_count,
        suspicious_segment_count=suspicious_count,
        segments=segments,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_segment(
    *,
    index: int,
    raw_text: str,
    provenance: Provenance,
    source_element: str | None,
    hidden: bool,
) -> NormalizedSegment:
    """
    Normalise a single text string and produce a NormalizedSegment.

    Detection runs on the *raw* text so that character offsets in
    SuspiciousIndicator objects are valid against raw_text.
    """
    # Run detectors on the original text before any transformation.
    indicators: list[SuspiciousIndicator] = []
    indicators.extend(detect_suspicious_unicode(raw_text))
    indicators.extend(detect_obfuscation(raw_text))

    # Sort by start offset for deterministic output.
    indicators.sort(key=lambda x: x.char_offset_start)

    normalized_text = _normalize_text(raw_text)

    return NormalizedSegment(
        segment_index=index,
        provenance=provenance,
        source_element=source_element,
        raw_text=raw_text,
        normalized_text=normalized_text,
        hidden=hidden,
        suspicious_indicators=indicators,
    )


def _normalize_text(text: str) -> str:
    """
    Apply NFKC unicode normalisation and whitespace normalisation.

    NFKC resolves compatibility equivalents (full-width letters, ligatures,
    circled numbers, etc.) into their canonical forms, which makes downstream
    pattern matching more reliable.  It does NOT strip zero-width characters —
    those are preserved so that classifiers can see them.

    Whitespace: collapse runs of spaces/tabs to a single space; strip leading
    and trailing whitespace per line; collapse runs of blank lines to one.
    """
    # Unicode normalisation.
    text = unicodedata.normalize("NFKC", text)

    # Collapse horizontal whitespace (spaces + tabs) within each line.
    text = re_sub(r"[ \t]+", " ", text)

    # Strip leading/trailing whitespace from each line.
    lines = [line.strip() for line in text.splitlines()]

    # Collapse consecutive blank lines to a single blank line.
    collapsed: list[str] = []
    prev_blank = False
    for line in lines:
        is_blank = line == ""
        if is_blank and prev_blank:
            continue
        collapsed.append(line)
        prev_blank = is_blank

    return "\n".join(collapsed).strip()
