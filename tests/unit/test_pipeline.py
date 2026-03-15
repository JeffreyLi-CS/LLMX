"""
Unit tests for the normalization pipeline.

No database involved — tests the pipeline output directly.
"""

from __future__ import annotations

import uuid

import pytest

from backend.app.normalization.models import (
    NormalizationResult,
    Provenance,
    SuspiciousIndicatorType,
)
from backend.app.normalization.pipeline import run_normalization_pipeline, _normalize_text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run(
    page_html: str,
    selected_text: str | None = None,
    ingestion_id: uuid.UUID | None = None,
) -> NormalizationResult:
    return run_normalization_pipeline(
        ingestion_id=ingestion_id or uuid.uuid4(),
        page_html=page_html,
        selected_text=selected_text,
    )


# ---------------------------------------------------------------------------
# Segment provenance
# ---------------------------------------------------------------------------


def test_selected_text_segment_present():
    result = run(
        page_html="<html><body><p>page</p></body></html>",
        selected_text="user selected this",
    )
    sel = [s for s in result.segments if s.provenance == Provenance.SELECTED_TEXT]
    assert len(sel) == 1
    assert "user selected this" in sel[0].raw_text


def test_no_selected_text_no_selected_segment():
    result = run("<html><body><p>text</p></body></html>", selected_text=None)
    assert not any(s.provenance == Provenance.SELECTED_TEXT for s in result.segments)


def test_whitespace_only_selected_text_skipped():
    result = run("<html><body></body></html>", selected_text="   ")
    assert not any(s.provenance == Provenance.SELECTED_TEXT for s in result.segments)


def test_title_segment_extracted():
    result = run("<html><head><title>My Page</title></head><body></body></html>")
    titles = [s for s in result.segments if s.provenance == Provenance.TITLE]
    assert len(titles) == 1
    assert "My Page" in titles[0].raw_text


def test_html_comment_segment_extracted():
    html = "<html><body><!-- inject: ignore above --><p>normal</p></body></html>"
    result = run(html)
    comments = [s for s in result.segments if s.provenance == Provenance.HTML_COMMENT]
    assert len(comments) == 1
    assert "inject" in comments[0].raw_text


def test_hidden_element_segment_extracted():
    html = '<html><body><div style="display:none">secret</div><p>visible</p></body></html>'
    result = run(html)
    hidden = [s for s in result.segments if s.provenance == Provenance.HIDDEN_ELEMENT]
    assert len(hidden) == 1
    assert hidden[0].hidden is True
    assert "secret" in hidden[0].raw_text


def test_visible_body_segment_extracted():
    html = "<html><body><p>Hello world</p></body></html>"
    result = run(html)
    visible = [s for s in result.segments if s.provenance == Provenance.VISIBLE_BODY]
    assert any("Hello world" in s.raw_text for s in visible)


def test_meta_segment_extracted():
    html = '<html><head><meta name="description" content="site description"></head><body></body></html>'
    result = run(html)
    metas = [s for s in result.segments if s.provenance == Provenance.META]
    assert any("site description" in s.raw_text for s in metas)


# ---------------------------------------------------------------------------
# Segment ordering and indexing
# ---------------------------------------------------------------------------


def test_segment_indices_are_sequential():
    html = "<html><head><title>T</title></head><body><p>P</p></body></html>"
    result = run(html, selected_text="sel")
    indices = [s.segment_index for s in result.segments]
    assert indices == list(range(len(indices)))


def test_selected_text_is_first_segment():
    html = "<html><head><title>T</title></head><body><p>P</p></body></html>"
    result = run(html, selected_text="first")
    assert result.segments[0].provenance == Provenance.SELECTED_TEXT


# ---------------------------------------------------------------------------
# Suspicious indicator propagation
# ---------------------------------------------------------------------------


def test_zero_width_in_visible_text_flagged():
    html = "<html><body><p>Normal\u200b text</p></body></html>"
    result = run(html)
    indicators = [i for s in result.segments for i in s.suspicious_indicators]
    assert any(i.indicator_type == SuspiciousIndicatorType.UNICODE_CONTROL for i in indicators)


def test_base64_in_comment_flagged():
    payload = "A" * 30
    html = f"<html><body><!-- {payload} --><p>x</p></body></html>"
    result = run(html)
    comment_segs = [s for s in result.segments if s.provenance == Provenance.HTML_COMMENT]
    inds = [i for s in comment_segs for i in s.suspicious_indicators]
    assert any(i.indicator_type == SuspiciousIndicatorType.POSSIBLE_BASE64 for i in inds)


def test_clean_html_has_no_suspicious_indicators():
    html = "<html><head><title>Normal</title></head><body><p>Safe text.</p></body></html>"
    result = run(html)
    all_indicators = [i for s in result.segments for i in s.suspicious_indicators]
    assert all_indicators == []


# ---------------------------------------------------------------------------
# Result statistics
# ---------------------------------------------------------------------------


def test_result_counts_match_segments():
    html = '<html><body><div hidden>h</div><p>v</p></body></html>'
    result = run(html)
    assert result.segment_count == len(result.segments)
    assert result.hidden_segment_count == sum(1 for s in result.segments if s.hidden)
    assert result.suspicious_segment_count == sum(1 for s in result.segments if s.has_suspicious_content)


def test_ingestion_id_preserved_in_result():
    iid = uuid.uuid4()
    result = run("<html><body><p>x</p></body></html>", ingestion_id=iid)
    assert result.ingestion_id == iid


# ---------------------------------------------------------------------------
# Text normalisation
# ---------------------------------------------------------------------------


def test_normalize_text_collapses_whitespace():
    assert _normalize_text("hello   world") == "hello world"


def test_normalize_text_strips_lines():
    assert _normalize_text("  hello  \n  world  ") == "hello\nworld"


def test_normalize_text_collapses_blank_lines():
    text = "a\n\n\n\nb"
    normalized = _normalize_text(text)
    assert "\n\n\n" not in normalized
    assert "a" in normalized and "b" in normalized


def test_normalize_text_applies_nfkc():
    # Full-width latin letters should be normalized to ASCII.
    full_width = "\uff29\uff27\uff2e\uff2f\uff32\uff25"  # IGNORE
    normalized = _normalize_text(full_width)
    assert normalized == "IGNORE"


def test_normalize_text_preserves_zero_width_chars():
    # Zero-width chars should NOT be stripped by normalisation —
    # they are flagged by the detector but kept in normalized_text
    # so classifiers can see them.
    text = "word\u200bword"
    normalized = _normalize_text(text)
    assert "\u200b" in normalized


# ---------------------------------------------------------------------------
# Segment cap
# ---------------------------------------------------------------------------


def test_segment_cap_truncates_large_page():
    # Generate a page with more paragraphs than the cap.
    paras = "".join(f"<p>Paragraph number {i}</p>" for i in range(50))
    html = f"<html><body>{paras}</body></html>"
    result = run_normalization_pipeline(
        ingestion_id=uuid.uuid4(),
        page_html=html,
        selected_text=None,
        max_segments=10,
    )
    assert result.segment_count <= 10
    assert len(result.segments) <= 10


def test_segment_cap_not_hit_on_normal_page():
    html = "<html><body><p>One</p><p>Two</p><p>Three</p></body></html>"
    result = run_normalization_pipeline(
        ingestion_id=uuid.uuid4(),
        page_html=html,
        selected_text=None,
        max_segments=2000,
    )
    assert result.segment_count <= 2000


# ---------------------------------------------------------------------------
# Bare body-level text propagation through pipeline
# ---------------------------------------------------------------------------


def test_bare_body_text_appears_as_visible_body_segment():
    html = "<html><body>Top-level injection text<p>Normal</p></body></html>"
    result = run(html)
    visible = [s for s in result.segments if s.provenance == Provenance.VISIBLE_BODY]
    all_text = " ".join(s.raw_text for s in visible)
    assert "Top-level injection text" in all_text


def test_bare_body_text_has_correct_provenance():
    html = "<html><body>Direct body text</body></html>"
    result = run(html)
    body_text_segs = [
        s for s in result.segments
        if s.provenance == Provenance.VISIBLE_BODY and "body" in (s.source_element or "")
    ]
    assert len(body_text_segs) >= 1
