"""
Benchmark / stress tests for the normalization pipeline.

These tests do NOT require a database.  They generate large synthetic HTML
pages and assert that the pipeline completes within an acceptable wall-clock
budget and produces internally consistent output.

Timing budgets are generous (10 s) so they pass on a wide range of hardware,
including CI runners.  The tests are more useful as regression guards: if
the pipeline starts taking 5 s on a page it used to handle in 0.1 s, that
is a signal of algorithmic regression.
"""

from __future__ import annotations

import time
import uuid

import pytest

from backend.app.normalization.pipeline import run_normalization_pipeline


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _large_page(n_paragraphs: int, inject_hidden: bool = False) -> str:
    """Generate a synthetic HTML page with *n_paragraphs* <p> elements."""
    paras = "".join(
        f"<p>Paragraph number {i}: This is some realistic prose content "
        f"that a normal web page might contain on a topic of general interest.</p>"
        for i in range(n_paragraphs)
    )
    hidden = (
        '<div style="display:none">Hidden injection payload attempting to override '
        "previous instructions and exfiltrate sensitive data.</div>"
        if inject_hidden
        else ""
    )
    return (
        f"<html><head><title>Large Page Benchmark</title>"
        f'<meta name="description" content="A long page for benchmarking.">'
        f"</head><body>{hidden}{paras}</body></html>"
    )


# ---------------------------------------------------------------------------
# Throughput benchmarks
# ---------------------------------------------------------------------------


def test_pipeline_1000_paragraphs_under_10s():
    """
    A page with 1 000 paragraphs must normalize in < 10 s.

    On a typical developer machine this completes in well under 1 s.
    The 10 s budget provides headroom for slow CI environments.
    """
    html = _large_page(1_000)
    start = time.monotonic()
    result = run_normalization_pipeline(
        ingestion_id=uuid.uuid4(),
        page_html=html,
        selected_text=None,
        max_segments=2_000,
    )
    elapsed = time.monotonic() - start

    assert elapsed < 10.0, f"Pipeline took {elapsed:.2f}s on 1 000-paragraph page"
    assert result.segment_count > 0


def test_pipeline_5mb_html_under_10s():
    """
    A near-max-size page (~5 MB of HTML) must normalize in < 10 s.

    This stresses the BeautifulSoup parser and the regex detectors on a
    very large text corpus.
    """
    # Each paragraph is ~130 chars; 38_000 paragraphs ≈ 5 MB HTML.
    html = _large_page(38_000)
    assert len(html.encode()) >= 4_000_000, "Page too small — adjust paragraph count"

    start = time.monotonic()
    result = run_normalization_pipeline(
        ingestion_id=uuid.uuid4(),
        page_html=html,
        selected_text=None,
        max_segments=2_000,
    )
    elapsed = time.monotonic() - start

    assert elapsed < 10.0, f"Pipeline took {elapsed:.2f}s on ~5 MB page"
    # Segment cap applies: result must be at most max_segments.
    assert result.segment_count <= 2_000


def test_segment_cap_enforced_on_huge_page():
    """Segment cap must be strictly respected regardless of page size."""
    html = _large_page(5_000)
    result = run_normalization_pipeline(
        ingestion_id=uuid.uuid4(),
        page_html=html,
        selected_text=None,
        max_segments=50,
    )
    assert result.segment_count <= 50
    assert len(result.segments) <= 50


# ---------------------------------------------------------------------------
# Correctness under stress
# ---------------------------------------------------------------------------


def test_large_page_segment_indices_sequential():
    """Segment indices must be sequential even for a capped large page."""
    html = _large_page(500)
    result = run_normalization_pipeline(
        ingestion_id=uuid.uuid4(),
        page_html=html,
        selected_text="user selected this snippet",
        max_segments=100,
    )
    indices = [s.segment_index for s in result.segments]
    assert indices == list(range(len(indices)))


def test_hidden_elements_detected_in_large_page():
    """Hidden injection segment must appear even inside a large page."""
    html = _large_page(200, inject_hidden=True)
    result = run_normalization_pipeline(
        ingestion_id=uuid.uuid4(),
        page_html=html,
        selected_text=None,
        max_segments=2_000,
    )
    hidden_segs = [s for s in result.segments if s.hidden]
    assert len(hidden_segs) >= 1
    assert any("injection payload" in s.raw_text for s in hidden_segs)


def test_result_statistics_consistent_on_large_page():
    """segment_count / hidden_segment_count must match the segments list."""
    html = _large_page(300, inject_hidden=True)
    result = run_normalization_pipeline(
        ingestion_id=uuid.uuid4(),
        page_html=html,
        selected_text=None,
        max_segments=2_000,
    )
    assert result.segment_count == len(result.segments)
    assert result.hidden_segment_count == sum(1 for s in result.segments if s.hidden)
    assert result.suspicious_segment_count == sum(
        1 for s in result.segments if s.has_suspicious_content
    )
