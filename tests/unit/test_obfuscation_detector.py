"""
Unit tests for the obfuscation / encoding pattern detector.
"""

from __future__ import annotations

import pytest

from backend.app.normalization.models import SuspiciousIndicatorType
from backend.app.normalization.obfuscation_detector import detect_obfuscation


# ---------------------------------------------------------------------------
# Base64
# ---------------------------------------------------------------------------


def test_detects_base64_payload():
    # A clearly base64-shaped string (>=24 chars).
    text = "Encoded: aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q="
    indicators = detect_obfuscation(text)
    assert any(i.indicator_type == SuspiciousIndicatorType.POSSIBLE_BASE64 for i in indicators)


def test_short_base64_not_flagged():
    # "dGVzdA==" is only 8 chars — below the 24-char threshold.
    text = "short: dGVzdA=="
    indicators = detect_obfuscation(text)
    assert not any(i.indicator_type == SuspiciousIndicatorType.POSSIBLE_BASE64 for i in indicators)


def test_base64_raw_value_truncated():
    very_long = "A" * 600
    text = f"data: {very_long}"
    indicators = detect_obfuscation(text)
    base64_inds = [i for i in indicators if i.indicator_type == SuspiciousIndicatorType.POSSIBLE_BASE64]
    for ind in base64_inds:
        assert len(ind.raw_value) <= 512


# ---------------------------------------------------------------------------
# Percent encoding
# ---------------------------------------------------------------------------


def test_detects_percent_encoding():
    # 3+ consecutive %XX sequences.
    text = "value=%41%42%43%44"
    indicators = detect_obfuscation(text)
    assert any(i.indicator_type == SuspiciousIndicatorType.POSSIBLE_PERCENT_ENCODING for i in indicators)


def test_single_percent_encoding_not_flagged():
    # Only one %XX — below the threshold of 3.
    text = "one: %41"
    indicators = detect_obfuscation(text)
    assert not any(i.indicator_type == SuspiciousIndicatorType.POSSIBLE_PERCENT_ENCODING for i in indicators)


def test_two_percent_encoding_not_flagged():
    text = "two: %41%42"
    indicators = detect_obfuscation(text)
    assert not any(i.indicator_type == SuspiciousIndicatorType.POSSIBLE_PERCENT_ENCODING for i in indicators)


# ---------------------------------------------------------------------------
# Hex escapes
# ---------------------------------------------------------------------------


def test_detects_hex_escapes():
    text = r"cmd: \x49\x67\x6e\x6f\x72\x65"
    indicators = detect_obfuscation(text)
    assert any(i.indicator_type == SuspiciousIndicatorType.POSSIBLE_HEX_ESCAPE for i in indicators)


def test_two_hex_escapes_not_flagged():
    text = r"\x41\x42"
    indicators = detect_obfuscation(text)
    assert not any(i.indicator_type == SuspiciousIndicatorType.POSSIBLE_HEX_ESCAPE for i in indicators)


# ---------------------------------------------------------------------------
# Unicode escapes
# ---------------------------------------------------------------------------


def test_detects_unicode_escapes():
    text = r"text: \u0049\u0067\u006e\u006f\u0072\u0065"
    indicators = detect_obfuscation(text)
    assert any(i.indicator_type == SuspiciousIndicatorType.POSSIBLE_UNICODE_ESCAPE for i in indicators)


def test_single_unicode_escape_not_flagged():
    text = r"one: \u0041"
    indicators = detect_obfuscation(text)
    assert not any(i.indicator_type == SuspiciousIndicatorType.POSSIBLE_UNICODE_ESCAPE for i in indicators)


# ---------------------------------------------------------------------------
# HTML entity cluster
# ---------------------------------------------------------------------------


def test_detects_html_entity_cluster():
    # 5+ consecutive named entities.
    text = "&lt;&gt;&amp;&quot;&apos;&lt;&gt;"
    indicators = detect_obfuscation(text)
    assert any(i.indicator_type == SuspiciousIndicatorType.POSSIBLE_HTML_ENTITY_CLUSTER for i in indicators)


def test_four_entities_not_flagged():
    text = "&lt;&gt;&amp;&quot;"
    indicators = detect_obfuscation(text)
    assert not any(i.indicator_type == SuspiciousIndicatorType.POSSIBLE_HTML_ENTITY_CLUSTER for i in indicators)


def test_numeric_entities_detected():
    text = "&#73;&#103;&#110;&#111;&#114;&#101;"
    indicators = detect_obfuscation(text)
    assert any(i.indicator_type == SuspiciousIndicatorType.POSSIBLE_HTML_ENTITY_CLUSTER for i in indicators)


# ---------------------------------------------------------------------------
# Data URI
# ---------------------------------------------------------------------------


def test_detects_data_uri():
    text = "src=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
    indicators = detect_obfuscation(text)
    assert any(i.indicator_type == SuspiciousIndicatorType.POSSIBLE_DATA_URI for i in indicators)


def test_data_uri_image():
    text = "background: data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA"
    indicators = detect_obfuscation(text)
    assert any(i.indicator_type == SuspiciousIndicatorType.POSSIBLE_DATA_URI for i in indicators)


# ---------------------------------------------------------------------------
# Clean text
# ---------------------------------------------------------------------------


def test_clean_text_no_indicators():
    text = "This is a normal sentence without any encoded content."
    assert detect_obfuscation(text) == []


def test_empty_string():
    assert detect_obfuscation("") == []


# ---------------------------------------------------------------------------
# Overlap de-duplication
# ---------------------------------------------------------------------------


def test_overlapping_matches_deduplicated():
    # A data URI contains a base64 body — only one indicator per region.
    text = "data:text/html;base64," + "A" * 100
    indicators = detect_obfuscation(text)
    offsets = [(i.char_offset_start, i.char_offset_end) for i in indicators]
    # Ensure no two indicators overlap.
    sorted_offs = sorted(offsets)
    for (_, end), (start2, _) in zip(sorted_offs, sorted_offs[1:]):
        assert end <= start2


def test_indicator_offsets_are_valid():
    text = "prefix %41%42%43%44 suffix"
    indicators = detect_obfuscation(text)
    for ind in indicators:
        assert 0 <= ind.char_offset_start < ind.char_offset_end <= len(text)
        assert text[ind.char_offset_start:ind.char_offset_end] == ind.raw_value
