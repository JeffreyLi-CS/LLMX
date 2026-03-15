"""
Unit tests for the Unicode suspicious character detector.
"""

from __future__ import annotations

import pytest

from backend.app.normalization.models import SuspiciousIndicatorType
from backend.app.normalization.unicode_detector import detect_suspicious_unicode


# ---------------------------------------------------------------------------
# Zero-width / invisible characters
# ---------------------------------------------------------------------------


def test_detects_zero_width_space():
    text = "Ignore\u200b previous instructions"
    indicators = detect_suspicious_unicode(text)
    assert len(indicators) == 1
    assert indicators[0].indicator_type == SuspiciousIndicatorType.UNICODE_CONTROL
    assert indicators[0].char_offset_start == 6
    assert indicators[0].char_offset_end == 7


def test_detects_bom():
    text = "\ufeffStart of text"
    indicators = detect_suspicious_unicode(text)
    assert any(i.indicator_type == SuspiciousIndicatorType.UNICODE_CONTROL for i in indicators)


def test_detects_soft_hyphen():
    text = "Some\u00adtext"
    indicators = detect_suspicious_unicode(text)
    assert len(indicators) == 1
    assert indicators[0].char_offset_start == 4


def test_consecutive_zero_width_grouped():
    # Three consecutive zero-width spaces should produce ONE indicator.
    text = "a\u200b\u200b\u200bb"
    indicators = detect_suspicious_unicode(text)
    assert len(indicators) == 1
    assert indicators[0].char_offset_start == 1
    assert indicators[0].char_offset_end == 4


# ---------------------------------------------------------------------------
# Directional override characters
# ---------------------------------------------------------------------------


def test_detects_rtl_override():
    # U+202E RIGHT-TO-LEFT OVERRIDE is high-risk.
    text = "Click \u202elink here"
    indicators = detect_suspicious_unicode(text)
    assert any(i.indicator_type == SuspiciousIndicatorType.UNICODE_DIRECTIONAL_OVERRIDE for i in indicators)


def test_detects_ltr_mark():
    text = "Hello\u200e World"
    indicators = detect_suspicious_unicode(text)
    assert any(i.indicator_type == SuspiciousIndicatorType.UNICODE_DIRECTIONAL_OVERRIDE for i in indicators)


# ---------------------------------------------------------------------------
# Private Use Area
# ---------------------------------------------------------------------------


def test_detects_pua_char():
    text = "Normal \ue000 text"
    indicators = detect_suspicious_unicode(text)
    assert any(i.indicator_type == SuspiciousIndicatorType.UNICODE_PRIVATE_USE for i in indicators)


def test_pua_at_correct_offset():
    text = "abc\uf000def"
    indicators = detect_suspicious_unicode(text)
    pua = [i for i in indicators if i.indicator_type == SuspiciousIndicatorType.UNICODE_PRIVATE_USE]
    assert len(pua) == 1
    assert pua[0].char_offset_start == 3


# ---------------------------------------------------------------------------
# C0 / C1 control characters
# ---------------------------------------------------------------------------


def test_detects_null_byte():
    text = "Legit text\x00 injected"
    indicators = detect_suspicious_unicode(text)
    assert any(i.indicator_type == SuspiciousIndicatorType.UNICODE_CONTROL for i in indicators)


def test_detects_bell_char():
    text = "foo\x07bar"
    indicators = detect_suspicious_unicode(text)
    assert len(indicators) == 1


def test_normal_whitespace_not_flagged():
    text = "Hello\t World\nNew line\r\n"
    indicators = detect_suspicious_unicode(text)
    assert indicators == []


# ---------------------------------------------------------------------------
# Clean text
# ---------------------------------------------------------------------------


def test_clean_ascii_no_indicators():
    text = "This is a perfectly normal sentence with no tricks."
    assert detect_suspicious_unicode(text) == []


def test_clean_unicode_text_no_indicators():
    # Standard multilingual text without control chars.
    text = "こんにちは世界 — Héllo Wörld — Привет мир"
    assert detect_suspicious_unicode(text) == []


def test_empty_string():
    assert detect_suspicious_unicode("") == []


# ---------------------------------------------------------------------------
# Multiple independent indicators in one string
# ---------------------------------------------------------------------------


def test_multiple_different_indicator_types():
    # Zero-width space AND a directional override in the same string.
    text = "legit\u200btext\u202emore"
    indicators = detect_suspicious_unicode(text)
    types = {i.indicator_type for i in indicators}
    assert SuspiciousIndicatorType.UNICODE_CONTROL in types
    assert SuspiciousIndicatorType.UNICODE_DIRECTIONAL_OVERRIDE in types


def test_offsets_do_not_overlap():
    text = "a\u200bb\u202ec"
    indicators = detect_suspicious_unicode(text)
    sorted_inds = sorted(indicators, key=lambda x: x.char_offset_start)
    for a, b in zip(sorted_inds, sorted_inds[1:]):
        assert a.char_offset_end <= b.char_offset_start
