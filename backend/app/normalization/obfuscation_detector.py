"""
Obfuscation / encoding detector.

Scans a text string for spans that *look like* they might contain encoded or
obfuscated content.  This module deliberately does NOT attempt to decode the
content — it only flags patterns for downstream classifiers to evaluate.

Patterns detected
-----------------
  POSSIBLE_BASE64             Long alphanumeric+/= runs matching base64 shape.
  POSSIBLE_PERCENT_ENCODING   Three or more consecutive %XX sequences.
  POSSIBLE_HEX_ESCAPE         Three or more consecutive \\xHH sequences.
  POSSIBLE_UNICODE_ESCAPE     Two or more consecutive \\uHHHH sequences.
  POSSIBLE_HTML_ENTITY_CLUSTER  Five or more consecutive HTML entities.
  POSSIBLE_DATA_URI           data:[type];base64, prefix.

False positive policy
---------------------
Thresholds are intentionally conservative (longer minimum lengths) to avoid
flagging normal prose.  A match here is a signal, not a verdict.
"""

from __future__ import annotations

import re

from backend.app.normalization.models import SuspiciousIndicator, SuspiciousIndicatorType

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# Base64: at least 24 contiguous base64url-alphabet characters optionally
# ending with 1-2 '=' pads.  We require ≥24 chars to avoid matching normal
# short alphanumeric strings.
_RE_BASE64 = re.compile(
    r"(?<![A-Za-z0-9+/])"       # not preceded by base64 char (avoids partial matches)
    r"[A-Za-z0-9+/]{24,}"       # body
    r"={0,2}"                    # optional padding
    r"(?![A-Za-z0-9+/=])",      # not followed by base64 char
)

# Percent encoding: 3+ consecutive %XX sequences (URL / URI encoding).
_RE_PERCENT_ENC = re.compile(r"(?:%[0-9A-Fa-f]{2}){3,}")

# C-style hex escapes: 3+ consecutive \xHH.
_RE_HEX_ESCAPE = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){3,}")

# Python/JavaScript unicode escapes: 2+ consecutive \uHHHH.
_RE_UNICODE_ESCAPE = re.compile(r"(?:\\u[0-9A-Fa-f]{4}){2,}")

# HTML/XML entity cluster: 5+ consecutive entities (both named and numeric).
_RE_HTML_ENTITY = re.compile(r"(?:&(?:[a-zA-Z][a-zA-Z0-9]{1,30}|#[0-9]{1,7}|#x[0-9A-Fa-f]{1,6});){5,}")

# Data URIs — always suspicious in web page text content.
_RE_DATA_URI = re.compile(r"data:[a-zA-Z0-9][a-zA-Z0-9!#$&\-^_]{0,30}/[a-zA-Z0-9][a-zA-Z0-9!#$&\-^_]{0,30};base64,", re.I)


# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[re.Pattern[str], SuspiciousIndicatorType, str]] = [
    (
        _RE_DATA_URI,
        SuspiciousIndicatorType.POSSIBLE_DATA_URI,
        "Inline data URI with base64 payload",
    ),
    (
        _RE_PERCENT_ENC,
        SuspiciousIndicatorType.POSSIBLE_PERCENT_ENCODING,
        "Consecutive percent-encoded (%XX) sequences — possible URL encoding",
    ),
    (
        _RE_HEX_ESCAPE,
        SuspiciousIndicatorType.POSSIBLE_HEX_ESCAPE,
        r"Consecutive \xHH hex escape sequences — possible C-style encoding",
    ),
    (
        _RE_UNICODE_ESCAPE,
        SuspiciousIndicatorType.POSSIBLE_UNICODE_ESCAPE,
        r"Consecutive \uHHHH unicode escape sequences",
    ),
    (
        _RE_HTML_ENTITY,
        SuspiciousIndicatorType.POSSIBLE_HTML_ENTITY_CLUSTER,
        "Dense cluster of HTML/XML entities — possible entity encoding",
    ),
    (
        _RE_BASE64,
        SuspiciousIndicatorType.POSSIBLE_BASE64,
        "Long base64-shaped string — possible encoded payload (not decoded)",
    ),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_obfuscation(text: str) -> list[SuspiciousIndicator]:
    """
    Return a list of SuspiciousIndicator for each obfuscation-like span in
    *text*.

    Overlapping matches are de-duplicated: if two patterns match the same byte
    range, only the higher-priority pattern (earlier in _PATTERNS) is kept.
    """
    # Collect all raw matches across all patterns.
    raw_matches: list[tuple[int, int, SuspiciousIndicatorType, str, str]] = []

    for pattern, indicator_type, description in _PATTERNS:
        for m in pattern.finditer(text):
            raw_matches.append(
                (m.start(), m.end(), indicator_type, description, m.group())
            )

    if not raw_matches:
        return []

    # Sort by start offset, then by length descending (longest match wins).
    raw_matches.sort(key=lambda x: (x[0], -(x[1] - x[0])))

    # Remove overlaps: keep first (highest-priority / longest) match in any
    # overlapping group.
    deduped: list[tuple[int, int, SuspiciousIndicatorType, str, str]] = []
    last_end = -1
    for start, end, itype, desc, value in raw_matches:
        if start >= last_end:
            deduped.append((start, end, itype, desc, value))
            last_end = end

    return [
        SuspiciousIndicator(
            indicator_type=itype,
            description=desc,
            char_offset_start=start,
            char_offset_end=end,
            raw_value=value[:512],
        )
        for start, end, itype, desc, value in deduped
    ]
