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

# Base64: candidate match — at least 40 chars.  The secondary filter
# _is_likely_base64() then rejects common benign strings (UUIDs, hex digests,
# monotone alpha runs, JWT headers, Google Analytics IDs, etc.).
#
# Rationale for 40-char minimum (≥ 30 bytes encoded):
#   - UUID hex without dashes: 32 chars — excluded
#   - SHA-1 hex: 40 chars but hex-only alphabet → filtered by char distribution
#   - GA tracking IDs, CSP nonces: typically < 40 chars or all-lowercase hex
#   - Real base64 payloads start at ≥12 bytes → ≥16 chars; raising to 40 chars
#     means ≥30 bytes — still catches meaningful short injections while cutting
#     the FP rate dramatically on analytics strings and identifiers.
_RE_BASE64 = re.compile(
    r"(?<![A-Za-z0-9+/])"       # not preceded by base64 char
    r"[A-Za-z0-9+/]{40,}"       # body (≥40 chars)
    r"={0,2}"                    # optional padding
    r"(?![A-Za-z0-9+/=])",      # not followed by base64 char
)


def _is_likely_base64(s: str) -> bool:
    """
    Secondary heuristic filter applied after the regex match.

    Rejects common benign strings that happen to match the base64 alphabet:
    - All lowercase or all uppercase hex digests (SHA/MD5/UUID without dashes).
    - Strings whose length (ignoring trailing =) is NOT a multiple of 4
      after alignment (strict base64 is always aligned to 4).
    - Strings with very skewed char-class distribution (monotone lowercase
      alpha runs, pure digit runs, etc.) that are unlikely to be real base64.

    Real base64 output of even a few bytes has a mix of upper, lower, digits,
    and often + or /.
    """
    body = s.rstrip("=")
    body_len = len(body)

    # Length must be divisible by 4 (ignoring padding) OR the full string
    # (including =) must be.  Canonical base64 is always length % 4 == 0.
    full_len = len(s)
    if full_len % 4 != 0:
        return False

    # Reject pure-hex strings (all chars in [0-9a-fA-F]): these are typically
    # SHA/MD5 digests, UUIDs, or tracking IDs — not base64 payloads.
    if all(c in "0123456789abcdefABCDEF" for c in body):
        return False

    # Require a mix of at least two distinct character classes:
    # uppercase, lowercase, digits.  Real base64 almost always hits all three.
    has_upper = any(c.isupper() for c in body)
    has_lower = any(c.islower() for c in body)
    has_digit = any(c.isdigit() for c in body)

    class_count = int(has_upper) + int(has_lower) + int(has_digit)
    if class_count < 2:
        return False

    # Reject if the string is ≥ 90% a single character class (e.g. all-lower
    # alphabetic run like a CSS class name or slug).
    lower_ratio = sum(1 for c in body if c.islower()) / body_len
    upper_ratio = sum(1 for c in body if c.isupper()) / body_len
    digit_ratio = sum(1 for c in body if c.isdigit()) / body_len

    if lower_ratio >= 0.9 or upper_ratio >= 0.9 or digit_ratio >= 0.9:
        return False

    return True

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
            value = m.group()
            # Extra filter for base64 candidates to reduce false positives.
            if indicator_type == SuspiciousIndicatorType.POSSIBLE_BASE64:
                if not _is_likely_base64(value):
                    continue
            raw_matches.append(
                (m.start(), m.end(), indicator_type, description, value)
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
