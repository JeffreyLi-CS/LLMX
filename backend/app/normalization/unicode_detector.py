"""
Unicode suspicious character detector.

Scans a text string for Unicode code points that are commonly used in prompt
injection and text manipulation attacks:

  * Zero-width and invisible characters — used to insert hidden instructions
    between visible words or split tokens in ways LLMs see but humans don't.
  * Directional override characters — used to visually reverse text so that
    what the user sees differs from what the model processes.
  * Private Use Area (PUA) codepoints — undefined meaning; may encode
    custom instructions understood by fine-tuned or prompted models.
  * C0/C1 control characters — generally not expected in human-readable web
    content; can disrupt tokenizers and parsers.

Each finding is returned as a SuspiciousIndicator with exact character offsets
into the original (un-normalised) text.
"""

from __future__ import annotations

import unicodedata

from backend.app.normalization.models import SuspiciousIndicator, SuspiciousIndicatorType

# ---------------------------------------------------------------------------
# Character sets
# ---------------------------------------------------------------------------

# Zero-width and invisible formatting characters.
_ZERO_WIDTH: frozenset[str] = frozenset(
    [
        "\u200b",  # ZERO WIDTH SPACE
        "\u200c",  # ZERO WIDTH NON-JOINER
        "\u200d",  # ZERO WIDTH JOINER
        "\u2060",  # WORD JOINER
        "\u2061",  # FUNCTION APPLICATION
        "\u2062",  # INVISIBLE TIMES
        "\u2063",  # INVISIBLE SEPARATOR
        "\u2064",  # INVISIBLE PLUS
        "\ufeff",  # ZERO WIDTH NO-BREAK SPACE / BOM
        "\u00ad",  # SOFT HYPHEN
        "\u180e",  # MONGOLIAN VOWEL SEPARATOR
    ]
)

# Bidirectional / directional override characters.
_DIRECTIONAL: frozenset[str] = frozenset(
    [
        "\u200e",  # LEFT-TO-RIGHT MARK
        "\u200f",  # RIGHT-TO-LEFT MARK
        "\u202a",  # LEFT-TO-RIGHT EMBEDDING
        "\u202b",  # RIGHT-TO-LEFT EMBEDDING
        "\u202c",  # POP DIRECTIONAL FORMATTING
        "\u202d",  # LEFT-TO-RIGHT OVERRIDE
        "\u202e",  # RIGHT-TO-LEFT OVERRIDE  ← high-risk
        "\u2066",  # LEFT-TO-RIGHT ISOLATE
        "\u2067",  # RIGHT-TO-LEFT ISOLATE
        "\u2068",  # FIRST STRONG ISOLATE
        "\u2069",  # POP DIRECTIONAL ISOLATE
        "\u2028",  # LINE SEPARATOR
        "\u2029",  # PARAGRAPH SEPARATOR
    ]
)

# Private Use Area ranges.
_PUA_RANGES: tuple[tuple[int, int], ...] = (
    (0xE000, 0xF8FF),    # BMP PUA
    (0xF0000, 0xFFFFF),  # Supplementary PUA-A
    (0x100000, 0x10FFFF), # Supplementary PUA-B
)

# C0 control characters (0x00–0x1F) that are NOT normal whitespace.
_NORMAL_WHITESPACE: frozenset[str] = frozenset("\t\n\r ")
_C0_CONTROLS: frozenset[str] = frozenset(
    chr(i) for i in range(0x00, 0x20) if chr(i) not in _NORMAL_WHITESPACE
)
# C1 control characters (0x80–0x9F).
_C1_CONTROLS: frozenset[str] = frozenset(chr(i) for i in range(0x80, 0xA0))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_suspicious_unicode(text: str) -> list[SuspiciousIndicator]:
    """
    Return a list of SuspiciousIndicator objects for every suspicious Unicode
    span found in *text*.

    Consecutive identical suspicious characters are grouped into a single
    indicator to avoid exploding the indicator list on densely-encoded payloads.
    """
    indicators: list[SuspiciousIndicator] = []

    i = 0
    while i < len(text):
        ch = text[i]
        cp = ord(ch)

        if ch in _ZERO_WIDTH:
            end = _consume_run(text, i, _ZERO_WIDTH)
            indicators.append(
                SuspiciousIndicator(
                    indicator_type=SuspiciousIndicatorType.UNICODE_CONTROL,
                    description=(
                        f"Zero-width/invisible character(s): "
                        f"{_describe_chars(text[i:end])}"
                    ),
                    char_offset_start=i,
                    char_offset_end=end,
                    raw_value=text[i:end][:64],
                )
            )
            i = end
            continue

        if ch in _DIRECTIONAL:
            end = _consume_run(text, i, _DIRECTIONAL)
            indicators.append(
                SuspiciousIndicator(
                    indicator_type=SuspiciousIndicatorType.UNICODE_DIRECTIONAL_OVERRIDE,
                    description=(
                        f"Directional override/mark character(s): "
                        f"{_describe_chars(text[i:end])}"
                    ),
                    char_offset_start=i,
                    char_offset_end=end,
                    raw_value=text[i:end][:64],
                )
            )
            i = end
            continue

        if _is_pua(cp):
            end = i + 1
            while end < len(text) and _is_pua(ord(text[end])):
                end += 1
            indicators.append(
                SuspiciousIndicator(
                    indicator_type=SuspiciousIndicatorType.UNICODE_PRIVATE_USE,
                    description=(
                        f"Private Use Area codepoint(s) U+{cp:04X}: "
                        "undefined semantics, may encode custom instructions"
                    ),
                    char_offset_start=i,
                    char_offset_end=end,
                    raw_value=text[i:end][:64],
                )
            )
            i = end
            continue

        if ch in _C0_CONTROLS or ch in _C1_CONTROLS:
            end = _consume_run(text, i, _C0_CONTROLS | _C1_CONTROLS)
            indicators.append(
                SuspiciousIndicator(
                    indicator_type=SuspiciousIndicatorType.UNICODE_CONTROL,
                    description=(
                        f"Non-whitespace control character(s): "
                        f"{_describe_chars(text[i:end])}"
                    ),
                    char_offset_start=i,
                    char_offset_end=end,
                    raw_value=text[i:end][:64],
                )
            )
            i = end
            continue

        i += 1

    return indicators


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _consume_run(text: str, start: int, char_set: frozenset[str]) -> int:
    """Return the index after the longest run of characters in char_set."""
    i = start
    while i < len(text) and text[i] in char_set:
        i += 1
    return i


def _is_pua(cp: int) -> bool:
    return any(lo <= cp <= hi for lo, hi in _PUA_RANGES)


def _describe_chars(span: str) -> str:
    """Return a human-readable description of the code points in *span*."""
    parts = [f"U+{ord(c):04X}({unicodedata.name(c, '?')})" for c in set(span)]
    return ", ".join(parts[:4])  # cap at 4 for log brevity
