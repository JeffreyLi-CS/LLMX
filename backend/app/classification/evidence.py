"""
Evidence span mapper.

Takes the raw evidence items emitted by a classifier provider (segment index +
text excerpt) and resolves them to precise character offsets within the
corresponding segment's raw_text.

Resolution strategy (in order of preference)
---------------------------------------------
1. Find the excerpt as a substring of raw_text (exact match).
2. Find the excerpt as a substring of normalized_text and translate the offset
   back to raw_text (best-effort; works when the LLM quoted the cleaned text).
3. Use the full segment span (offset 0 → len(raw_text)) as a fallback with a
   warning.  This is conservative: the whole segment is flagged as evidence
   rather than dropping the reference entirely.
"""

from __future__ import annotations

import structlog

from backend.app.classification.models import EvidenceSpan
from backend.app.normalization.models import NormalizedSegment

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


def map_evidence_spans(
    raw_evidence: list[dict],
    segments: list[NormalizedSegment],
) -> list[EvidenceSpan]:
    """
    Convert provider-emitted evidence dicts to typed EvidenceSpan objects.

    Parameters
    ----------
    raw_evidence:
        List of dicts, each with keys:
          - segment_index: int
          - excerpt: str
          - reasoning: str
    segments:
        The full list of NormalizedSegment objects for this ingestion, keyed
        by segment_index.

    Returns
    -------
    A list of EvidenceSpan objects with resolved character offsets.
    """
    seg_by_index = {s.segment_index: s for s in segments}
    spans: list[EvidenceSpan] = []

    for item in raw_evidence:
        seg_index: int = int(item.get("segment_index", -1))
        excerpt: str = str(item.get("excerpt", "")).strip()
        reasoning: str = str(item.get("reasoning", "")).strip()

        seg = seg_by_index.get(seg_index)
        if seg is None:
            logger.warning(
                "evidence.segment_not_found",
                segment_index=seg_index,
                excerpt_preview=excerpt[:80],
            )
            continue

        start, end = _resolve_offsets(excerpt, seg)

        spans.append(
            EvidenceSpan(
                segment_id=seg.id,
                segment_index=seg_index,
                provenance=seg.provenance.value,
                char_offset_start=start,
                char_offset_end=end,
                excerpt=excerpt[:1024],
                reasoning=reasoning[:2048],
            )
        )

    return spans


def _resolve_offsets(excerpt: str, seg: NormalizedSegment) -> tuple[int, int]:
    """
    Return (start, end) character offsets for *excerpt* within *seg.raw_text*.

    Falls back gracefully when the excerpt cannot be located.
    """
    if not excerpt:
        return 0, len(seg.raw_text)

    # Strategy 1: exact match in raw_text.
    pos = seg.raw_text.find(excerpt)
    if pos >= 0:
        return pos, pos + len(excerpt)

    # Strategy 2: exact match in normalized_text; return (0, len) for raw_text
    # since the character offsets don't translate reliably after NFKC.
    if seg.normalized_text.find(excerpt) >= 0:
        return 0, len(seg.raw_text)

    # Strategy 3: case-insensitive match in raw_text.
    pos_ci = seg.raw_text.lower().find(excerpt.lower())
    if pos_ci >= 0:
        return pos_ci, pos_ci + len(excerpt)

    logger.debug(
        "evidence.excerpt_not_located",
        segment_index=seg.segment_index,
        excerpt_preview=excerpt[:80],
    )
    # Fallback: flag the entire segment.
    return 0, len(seg.raw_text)
