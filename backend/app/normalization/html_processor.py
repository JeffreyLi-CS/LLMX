"""
HTML processor: parse raw page HTML and extract structured content pieces.

All extraction happens before any text normalization so that the raw offsets
are available for evidence spans.

Design principles
-----------------
* Treat the HTML as adversarial: hidden elements are preserved (not silently
  discarded) so that downstream components can reason about them.
* Do not silently normalise content here — just extract and label.
* Use lxml as the BeautifulSoup parser for speed and robustness.
* Produce typed dataclasses; callers should not need to inspect raw BS4 nodes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup, Comment, NavigableString, Tag

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Block-level elements that delimit natural reading-order segments.
_BLOCK_TAGS: frozenset[str] = frozenset(
    {
        "address", "article", "aside", "blockquote", "caption",
        "dd", "details", "dialog", "div", "dl", "dt",
        "fieldset", "figcaption", "figure", "footer",
        "form", "h1", "h2", "h3", "h4", "h5", "h6",
        "header", "hgroup", "hr", "legend", "li",
        "main", "nav", "ol", "p", "pre", "section",
        "summary", "table", "td", "th", "tr", "ul",
    }
)

# Tags whose text content is never part of the visible page body.
_SKIP_TAGS: frozenset[str] = frozenset(
    {
        "script", "style", "noscript", "template",
        "svg", "math", "canvas", "iframe", "object", "embed",
        "head",
    }
)

# Common CSS class names used to hide elements visually.
_HIDING_CLASSES: frozenset[str] = frozenset(
    {
        "sr-only", "visually-hidden", "visually_hidden",
        "screen-reader-only", "screen-reader-text",
        "hidden", "d-none", "hide", "invisible",
        "offscreen", "off-screen",
    }
)

# Regex: inline style patterns that indicate hidden elements.
_RE_DISPLAY_NONE = re.compile(r"display\s*:\s*none", re.I)
_RE_VISIBILITY_HIDDEN = re.compile(r"visibility\s*:\s*hidden", re.I)
_RE_OPACITY_ZERO = re.compile(r"opacity\s*:\s*0(?:\.0+)?\b", re.I)
_RE_FONT_SIZE_ZERO = re.compile(r"font-size\s*:\s*0(?:px|pt|em|rem)?\b", re.I)
_RE_OVERFLOW_HIDDEN = re.compile(r"overflow\s*:\s*hidden", re.I)
_RE_WIDTH_ZERO = re.compile(r"\bwidth\s*:\s*0(?:px)?\b", re.I)
_RE_HEIGHT_ZERO = re.compile(r"\bheight\s*:\s*0(?:px)?\b", re.I)
# Very negative position: left/top with absolute value >= 100 (any unit or bare).
# Requires 3+ digits before the optional unit to avoid flagging -1px / -2em,
# which are used in legitimate micro-adjustments.
_RE_OFFSCREEN = re.compile(
    r"(?:left|top)\s*:\s*-[0-9]{3,}(?:\.[0-9]+)?(?:px|em|rem|%|vw|vh)?(?![0-9A-Za-z])",
    re.I,
)


# ---------------------------------------------------------------------------
# Output dataclasses
# ---------------------------------------------------------------------------


@dataclass
class MetaItem:
    name: str       # meta name/property attribute value
    content: str    # meta content attribute value


@dataclass
class HiddenElement:
    tag_name: str
    source_hint: str    # CSS-selector-like label, e.g. "div.tooltip"
    text: str           # raw text content extracted from the element
    reason: str         # why it is considered hidden


@dataclass
class TextBlock:
    tag_name: str
    source_hint: str    # e.g. "h1", "p", "div#main"
    text: str


@dataclass
class ProcessedHTML:
    title: str | None
    meta_items: list[MetaItem] = field(default_factory=list)
    html_comments: list[str] = field(default_factory=list)
    hidden_elements: list[HiddenElement] = field(default_factory=list)
    visible_blocks: list[TextBlock] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def process_html(html: str) -> ProcessedHTML:
    """
    Parse *html* and return a ProcessedHTML with all content pieces extracted.

    This function does NOT normalise whitespace or unicode — it only extracts
    and labels.  Normalisation is the responsibility of the pipeline.
    """
    soup = BeautifulSoup(html, "lxml")

    title = _extract_title(soup)
    meta_items = _extract_meta(soup)
    html_comments = _extract_comments(soup)
    hidden_elements, hidden_tag_ids = _extract_hidden(soup)
    visible_blocks = _extract_visible_blocks(soup, hidden_tag_ids)

    return ProcessedHTML(
        title=title,
        meta_items=meta_items,
        html_comments=html_comments,
        hidden_elements=hidden_elements,
        visible_blocks=visible_blocks,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_title(soup: BeautifulSoup) -> str | None:
    tag = soup.find("title")
    if tag and tag.string:
        return tag.string.strip() or None
    return None


def _extract_meta(soup: BeautifulSoup) -> list[MetaItem]:
    items: list[MetaItem] = []
    for tag in soup.find_all("meta"):
        if not isinstance(tag, Tag):
            continue
        name = tag.get("name") or tag.get("property") or tag.get("http-equiv")
        content = tag.get("content")
        if name and content:
            items.append(MetaItem(name=str(name), content=str(content)))
    return items


def _extract_comments(soup: BeautifulSoup) -> list[str]:
    return [str(node) for node in soup.find_all(string=lambda t: isinstance(t, Comment))]


def _is_hidden(tag: Tag) -> tuple[bool, str]:
    """
    Return (is_hidden, reason) for a single tag.

    Checks inline styles, the HTML `hidden` attribute, aria-hidden, and
    commonly-used hiding CSS class names.  Does NOT evaluate external
    stylesheets — that would require a full rendering engine.
    """
    # HTML `hidden` attribute (boolean)
    if tag.has_attr("hidden"):
        return True, "html[hidden]"

    style = tag.get("style", "")
    if isinstance(style, list):
        style = " ".join(style)

    if _RE_DISPLAY_NONE.search(style):
        return True, "style:display:none"
    if _RE_VISIBILITY_HIDDEN.search(style):
        return True, "style:visibility:hidden"
    if _RE_OPACITY_ZERO.search(style):
        return True, "style:opacity:0"
    if _RE_FONT_SIZE_ZERO.search(style):
        return True, "style:font-size:0"
    if (
        _RE_WIDTH_ZERO.search(style)
        and _RE_HEIGHT_ZERO.search(style)
        and _RE_OVERFLOW_HIDDEN.search(style)
    ):
        return True, "style:collapsed(w0,h0,overflow:hidden)"
    if _RE_OFFSCREEN.search(style):
        return True, "style:offscreen"

    # aria-hidden="true" — element is hidden from assistive tech but may be
    # visually present.  Flag it with a distinct reason so callers can decide
    # how to weight it.
    aria = tag.get("aria-hidden", "")
    if str(aria).lower() == "true":
        return True, "aria-hidden:true"

    # Common CSS hiding class names.
    classes = set(tag.get("class") or [])
    matching = classes & _HIDING_CLASSES
    if matching:
        return True, f"class:{','.join(sorted(matching))}"

    return False, ""


def _source_hint(tag: Tag) -> str:
    """Produce a concise CSS-selector-like label for a tag."""
    parts = [tag.name]
    if tag.get("id"):
        parts.append(f"#{tag['id']}")
    elif tag.get("class"):
        classes = tag["class"]
        if isinstance(classes, list):
            classes = classes[:2]  # truncate long class lists
        parts.append(f".{'.'.join(classes)}")
    return "".join(parts)


def _extract_hidden(soup: BeautifulSoup) -> tuple[list[HiddenElement], set[int]]:
    """
    Find all tags that are hidden by inline style, attribute, or class,
    and extract their text content.

    We walk the full tree and collect the *outermost* hidden containers —
    i.e., if a hidden div contains hidden spans, we record the div but not
    each child individually.

    Returns a tuple of (hidden_elements, hidden_tag_ids) where hidden_tag_ids
    is the set of id() values for all hidden tags (and their descendants).
    This set is passed to _extract_visible_blocks to exclude hidden content.
    """
    results: list[HiddenElement] = []
    # Tracks all tag ids that are hidden (outermost hidden containers AND their
    # descendants) so that _extract_visible_blocks can exclude them.
    hidden_tag_ids: set[int] = set()

    for tag in soup.find_all(True):
        if not isinstance(tag, Tag):
            continue
        if tag.name in _SKIP_TAGS:
            continue
        tag_id = id(tag)
        if tag_id in hidden_tag_ids:
            # Already recorded as a descendant of a hidden container.
            continue

        is_hidden, reason = _is_hidden(tag)
        if is_hidden:
            text = tag.get_text(separator=" ", strip=True)
            # Skip purely decorative / icon elements: aria-hidden or class-based
            # hiding of content that is 1-2 chars (e.g. icon glyphs, ✓, ×).
            # These are legitimate accessibility patterns, not injection surfaces.
            # Hard CSS hiding (display:none, visibility:hidden, html[hidden]) is
            # always flagged regardless of text length.
            if text and len(text) <= 2 and reason.startswith(("aria-hidden", "class:")):
                hidden_tag_ids.add(tag_id)
                for descendant in tag.find_all(True):
                    hidden_tag_ids.add(id(descendant))
                continue
            if text:
                results.append(
                    HiddenElement(
                        tag_name=tag.name,
                        source_hint=f"hidden:{_source_hint(tag)}",
                        text=text,
                        reason=reason,
                    )
                )
            # Mark this tag and all its descendants as hidden regardless of
            # whether they produced text, so visible_blocks excludes them.
            hidden_tag_ids.add(tag_id)
            for descendant in tag.find_all(True):
                hidden_tag_ids.add(id(descendant))

    return results, hidden_tag_ids


def _extract_visible_blocks(
    soup: BeautifulSoup,
    hidden_tag_ids: set[int],
) -> list[TextBlock]:
    """
    Extract meaningful text blocks from visible, non-skipped elements.

    Strategy: walk block-level elements in document order.  For each block
    that is not inside a skipped or hidden container, collect its direct text
    (excluding the text of any nested block — those will be their own entries).

    Additionally captures bare NavigableString children of the <body> element
    (text that is not wrapped in any HTML element) so top-level injected text
    is not silently discarded.
    """
    results: list[TextBlock] = []
    body = soup.find("body") or soup

    if not isinstance(body, Tag):
        return results

    # ── Bare text nodes directly under <body> ─────────────────────────────────
    # Text nodes at body level (not inside any element) are valid injection
    # surfaces and must not be dropped silently.
    for child in body.children:
        if isinstance(child, NavigableString) and not isinstance(child, Comment):
            text = str(child).strip()
            if text:
                results.append(
                    TextBlock(
                        tag_name="body",
                        source_hint="body#text",
                        text=text,
                    )
                )

    def _walk(node: Tag) -> None:
        for child in node.children:
            if not isinstance(child, Tag):
                continue
            if child.name in _SKIP_TAGS:
                continue
            if id(child) in hidden_tag_ids:
                continue

            if child.name in _BLOCK_TAGS:
                # Collect only direct text children (not text inside nested blocks).
                direct_text_parts: list[str] = []
                for sub in child.children:
                    if isinstance(sub, NavigableString) and not isinstance(sub, Comment):
                        direct_text_parts.append(str(sub))
                    elif isinstance(sub, Tag) and sub.name not in _BLOCK_TAGS:
                        if sub.name not in _SKIP_TAGS and id(sub) not in hidden_tag_ids:
                            direct_text_parts.append(sub.get_text(separator=" "))

                text = " ".join(direct_text_parts).strip()
                if text:
                    results.append(
                        TextBlock(
                            tag_name=child.name,
                            source_hint=_source_hint(child),
                            text=text,
                        )
                    )
                # Recurse into the block to find nested blocks.
                _walk(child)
            else:
                _walk(child)

    _walk(body)
    return results
