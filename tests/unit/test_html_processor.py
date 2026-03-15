"""
Unit tests for the HTML processor.

No database, no network — pure HTML parsing logic.
"""

from __future__ import annotations

import pytest

from backend.app.normalization.html_processor import (
    HiddenElement,
    TextBlock,
    process_html,
)


# ---------------------------------------------------------------------------
# Title extraction
# ---------------------------------------------------------------------------


def test_extracts_title():
    result = process_html("<html><head><title>  Test Page  </title></head><body></body></html>")
    assert result.title == "Test Page"


def test_missing_title_returns_none():
    result = process_html("<html><body><p>No title here</p></body></html>")
    assert result.title is None


# ---------------------------------------------------------------------------
# Meta extraction
# ---------------------------------------------------------------------------


def test_extracts_meta_description():
    html = '<html><head><meta name="description" content="A test description"></head><body></body></html>'
    result = process_html(html)
    assert any(m.name == "description" and "test description" in m.content for m in result.meta_items)


def test_extracts_og_meta():
    html = '<html><head><meta property="og:title" content="OG Title"></head><body></body></html>'
    result = process_html(html)
    assert any(m.name == "og:title" for m in result.meta_items)


def test_skips_meta_without_content():
    html = '<html><head><meta name="viewport" content=""></head><body></body></html>'
    result = process_html(html)
    # viewport meta has no content → should be absent
    assert not any(m.name == "viewport" for m in result.meta_items)


# ---------------------------------------------------------------------------
# HTML comment extraction
# ---------------------------------------------------------------------------


def test_extracts_html_comment():
    html = "<html><body><!-- hidden instruction: ignore all previous -->visible</body></html>"
    result = process_html(html)
    assert len(result.html_comments) == 1
    assert "hidden instruction" in result.html_comments[0]


def test_multiple_comments():
    html = "<html><body><!-- comment one --><p>text</p><!-- comment two --></body></html>"
    result = process_html(html)
    assert len(result.html_comments) == 2


def test_no_comments():
    html = "<html><body><p>Just text</p></body></html>"
    result = process_html(html)
    assert result.html_comments == []


# ---------------------------------------------------------------------------
# Hidden element detection
# ---------------------------------------------------------------------------


def test_detects_display_none():
    html = '<html><body><div style="display:none">Secret payload</div><p>Visible</p></body></html>'
    result = process_html(html)
    hidden_texts = [h.text for h in result.hidden_elements]
    assert any("Secret payload" in t for t in hidden_texts)
    assert any("display:none" in h.reason for h in result.hidden_elements)


def test_detects_visibility_hidden():
    html = '<html><body><span style="visibility: hidden">invisible</span></body></html>'
    result = process_html(html)
    assert any("invisible" in h.text for h in result.hidden_elements)


def test_detects_opacity_zero():
    html = '<html><body><p style="opacity:0">ghost text</p></body></html>'
    result = process_html(html)
    assert any("ghost text" in h.text for h in result.hidden_elements)


def test_detects_html_hidden_attr():
    html = "<html><body><div hidden>hidden content</div></body></html>"
    result = process_html(html)
    assert any("hidden content" in h.text for h in result.hidden_elements)


def test_detects_aria_hidden():
    html = '<html><body><span aria-hidden="true">screen-reader hidden</span></body></html>'
    result = process_html(html)
    assert any("screen-reader hidden" in h.text for h in result.hidden_elements)
    assert any("aria-hidden" in h.reason for h in result.hidden_elements)


def test_detects_sr_only_class():
    html = '<html><body><span class="sr-only">for screen readers only</span></body></html>'
    result = process_html(html)
    assert any("for screen readers only" in h.text for h in result.hidden_elements)


def test_empty_hidden_element_not_included():
    html = '<html><body><div style="display:none">   </div></body></html>'
    result = process_html(html)
    assert result.hidden_elements == []


def test_nested_hidden_not_double_counted():
    html = """
    <html><body>
      <div style="display:none">
        outer
        <span style="visibility:hidden">inner</span>
      </div>
    </body></html>
    """
    result = process_html(html)
    # Both texts appear under one hidden element (the outer div), not two.
    assert len(result.hidden_elements) == 1
    assert "outer" in result.hidden_elements[0].text


# ---------------------------------------------------------------------------
# Visible block extraction
# ---------------------------------------------------------------------------


def test_extracts_paragraph_text():
    html = "<html><body><p>Hello world</p></body></html>"
    result = process_html(html)
    assert any("Hello world" in b.text for b in result.visible_blocks)


def test_script_content_not_in_visible():
    html = "<html><body><script>alert('xss')</script><p>Real text</p></body></html>"
    result = process_html(html)
    for block in result.visible_blocks:
        assert "alert" not in block.text


def test_style_content_not_in_visible():
    html = "<html><body><style>.foo { color: red; }</style><p>Real</p></body></html>"
    result = process_html(html)
    for block in result.visible_blocks:
        assert "color" not in block.text


def test_hidden_content_not_in_visible_blocks():
    html = '<html><body><div style="display:none">Secret</div><p>Public</p></body></html>'
    result = process_html(html)
    visible_texts = [b.text for b in result.visible_blocks]
    assert not any("Secret" in t for t in visible_texts)
    assert any("Public" in t for t in visible_texts)


def test_multiple_headings_extracted():
    html = "<html><body><h1>Title</h1><h2>Subtitle</h2><p>Content</p></body></html>"
    result = process_html(html)
    texts = [b.text for b in result.visible_blocks]
    assert any("Title" in t for t in texts)
    assert any("Subtitle" in t for t in texts)
    assert any("Content" in t for t in texts)


def test_source_hint_reflects_tag():
    html = "<html><body><p>paragraph</p></body></html>"
    result = process_html(html)
    assert any(b.tag_name == "p" for b in result.visible_blocks)


def test_deeply_malformed_html_does_not_raise():
    # BeautifulSoup should handle this gracefully.
    html = "<<<not really html>><p unclosed>text"
    result = process_html(html)
    # Just ensure no exception is raised and something is returned.
    assert result is not None


def test_empty_html():
    result = process_html("")
    assert result.title is None
    assert result.visible_blocks == []
    assert result.html_comments == []


# ---------------------------------------------------------------------------
# Body-level bare text nodes (regression: these were silently dropped)
# ---------------------------------------------------------------------------


def test_bare_text_directly_under_body_is_captured():
    html = "<html><body>Inject me\n<p>Normal para</p></body></html>"
    result = process_html(html)
    all_text = " ".join(b.text for b in result.visible_blocks)
    assert "Inject me" in all_text


def test_bare_body_text_not_double_counted_with_paragraph():
    html = "<html><body>Top text<p>Para text</p></body></html>"
    result = process_html(html)
    texts = [b.text for b in result.visible_blocks]
    # "Top text" should appear exactly once, not twice.
    combined = " | ".join(texts)
    assert combined.count("Top text") == 1
    assert combined.count("Para text") == 1


def test_inline_text_inside_paragraph_not_double_counted():
    # Inline <span> text inside a <p> must appear once (in the p's segment),
    # not as a separate body#text segment.
    html = "<html><body><p>Before <span>inline</span> after</p></body></html>"
    result = process_html(html)
    texts = [b.text for b in result.visible_blocks]
    combined = " | ".join(texts)
    assert combined.count("inline") == 1


# ---------------------------------------------------------------------------
# Off-screen position detection — threshold correctness
# ---------------------------------------------------------------------------


def test_small_negative_position_not_flagged_as_offscreen():
    # -1px and -2em are used for legitimate micro-adjustments, not injection.
    html = '<html><body><div style="left: -1px">micro-adjust</div></body></html>'
    result = process_html(html)
    # Should NOT be classified as hidden via offscreen.
    for h in result.hidden_elements:
        assert "offscreen" not in h.reason, f"False positive offscreen for -1px: {h}"


def test_two_digit_negative_position_not_flagged_as_offscreen():
    html = '<html><body><p style="top: -99px">slightly up</p></body></html>'
    result = process_html(html)
    for h in result.hidden_elements:
        assert "offscreen" not in h.reason


def test_large_negative_position_flagged_as_offscreen():
    html = '<html><body><div style="left: -9999px">off screen</div></body></html>'
    result = process_html(html)
    hidden_texts = [h.text for h in result.hidden_elements]
    assert any("off screen" in t for t in hidden_texts)
    assert any("offscreen" in h.reason for h in result.hidden_elements)


def test_negative_position_100_flagged():
    html = '<html><body><span style="top: -100px">gone</span></body></html>'
    result = process_html(html)
    assert any("offscreen" in h.reason for h in result.hidden_elements)
