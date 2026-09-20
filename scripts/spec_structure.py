"""Shared bounded Markdown structure/provenance parser for MsgRiver revision-3 E5.

This module owns the single source of truth for release-canonical Markdown
lexing used by the spec-universe extractor (``extract_spec_universe``), the
universe checker (``check_spec_universe``), and the canonical spec checker
(``check_specs``).  No consumer may reconstruct a span, infer a table
independently, or apply a second definition/visibility/sentence/RFC lexer.

Public surface:

* ``parse_spec_structure_v1(canonical_document, canonical_path)`` returns the
  frozen ownership tree with exact source/visible provenance for every unit.
* ``render_visible_v1(source)`` is the shared inline renderer; it produces the
  semantic text plus offset-aware code/autolink provenance used by the frozen
  sentence splitter and the RFC-2119/ambiguity lexers.

Everything is stdlib-only, deterministic, byte-bounded, and free of clock,
locale, environment, network, or filesystem state.
"""

from __future__ import annotations

import re
import unicodedata
from typing import List, Optional, Tuple

__all__ = ["parse_spec_structure_v1", "render_visible_v1", "validate_structure", "StructureError"]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

UNIT_KINDS = frozenset(
    {"document", "section", "definition", "block", "table", "clause", "table_row"}
)
BLOCK_KINDS = frozenset({"paragraph", "list_item", "blockquote", "fenced_code"})
LEAF_KINDS = frozenset({"clause", "table_row"})

RFC_TOKENS = ("MUST NOT", "SHOULD NOT", "MUST", "SHOULD", "MAY")
_RFC_RE = re.compile(
    r"(?<![A-Za-z0-9_])(MUST NOT|SHOULD NOT|MUST|SHOULD|MAY)(?![A-Za-z0-9_])"
)

PRODUCT_PATH = "specs/product.md"
ARCHITECTURE_PATH = "specs/architecture.md"

# Frozen raw-input bounds (A-17.1).  A complete source line may carry at most
# 8,192 Unicode characters and a whole document at most 1,048,576; both are
# enforced before entity decoding, fence classification, HTML, Markdown,
# rendering, or table work.  Unicode Bidi_Control code points are rejected
# (never silently deleted) in both literal and entity-encoded form.
MAX_LINE_CHARS = 8_192
MAX_DOCUMENT_CHARS = 1_048_576
BIDI_CONTROLS = frozenset(
    {
        0x061C,  # ARABIC LETTER MARK
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
        0x202A,  # LEFT-TO-RIGHT EMBEDDING
        0x202B,  # RIGHT-TO-LEFT EMBEDDING
        0x202C,  # POP DIRECTIONAL FORMATTING
        0x202D,  # LEFT-TO-RIGHT OVERRIDE
        0x202E,  # RIGHT-TO-LEFT OVERRIDE
        0x2066,  # LEFT-TO-RIGHT ISOLATE
        0x2067,  # RIGHT-TO-LEFT ISOLATE
        0x2068,  # FIRST STRONG ISOLATE
        0x2069,  # POP DIRECTIONAL ISOLATE
    }
)


class StructureError(Exception):
    """Raised when canonical Markdown is structurally ambiguous or invalid."""


# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------


def canonicalize_release(source: bytes) -> bytes:
    """Apply ``utf8-newlines-v1``: normalize line endings and pin one terminal LF."""
    if not isinstance(source, (bytes, bytearray)):
        raise StructureError("canonicalization requires bytes")
    decoded = bytes(source).replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return decoded.rstrip(b"\n") + b"\n"


def _enforce_source_bounds(canonical: bytes) -> str:
    """Decode canonical bytes and enforce the frozen line/document character bounds.

    Returns the decoded text.  The line bound counts Unicode characters per
    complete source line and the document bound counts total characters; both
    fire before any entity decoding, fence classification, or rendering.
    """
    try:
        text = canonical.decode("utf-8")
    except UnicodeDecodeError as error:
        raise StructureError(f"canonical document is not UTF-8: {error}")
    if len(text) > MAX_DOCUMENT_CHARS:
        raise StructureError("document exceeds the frozen source-character bound")
    line_start = 0
    for index, ch in enumerate(text):
        if ch == "\n":
            if index - line_start > MAX_LINE_CHARS:
                raise StructureError("source line exceeds the frozen line bound")
            line_start = index + 1
    if len(text) - line_start > MAX_LINE_CHARS:
        raise StructureError("source line exceeds the frozen line bound")
    return text


def _reject_bidi_controls(text: str) -> None:
    """Reject every literal or entity-encoded Unicode Bidi_Control code point.

    This is the bounded visibility/control pass: it entity-decodes only to expose
    encoded bidi controls and performs no structural work.  It runs before fence
    classification or structural parsing so a bidi control can never reach a later
    pass regardless of its structural context (including inside a code fence).
    """
    index = 0
    length = len(text)
    while index < length:
        ch = text[index]
        if ch == "&":
            match = _ENTITY_RE.match(text, index)
            if match is not None:
                decoded = _decode_entity(match)
                if any(ord(c) in BIDI_CONTROLS for c in decoded):
                    raise StructureError("entity-encoded Unicode Bidi_Control is forbidden")
                index = match.end()
                continue
        if ord(ch) in BIDI_CONTROLS:
            raise StructureError("Unicode Bidi_Control character is forbidden")
        index += 1



# ---------------------------------------------------------------------------
# Inline rendering (render_visible_v1)
# ---------------------------------------------------------------------------

_MARKDOWN_ESCAPABLE = frozenset("\\`*_{}[]()#+!.<>|~\"'-")
_AUTOLINK_RE = re.compile(r"<([A-Za-z][A-Za-z0-9+.\-]{1,31}:[^\s<>`]+?)>")
_HTML_TAG_RE = re.compile(r"</?[A-Za-z][A-Za-z0-9\-]*(?:\s[^<>]*?)?/?>")
_ENTITY_RE = re.compile(r"&(#[0-9]+|#[Xx][0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]+);")

# Whole-document raw-HTML model (A-17.1).  One coherent stream/stack validates
# tag matching and visibility; ambiguous or rendering-affecting markup fails
# closed rather than being silently recovered.
MAX_HTML_NESTING = 64
_HTML_VOID_ELEMENTS = frozenset(
    {"area", "base", "br", "col", "embed", "hr", "img", "input",
     "link", "meta", "param", "source", "track", "wbr"}
)
# Raw-text elements whose content is never visible.  script/style/template are
# the CSS-free hidden model; their content is consumed up to the matching close.
_HTML_HIDDEN_RAWTEXT = frozenset({"script", "style", "template"})
_HTML_COMMENT_OPEN = "<!--"
_HTML_CDATA_OPEN = "<![CDATA["
_HTML_COMMENT_CLOSE = "-->"
_HTML_CDATA_CLOSE = "]]>"
_HTML_DECL_RE = re.compile(r"<![A-Z][^>]*>")
_HTML_PI_RE = re.compile(r"<\?.*?\?>")
_HTML_TAG_CLOSE_RE = re.compile(r"</([A-Za-z][A-Za-z0-9\-]*)([^>]*)>")
_HTML_ATTR_NAME_RE = re.compile(r"[A-Za-z_:][A-Za-z0-9_.:\-]*")
_HTML_ATTR_SPACE = frozenset(" \t\f")
_HTML_ASCII_WHITESPACE_RE = re.compile(r"[ \t\n\f\r]+")
_HTML_UNQUOTED_FORBIDDEN = frozenset("\"'`=<>")
_HTML_BLOCK_ELEMENTS = frozenset(
    {"address", "article", "aside", "blockquote", "details", "dialog", "dd",
     "div", "dl", "dt", "fieldset", "figcaption", "figure", "footer", "form",
     "h1", "h2", "h3", "h4", "h5", "h6", "header", "hgroup", "hr", "li",
     "main", "nav", "ol", "p", "pre", "section", "table", "tbody", "td",
     "tfoot", "th", "thead", "tr", "ul"}
)
_HTML_BLOCK_START_RE = re.compile(
    r"<(" + "|".join(sorted(_HTML_BLOCK_ELEMENTS)) + r")\b",
    re.IGNORECASE,
)

# Closed A-17.1 modeled-element visibility vocabulary, mirroring the canonical
# checker's frozen HTML constants exactly.  An opening tag whose name is not in
# this set is an unmodeled/legacy element (e.g. ``<center>``, ``<font>``) and
# fails closed before any rendering; a rendering-affecting element or attribute
# fails closed the same way.  script/style/template stay hidden (raw-text).
_HTML_BREAK_ELEMENTS = frozenset({"br", "hr", "wbr"})
_HTML_CONTEXTUAL_VISIBILITY_ELEMENTS = frozenset(
    {"audio", "canvas", "datalist", "details", "dialog", "iframe", "img",
     "math", "noscript", "object", "picture", "svg", "title", "video"}
)
_HTML_INLINE_VISIBLE_ELEMENTS = frozenset(
    {"a", "abbr", "b", "cite", "code", "data", "del", "dfn", "em", "i",
     "ins", "kbd", "label", "mark", "q", "s", "samp", "small", "span",
     "strong", "sub", "sup", "time", "u", "var"}
)
_HTML_VISIBLE_STRUCTURAL_ELEMENTS = frozenset(
    {"address", "article", "aside", "body", "blockquote", "caption", "dd",
     "div", "dl", "dt", "fieldset", "figcaption", "figure", "footer", "form",
     "h1", "h2", "h3", "h4", "h5", "h6", "header", "hgroup", "html", "legend",
     "li", "main", "menu", "nav", "ol", "p", "pre", "search", "section",
     "table", "tbody", "td", "tfoot", "th", "thead", "tr", "ul"}
)
_HTML_MODELED_ELEMENTS = (
    _HTML_BREAK_ELEMENTS
    | _HTML_CONTEXTUAL_VISIBILITY_ELEMENTS
    | _HTML_HIDDEN_RAWTEXT
    | _HTML_INLINE_VISIBLE_ELEMENTS
    | _HTML_VISIBLE_STRUCTURAL_ELEMENTS
    | frozenset({"link"})
)
_HTML_RENDERING_ATTRS = frozenset({"class", "dir", "id", "popover", "style"})

_MAX_MARKDOWN_NESTING = 64
_FenceContainer = Tuple[Tuple[str, int], ...]


def _markdown_tab_width(column: int) -> int:
    """Return the CommonMark width of a tab beginning at one visual column."""
    return 4 - column % 4


def _markdown_list_marker(
    line: str, position: int, column: int
) -> Optional[Tuple[int, int, Optional[int], int]]:
    """Return raw/visual content starts, ordered value, and visual padding."""
    marker_start = position
    ordered_value: Optional[int] = None
    if position < len(line) and line[position] in "-*+":
        marker_end = position + 1
    elif (
        position < len(line)
        and line[position].isascii()
        and line[position].isdigit()
    ):
        marker_end = position
        while (
            marker_end < len(line)
            and line[marker_end].isascii()
            and line[marker_end].isdigit()
        ):
            marker_end += 1
        if (
            marker_end - position > 9
            or marker_end >= len(line)
            or line[marker_end] not in ".)"
        ):
            return None
        ordered_value = int(line[position:marker_end])
        marker_end += 1
    else:
        return None

    marker_column = column + marker_end - marker_start
    if marker_end >= len(line) or line[marker_end] not in " \t":
        return None
    whitespace_end = marker_end
    whitespace_column = marker_column
    while whitespace_end < len(line) and line[whitespace_end] in " \t":
        if line[whitespace_end] == "\t":
            whitespace_column += _markdown_tab_width(whitespace_column)
        else:
            whitespace_column += 1
        whitespace_end += 1
    return (
        whitespace_end,
        whitespace_column,
        ordered_value,
        whitespace_column - marker_column,
    )


def _markdown_leading_indentation(
    source: str, start_column: int = 0
) -> Tuple[int, int]:
    """Return raw leading-whitespace bytes and their tab-expanded width."""
    position = 0
    column = start_column
    while position < len(source) and source[position] in " \t":
        if source[position] == "\t":
            column += _markdown_tab_width(column)
        else:
            column += 1
        position += 1
    return position, column - start_column


def _markdown_normalized_indentation_view(
    source: str, start_column: int, remove_columns: int
) -> Optional[Tuple[str, int]]:
    """Expand only leading indentation and remove proven container columns."""
    raw_width, visual_width = _markdown_leading_indentation(source, start_column)
    if visual_width < remove_columns:
        return None
    return " " * (visual_width - remove_columns) + source[raw_width:], raw_width


def _markdown_fence_opening_content(line: str) -> Tuple[str, _FenceContainer]:
    """Return content after a bounded blockquote/list container prefix."""
    position = 0
    column = 0
    tokens: List[Tuple[str, int]] = []
    while position < len(line):
        start = position
        start_column = column
        spaces = 0
        while position < len(line) and line[position] == " " and spaces < 3:
            position += 1
            column += 1
            spaces += 1
        if position < len(line) and line[position] == ">":
            position += 1
            column += 1
            if position < len(line) and line[position] == " ":
                position += 1
                column += 1
            tokens.append(("quote", column - start_column))
        else:
            marker = _markdown_list_marker(line, position, column)
            if marker is None or marker[3] > 4:
                position = start
                column = start_column
                break
            position, column, _, _ = marker
            tokens.append(("list", column - start_column))
        if len(tokens) > _MAX_MARKDOWN_NESTING:
            raise StructureError("Markdown fence container nesting exceeds bound")
    return line[position:], tuple(tokens)


def _markdown_fence_continuation_content(
    line: str, container: _FenceContainer
) -> Optional[str]:
    """Strip the exact continuation prefix for a recognized fence container."""
    content = line
    column = 0
    for kind, width in container:
        if kind == "quote":
            position = 0
            spaces = 0
            while (
                position < len(content)
                and content[position] == " "
                and spaces < 3
            ):
                position += 1
                column += 1
                spaces += 1
            if position >= len(content) or content[position] != ">":
                return None
            position += 1
            column += 1
            if position < len(content) and content[position] == " ":
                position += 1
                column += 1
            content = content[position:]
        else:
            normalized = _markdown_normalized_indentation_view(
                content, column, width
            )
            if normalized is None:
                return None
            content, _ = normalized
            column += width
    return content


def _markdown_fence_opening(
    line: str,
) -> Optional[Tuple[str, int, _FenceContainer]]:
    """Return one valid bounded GFM fence opener and its container."""
    content, container = _markdown_fence_opening_content(line)
    match = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", content)
    if match is None:
        return None
    marker, info = match.groups()
    if marker[0] == "`" and "`" in info:
        return None
    return marker[0], len(marker), container


def _markdown_fenced_code_spans(
    source: str,
) -> List[Tuple[int, int, int, int]]:
    """Return opener/content/closer offsets for bounded GFM fences.

    The returned tuples match the inline-code span shape: marker start,
    payload start, payload end, and marker end. Container prefixes remain
    outside the span, while the payload (including info/source line breaks)
    retains visible code provenance. An unclosed fence owns through its exact
    container boundary or EOF and has an empty closing-marker range.
    """
    if len(source) > MAX_DOCUMENT_CHARS:
        raise StructureError("document exceeds the frozen source-character bound")
    spans: List[Tuple[int, int, int, int]] = []
    active: Optional[
        Tuple[str, int, _FenceContainer, int, int]
    ] = None
    offset = 0
    for raw_line in source.splitlines(keepends=True):
        line = raw_line.rstrip("\r\n")
        next_offset = offset + len(raw_line)
        if active is not None:
            character, width, container, opening_start, payload_start = active
            content = _markdown_fence_continuation_content(line, container)
            if content is not None:
                if re.fullmatch(
                    rf" {{0,3}}{re.escape(character)}{{{width},}}[ \t]*",
                    content,
                ):
                    closing = re.search(
                        rf"({re.escape(character)}{{{width},}})[ \t]*$",
                        line,
                    )
                    if closing is None:
                        raise StructureError("fence closer lost raw-source provenance")
                    spans.append(
                        (
                            opening_start,
                            payload_start,
                            offset + closing.start(1),
                            offset + closing.end(1),
                        )
                    )
                    active = None
                offset = next_offset
                continue
            # Leaving a quote/list container terminates its unclosed fence
            # before the dedented source line, which is processed normally.
            spans.append((opening_start, payload_start, offset, offset))
            active = None

        opening = _markdown_fence_opening(line)
        if opening is not None:
            character, width, container = opening
            content, _ = _markdown_fence_opening_content(line)
            match = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", content)
            if match is None:
                raise StructureError("fence opener lost raw-source provenance")
            content_offset = len(line) - len(content)
            opening_start = offset + content_offset + match.start(1)
            active = (
                character,
                width,
                container,
                opening_start,
                opening_start + width,
            )
        offset = next_offset
    if active is not None:
        _character, _width, _container, opening_start, payload_start = active
        spans.append((opening_start, payload_start, len(source), len(source)))
    return spans


def _fenced_code_mask(text: str) -> List[bool]:
    """Mark complete fenced-code spans before inline/HTML interpretation."""
    mask = [False] * len(text)
    for start, _payload_start, _payload_end, end in _markdown_fenced_code_spans(text):
        mask[start:end] = [True] * (end - start)
    return mask


def _backtick_runs(
    text: str, excluded: Optional[List[bool]] = None
) -> List[Tuple[int, int]]:
    """Return maximal half-open backtick runs in source order."""
    runs: List[Tuple[int, int]] = []
    index = 0
    while index < len(text):
        if text[index] != "`" or (excluded is not None and excluded[index]):
            index += 1
            continue
        end = index + 1
        while (
            end < len(text)
            and text[end] == "`"
            and (excluded is None or not excluded[end])
        ):
            end += 1
        runs.append((index, end))
        index = end
    return runs


def _inline_code_spans(
    text: str, excluded: Optional[List[bool]] = None
) -> List[Tuple[int, int, int, int]]:
    """Return matched code spans as opener/content/closer boundaries in O(n).

    Each tuple is ``(opener_start, content_start, content_end, closer_end)``.
    A block-keyed reverse width table finds the nearest later eligible backtick
    run at least as wide as each opener. Updating widths 1..run-width is linear
    overall because maximal runs are disjoint and their widths sum to at most
    the source size.
    """
    length = len(text)
    if length == 0 or "`" not in text:
        return []
    if excluded is not None and len(excluded) != length:
        raise StructureError("inline-code exclusion mask length mismatch")
    escaped = _link_escape_mask(text)
    runs = _backtick_runs(text, excluded)
    if not runs:
        return []
    boundary_offsets = _inline_block_boundaries(text)
    run_blocks: List[int] = []
    block = 0
    scanned_through = 0
    for start, _end in runs:
        while scanned_through <= start:
            if scanned_through in boundary_offsets:
                block += 1
            scanned_through += 1
        run_blocks.append(block)

    nearest_by_block_width: dict[Tuple[int, int], int] = {}
    close_run_for: List[Optional[int]] = [None] * len(runs)
    opener_starts: List[int] = []
    for start, end in runs:
        opener_starts.append(start + 1 if escaped[start] else start)

    for run_index in range(len(runs) - 1, -1, -1):
        start, end = runs[run_index]
        opener_width = end - opener_starts[run_index]
        if opener_width > 0:
            close_run_for[run_index] = nearest_by_block_width.get(
                (run_blocks[run_index], opener_width)
            )
        for width in range(1, end - start + 1):
            nearest_by_block_width[(run_blocks[run_index], width)] = run_index

    spans: List[Tuple[int, int, int, int]] = []
    consumed_through = 0
    for run_index, (start, end) in enumerate(runs):
        opener_start = opener_starts[run_index]
        if opener_start >= end or opener_start < consumed_through:
            continue
        close_run_index = close_run_for[run_index]
        if close_run_index is None:
            continue
        close_start, close_end = runs[close_run_index]
        spans.append((opener_start, end, close_start, close_end))
        consumed_through = close_end
    return spans


def _table_code_span_ends(text: str) -> dict[int, int]:
    """Map every table-cell opener suffix to its linear-time closer end.

    Unlike the renderer, the frozen table splitter retries the next suffix of
    an unmatched backtick run as a shorter opener. Enumerating those suffixes
    and updating the reverse width table are both linear because maximal run
    widths sum to at most the source length.
    """
    if not text or "`" not in text:
        return {}
    escaped = _link_escape_mask(text)
    runs = _backtick_runs(text)
    maximum_width = max(end - start for start, end in runs)
    nearest_by_width: List[Optional[int]] = [None] * (maximum_width + 1)
    span_ends: dict[int, int] = {}
    for run_index in range(len(runs) - 1, -1, -1):
        start, end = runs[run_index]
        for opener in range(start, end):
            if escaped[opener]:
                continue
            close_run_index = nearest_by_width[end - opener]
            if close_run_index is not None:
                span_ends[opener] = runs[close_run_index][1]
        for width in range(1, end - start + 1):
            nearest_by_width[width] = run_index
    return span_ends


def _inline_code_char_ranges(text: str) -> List[Tuple[int, int]]:
    """Half-open ``[start, end)`` char ranges of matched inline-code spans."""
    return [(start, end) for start, _content, _close, end in _inline_code_spans(text)]


def _in_any_range(position: int, ranges: List[Tuple[int, int]]) -> bool:
    return any(start <= position < end for start, end in ranges)

_HTML5_ENTITIES = {
    "amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'",
    "nbsp": "\u00a0", "copy": "\u00a9", "reg": "\u00ae", "trade": "\u2122",
    "mdash": "\u2014", "ndash": "\u2013", "hellip": "\u2026",
    "rarr": "\u2192", "larr": "\u2190",
}

_DEFAULT_IGNORABLE_RANGES = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160),
    (0x17B4, 0x17B5), (0x180B, 0x180E), (0x200B, 0x200F), (0x202A, 0x202E),
    (0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0), (0xFFF9, 0xFFFB), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)


def _is_default_ignorable_char(ch: str) -> bool:
    if not ch:
        return True
    codepoint = ord(ch)
    if codepoint < 0x80:
        return False  # ASCII is never default-ignorable
    cat = unicodedata.category(ch)
    if cat == "Cf":
        return True
    for low, high in _DEFAULT_IGNORABLE_RANGES:
        if low <= codepoint <= high:
            return True
    return False


class _Char:
    __slots__ = ("text", "start", "end", "code")

    def __init__(self, text: str, start: int, end: int, code: bool) -> None:
        self.text = text
        self.start = start
        self.end = end
        self.code = code


class Visible:
    __slots__ = ("chars", "semantic")

    def __init__(self, chars: List[_Char], semantic: str) -> None:
        self.chars = chars
        self.semantic = semantic


def _build_byte_offsets(text: str) -> List[int]:
    offsets = [0] * (len(text) + 1)
    pos = 0
    for index, ch in enumerate(text):
        offsets[index] = pos
        pos += len(ch.encode("utf-8"))
    offsets[len(text)] = pos
    return offsets


def _decode_entity(match: "re.Match[str]") -> str:
    body = match.group(1)
    if body.startswith("#"):
        try:
            codepoint = int(body[2:], 16) if body[1] in "Xx" else int(body[1:])
        except ValueError:
            return match.group(0)
        if 0 <= codepoint <= 0x10FFFF:
            try:
                return chr(codepoint)
            except (ValueError, OverflowError):
                pass
        return match.group(0)
    return _HTML5_ENTITIES.get(body, match.group(0))


def _fold_whitespace(chars: List[_Char]) -> List[_Char]:
    """Collapse non-code whitespace runs to one space and trim both ends."""
    folded: List[_Char] = []
    run: Optional[List[_Char]] = None
    for ch in chars:
        if (not ch.code) and ch.text.isspace():
            # Append to one accumulator; never repeatedly copy a growing run.
            if run is None:
                run = []
            run.append(ch)
        else:
            if run is not None and folded:
                folded.append(_Char(" ", run[0].start, run[-1].end, False))
            run = None
            folded.append(ch)
    result: List[_Char] = []
    leading = True
    for ch in folded:
        if leading and ch.text == " " and not ch.code:
            continue
        leading = False
        result.append(ch)
    return result


def _is_ws_char(ch: str) -> bool:
    return bool(ch) and ch.isspace()


def _is_punct_char(ch: str) -> bool:
    if not ch:
        return False
    return unicodedata.category(ch)[0] == "P"


def _emit_range(
    chars: List[_Char], text: str, offsets: List[int], start: int, end: int, code: bool
) -> None:
    for index in range(start, end):
        ch = text[index]
        codepoint = ord(ch)
        if codepoint >= 0x80:
            if codepoint in BIDI_CONTROLS:
                raise StructureError("Unicode Bidi_Control character is forbidden")
            if _is_default_ignorable_char(ch):
                continue
        chars.append(_Char(ch, offsets[index], offsets[index + 1], code))


def _emit_entity_chars(chars: List[_Char], start: int, end: int, decoded: str) -> None:
    # Every rendered output character of a decoded entity maps to the complete
    # original entity source span (including a terminal semicolon at end of input).
    for ch in decoded:
        if ord(ch) in BIDI_CONTROLS:
            raise StructureError("Unicode Bidi_Control character is forbidden")
        if _is_default_ignorable_char(ch):
            continue
        chars.append(_Char(ch, start, end, False))


def _nfkc_chars(chars: List[_Char]) -> List[_Char]:
    """Apply NFKC to the provenance-bearing rendered characters.

    Each folded character is normalized in place; a compatibility expansion maps
    every output character to the conservative complete source span and the
    code/autolink ownership of its origin.  Because the semantic text is always
    derived from this same char list, the normalized sequence and its
    provenance/tag sequence can never diverge in length or value.
    """
    out: List[_Char] = []
    for ch in chars:
        if ord(ch.text) < 0x80:
            # ASCII is NFKC-stable, never bidi, and never default-ignorable.
            out.append(ch)
            continue
        normalized = unicodedata.normalize("NFKC", ch.text)
        for piece in normalized:
            codepoint = ord(piece)
            if codepoint in BIDI_CONTROLS:
                raise StructureError("Unicode Bidi_Control character is forbidden")
            if codepoint >= 0x80 and _is_default_ignorable_char(piece):
                continue
            out.append(_Char(piece, ch.start, ch.end, ch.code))
    return out


_LINK_PAREN_LIMIT = 32


def _code_mask(text: str) -> List[bool]:
    """Per-character Markdown-code membership for fenced and inline spans."""
    mask = _fenced_code_mask(text)
    for start, _content, _close, end in _inline_code_spans(text, mask):
        for k in range(start, end):
            mask[k] = True
    return mask


def _link_spend(work: List[int], amount: int = 1) -> None:
    """Charge bounded inline work; fail closed instead of rescanning suffixes."""
    work[0] -= amount
    if work[0] < 0:
        raise StructureError("Markdown link scan exceeds its linear work budget")


def _skip_link_ws(
    text: str, i: int, work: List[int], boundaries: set[int]
) -> Optional[Tuple[int, bool]]:
    """Skip inline whitespace, rejecting a whitespace-only blank line."""
    length = len(text)
    consumed = False
    while i < length:
        _link_spend(work)
        ch = text[i]
        if ch in " \t":
            consumed = True
            i += 1
        elif ch == "\n":
            consumed = True
            if i + 1 in boundaries:
                return None
            probe = i + 1
            while probe < length and text[probe] in " \t":
                _link_spend(work)
                probe += 1
            if probe < length and text[probe] == "\n":
                return None
            i += 1
        else:
            break
    return (i, consumed)


def _parse_inline_link(
    text: str,
    paren_pos: int,
    work: List[int],
    boundaries: set[int],
) -> Optional[int]:
    """Parse a ``(destination opt-title)`` inline link tail.

    ``paren_pos`` is the ``(`` index; returns the index past the closing ``)``
    for a grammatically complete, bounded, in-balanced tail, else ``None``.
    """
    length = len(text)
    skipped = _skip_link_ws(text, paren_pos + 1, work, boundaries)
    if skipped is None:
        return None
    i, leading_ws = skipped
    if i >= length:
        return None
    # Empty destination without a title.
    if text[i] == ")":
        return i + 1

    destination_present = True
    separator_before_title = False
    # An empty destination may be followed by a title only after whitespace.
    if leading_ws and text[i] in "\"'(":
        destination_present = False
        dest_end = i
        separator_before_title = True
    elif text[i] in "\"'":
        return None
    if text[i] == "<":
        # Angle-bracket destination: one line, no inner '<' or '>'.
        j = i + 1
        while j < length:
            _link_spend(work)
            ch = text[j]
            if ch == "\\" and j + 1 < length:
                j += 2
                continue
            if ch == "\n" or ch == "<":
                return None
            if ch == ">":
                break
            j += 1
        if j >= length or text[j] != ">":
            return None
        dest_end = j + 1
    elif destination_present:
        # Bare destination: balanced parentheses, no whitespace/quotes/<>.
        depth = 0
        j = i
        while j < length:
            _link_spend(work)
            ch = text[j]
            if ch == "\\" and j + 1 < length:
                j += 2
                continue
            if ch == "\n":
                return None
            if ch in " \t":
                break
            if ch in "<>\"'":
                return None
            if ch == "(":
                depth += 1
                if depth > _LINK_PAREN_LIMIT:
                    return None
            elif ch == ")":
                if depth == 0:
                    break
                depth -= 1
            j += 1
        if depth != 0:
            return None
        dest_end = j
    if destination_present:
        skipped = _skip_link_ws(text, dest_end, work, boundaries)
        if skipped is None:
            return None
        i, separator_before_title = skipped
    else:
        i = dest_end
    if i >= length:
        return None
    # Optional title in double-quote, single-quote, or parens.
    if i < length and text[i] in "\"'(":
        if not separator_before_title:
            return None
        close_ch = ")" if text[i] == "(" else text[i]
        j = i + 1
        closed = False
        while j < length:
            _link_spend(work)
            if text[j] == "\\" and j + 1 < length:
                j += 2
                continue
            if text[j] == "\n":
                if j + 1 in boundaries:
                    return None
                probe = j + 1
                while probe < length and text[probe] in " \t":
                    _link_spend(work)
                    probe += 1
                if probe < length and text[probe] == "\n":
                    return None
            if text[j] == close_ch:
                closed = True
                j += 1
                break
            j += 1
        if not closed:
            return None
        skipped = _skip_link_ws(text, j, work, boundaries)
        if skipped is None:
            return None
        i = skipped[0]
    if i < length and text[i] == ")":
        return i + 1
    return None


def _link_escape_mask(text: str) -> List[bool]:
    """Return whether each character is preceded by an odd backslash run."""
    escaped = [False] * len(text)
    run = 0
    for index, ch in enumerate(text):
        escaped[index] = run % 2 == 1
        run = run + 1 if ch == "\\" else 0
    return escaped


def _starts_inline_block(line: str) -> bool:
    """Conservative frozen inline-state boundary at one complete source line."""
    if line.strip() == "":
        return True
    stripped = line.lstrip(" ")
    indent = len(line) - len(stripped)
    if indent > 3:
        return False
    if re.match(r"^#{1,6}[ \t]", stripped):
        return True
    if re.match(r"^(?:[-+*][ \t]+|1[.)][ \t]+|>|[`~]{3,})", stripped):
        return True
    if stripped.startswith("|") or _HTML_BLOCK_START_RE.match(stripped):
        return True
    if re.fullmatch(r"(?:[-*_][ \t]*){3,}", stripped):
        return True
    if re.fullmatch(r"(?:=+|-+)[ \t]*", stripped):
        return True
    return False


def _inline_block_boundaries(text: str) -> set[int]:
    """Return line-start offsets at which pending inline label state is cleared."""
    boundaries = {0}
    start = 0
    length = len(text)
    while start < length:
        newline = text.find("\n", start)
        if newline < 0:
            break
        next_start = newline + 1
        next_end = text.find("\n", next_start)
        if next_end < 0:
            next_end = length
        current = text[start:newline]
        following = text[next_start:next_end]
        if current.strip() == "" or _starts_inline_block(following):
            boundaries.add(next_start)
        start = next_start
    return boundaries


def _link_label_pairs(
    text: str,
    code_mask: List[bool],
    html_mask: List[bool],
    escaped: List[bool],
    boundaries: set[int],
) -> dict[int, int]:
    """Match all in-block square brackets once, in source order."""
    pairs: dict[int, int] = {}
    stack: List[int] = []
    for index, ch in enumerate(text):
        if index in boundaries:
            stack.clear()
        if code_mask[index] or html_mask[index] or escaped[index]:
            continue
        if ch == "[":
            stack.append(index)
        elif ch == "]" and stack:
            pairs[stack.pop()] = index
    return pairs


def _invalid_link_tail_end(
    text: str, opening: int, work: List[int], boundaries: set[int]
) -> int:
    """Return a bounded literal-restoration end for an invalid parenthesized tail."""
    length = len(text)
    depth = 0
    quote = ""
    index = opening
    while index < length:
        _link_spend(work)
        ch = text[index]
        if ch == "\n":
            if index + 1 in boundaries:
                return index
            index += 1
            continue
        if ch == "\\" and index + 1 < length:
            index += 2
            continue
        if quote:
            if ch == quote:
                quote = ""
            index += 1
            continue
        if ch in "\"'":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return length


def _html_markdown_mask(
    text: str,
    code_mask: List[bool],
    literal_mask: Optional[List[bool]] = None,
    permissive: bool = False,
) -> List[bool]:
    """Mark HTML tags and hidden subtree bytes excluded from Markdown parsing.

    The same strict HTML construct parser used by token emission owns this
    visibility pass. Permissive mode discovers only tag extents for link
    pairing; the later strict pass owns validity after literal restoration is
    known. Inline-code and autolink bytes retain their established precedence.
    """
    mask = [False] * len(text)
    stack: List[Tuple[str, bool]] = []
    hidden_depth = 0
    index = 0
    while index < len(text):
        if code_mask[index]:
            index += 1
            continue
        if literal_mask is not None and literal_mask[index] and hidden_depth == 0:
            index += 1
            continue
        if text[index] == "<" and _AUTOLINK_RE.match(text, index) is None:
            try:
                result = _consume_html_construct(text, index, stack)
            except StructureError:
                if not permissive:
                    raise
                # Link pairing needs only quote-aware tag extents. Full HTML
                # validity is checked after invalid-link literal ranges are
                # known, so bytes restored by that contract are not
                # prematurely reinterpreted as HTML.
                try:
                    opening = _scan_html_open_tag(text, index)
                except StructureError:
                    opening = None
                closing = _HTML_TAG_CLOSE_RE.match(text, index)
                end = (
                    opening[0]
                    if opening is not None
                    else closing.end()
                    if closing is not None
                    else index + 1
                )
                result = (end, 0)
            if result is not None:
                end, delta = result
                mask[index:end] = [True] * (end - index)
                hidden_depth += delta
                index = end
                continue
        if hidden_depth > 0:
            mask[index] = True
        index += 1
    if stack and not permissive:
        raise StructureError("unclosed raw-HTML element fails closed")
    return mask


def _scan_link_syntax(
    text: str,
    code_mask: Optional[List[bool]] = None,
    html_mask: Optional[List[bool]] = None,
) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
    """Return sorted metadata and invalid-syntax literal ranges.

    The visible label/alt text is never metadata.  Metadata is the ``!``/``[``
    opener, the closing ``]``, and the destination/optional title (inline) or
    reference label (full/collapsed) that follows it; a complete ``[label]`` with
    no tail is a shortcut reference whose brackets are metadata.  Inline-code
    spans and backslash escapes are respected and a blank line is never crossed;
    invalid, incomplete, or block-crossing syntax is left untouched so the caller
    restores it as visible literal source.
    """
    length = len(text)
    if length == 0 or "[" not in text:
        return ([], [])
    if code_mask is None:
        code_mask = _code_mask(text)
    if html_mask is None:
        html_mask = _html_markdown_mask(text, code_mask, permissive=True)
    escaped = _link_escape_mask(text)
    boundaries = _inline_block_boundaries(text)
    pairs = _link_label_pairs(text, code_mask, html_mask, escaped, boundaries)
    # Tail parsers share one strict linear budget, preventing many malformed
    # candidate openers from repeatedly scanning the same suffix.
    work = [max(64, 32 * length)]
    meta: List[Tuple[int, int]] = []
    literals: List[Tuple[int, int]] = []
    scheduled_closes: dict[int, int] = {}
    active_labels: List[Tuple[int, bool]] = []  # (closing bracket, is_image)
    active_nonimage_labels = 0
    ignored_image_brackets: set[int] = set()
    index = 0
    while index < length:
        while active_labels and active_labels[-1][0] < index:
            _close, image = active_labels.pop()
            if not image:
                active_nonimage_labels -= 1
        scheduled_end = scheduled_closes.get(index)
        if scheduled_end is not None:
            meta.append((index, scheduled_end))
            index = scheduled_end
            while active_labels and active_labels[-1][0] < index:
                _close, image = active_labels.pop()
                if not image:
                    active_nonimage_labels -= 1
            continue
        if code_mask[index] or html_mask[index]:
            index += 1
            continue
        bracket = -1
        opener_start = index
        ch = text[index]
        is_image = False
        if ch == "!" and index + 1 < length and text[index + 1] == "[" and not escaped[index]:
            opener_start = index
            bracket = index + 1
            is_image = True
        elif ch == "[" and not escaped[index] and index not in ignored_image_brackets:
            bracket = index
        if (
            bracket >= 0
            and not code_mask[bracket]
            and not html_mask[bracket]
            and bracket in pairs
        ):
            close = pairs[bracket]
            # CommonMark does not create a nested link inside a link label;
            # complete nested images remain eligible and keep their alt visible.
            nested_link = (not is_image) and active_nonimage_labels > 0
            if nested_link:
                index = bracket + 1
                continue
            meta_end: Optional[int]
            tail = close + 1
            if tail < length and text[tail] == "(":
                meta_end = _parse_inline_link(
                    text, tail, work, boundaries
                )
            elif tail < length and text[tail] == "[":
                ref = pairs.get(tail)
                meta_end = (ref + 1) if ref is not None else None
            else:
                meta_end = tail  # shortcut reference
            if active_labels and meta_end is not None and meta_end > active_labels[-1][0]:
                meta_end = None
            if meta_end is not None:
                meta.append((opener_start, bracket + 1))  # '![' or '['
                scheduled_closes[close] = meta_end
                active_labels.append((close, is_image))
                if not is_image:
                    active_nonimage_labels += 1
                index = bracket + 1
                continue
            if tail < length and text[tail] == "(":
                literal_end = _invalid_link_tail_end(text, tail, work, boundaries)
                # An invalid nested image remains literal label content, but it
                # cannot consume the already-proven close/metadata of its
                # enclosing link or image.  Stop at the innermost scheduled
                # owner so its close is processed on the next iteration.
                if active_labels and literal_end > active_labels[-1][0]:
                    literal_end = active_labels[-1][0]
                literals.append((opener_start, literal_end))
                index = literals[-1][1]
                continue
            if is_image:
                # Do not reinterpret the bracket of one invalid image as an
                # independent shortcut link and partially hide its source.
                ignored_image_brackets.add(bracket)
                index = bracket + 1
                continue
        index += 1
    return (meta, literals)


def _scan_link_metadata(text: str) -> List[Tuple[int, int]]:
    """Compatibility helper returning only proven nonrendered metadata ranges."""
    return _scan_link_syntax(text)[0]


def _tokenize_inline(text: str) -> List[dict]:
    """Tokenize inline source into provenance-bearing spans.

    Each token is a dict.  ``lit``/``code`` carry ``[s, e)`` source ranges;
    ``entity`` carries its decoded text plus the full entity span; ``delim`` is an
    emphasis/strikethrough delimiter run awaiting matching.  Only proven matched
    delimiter runs are later removed; unmatched ones fall back to literal source.
    """
    tokens: List[dict] = []
    length = len(text)
    index = 0
    fence_spans = _markdown_fenced_code_spans(text)
    fenced_mask = [False] * length
    fence_by_start: dict[int, Tuple[int, int, int]] = {}
    for start, payload_start, payload_end, end in fence_spans:
        fenced_mask[start:end] = [True] * (end - start)
        fence_by_start[start] = (payload_start, payload_end, end)
    code_spans = _inline_code_spans(text, fenced_mask)
    code_mask = list(fenced_mask)
    code_by_start: dict[int, Tuple[int, int, int]] = {}
    for start, content_start, content_end, end in code_spans:
        code_mask[start:end] = [True] * (end - start)
        code_by_start[start] = (content_start, content_end, end)
    link_html_mask = _html_markdown_mask(text, code_mask, permissive=True)
    # Offset-preserving link/image visibility: the syntactic metadata of every
    # grammatically complete Markdown link/image construct is nonvisible.  No
    # consumer may infer link visibility or reparse Markdown independently.
    link_skips, link_literals = _scan_link_syntax(
        text, code_mask, link_html_mask
    )
    literal_mask = [False] * length
    for start, end in link_literals:
        literal_mask[start:end] = [True] * (end - start)
    # The link scanner has already proved these metadata ranges to be
    # nonrendered Markdown syntax.  Exclude them from the later strict HTML
    # interpretation so an angle destination cannot be re-owned as an HTML
    # opener/closer.  Keep ``literal_mask`` separate: invalid link syntax still
    # needs its exact source restored by token emission below.
    html_excluded_mask = list(literal_mask)
    for start, end in link_skips:
        html_excluded_mask[start:end] = [True] * (end - start)
    html_mask = _html_markdown_mask(text, code_mask, html_excluded_mask)
    skip_ptr = 0
    literal_ptr = 0
    while index < length:
        fence_span = fence_by_start.get(index)
        if fence_span is not None:
            payload_start, payload_end, closer_end = fence_span
            if payload_start > index:
                tokens.append({"kind": "skip", "s": index, "e": payload_start})
            if payload_end > payload_start:
                tokens.append(
                    {"kind": "code", "s": payload_start, "e": payload_end}
                )
            if closer_end > payload_end:
                tokens.append(
                    {"kind": "skip", "s": payload_end, "e": closer_end}
                )
            index = closer_end
            continue
        while (
            literal_ptr < len(link_literals)
            and link_literals[literal_ptr][1] <= index
        ):
            literal_ptr += 1
        if (
            literal_ptr < len(link_literals)
            and link_literals[literal_ptr][0] == index
        ):
            start, end = link_literals[literal_ptr]
            cursor = start
            while cursor < end:
                masked = html_mask[cursor]
                segment_end = cursor + 1
                while segment_end < end and html_mask[segment_end] == masked:
                    segment_end += 1
                tokens.append(
                    {
                        "kind": "skip" if masked else "lit",
                        "s": cursor,
                        "e": segment_end,
                    }
                )
                cursor = segment_end
            index = end
            literal_ptr += 1
            continue
        # Drop link-metadata ranges already passed, then skip one beginning here.
        while skip_ptr < len(link_skips) and link_skips[skip_ptr][1] <= index:
            skip_ptr += 1
        if skip_ptr < len(link_skips) and link_skips[skip_ptr][0] == index:
            start, end = link_skips[skip_ptr]
            tokens.append({"kind": "skip", "s": start, "e": end})
            index = end
            skip_ptr += 1
            continue
        if html_mask[index]:
            end = index + 1
            while end < length and html_mask[end]:
                end += 1
            tokens.append({"kind": "skip", "s": index, "e": end})
            index = end
            continue
        ch = text[index]
        if ch == "\\" and index + 1 < length and text[index + 1] in _MARKDOWN_ESCAPABLE:
            tokens.append({"kind": "lit", "s": index + 1, "e": index + 2})
            index += 2
            continue
        if ch == "`":
            span = code_by_start.get(index)
            if span is not None:
                content_start, content_end, closer_end = span
                inner = text[content_start:content_end]
                if len(inner) >= 2 and inner[0] == " " and inner[-1] == " " and inner.strip():
                    content_start += 1
                    content_end -= 1
                tokens.append({"kind": "skip", "s": index, "e": content_start})
                tokens.append({"kind": "code", "s": content_start, "e": content_end})
                tokens.append({"kind": "skip", "s": content_end, "e": closer_end})
                index = closer_end
                continue
            # Unmatched backtick run stays literal.
            run_len = 1
            while index + run_len < length and text[index + run_len] == "`":
                run_len += 1
            tokens.append({"kind": "lit", "s": index, "e": index + run_len})
            index += run_len
            continue
        if ch == "<":
            match = _AUTOLINK_RE.match(text, index)
            if match is not None:
                tokens.append({"kind": "skip", "s": index, "e": index + 1})
                tokens.append({"kind": "code", "s": index + 1, "e": match.end() - 1})
                tokens.append({"kind": "skip", "s": match.end() - 1, "e": match.end()})
                index = match.end()
                continue
            # Not a recognized HTML construct: '<' is visible literal source.
            tokens.append({"kind": "lit", "s": index, "e": index + 1})
            index += 1
            continue
        if ch == "&":
            match = _ENTITY_RE.match(text, index)
            if match is not None:
                decoded = _decode_entity(match)
                tokens.append(
                    {"kind": "entity", "s": index, "e": match.end(), "text": decoded}
                )
                index = match.end()
                continue
        if ch == "*" or ch == "_":
            run_len = 1
            while index + run_len < length and text[index + run_len] == ch:
                run_len += 1
            tokens.append(_make_delim(text, index, index + run_len, ch, run_len))
            index += run_len
            continue
        if ch == "~":
            run_len = 1
            while index + run_len < length and text[index + run_len] == "~":
                run_len += 1
            if run_len >= 2:
                tokens.append(_make_delim(text, index, index + run_len, "~", run_len))
            else:
                tokens.append({"kind": "lit", "s": index, "e": index + run_len})
            index += run_len
            continue
        tokens.append({"kind": "lit", "s": index, "e": index + 1})
        index += 1
    return tokens


def _scan_html_open_tag(
    text: str, index: int
) -> Optional[Tuple[int, str, str, bool]]:
    """Return one complete quote-aware opening tag, or ``None`` for literal ``<``.

    The returned tuple is ``(end, lowercase_name, raw_attributes, self_closing)``.
    Once ``<`` is followed by an ASCII tag-name start, incomplete, multiline, or
    quote-ambiguous syntax fails closed instead of being recovered as prose.
    """
    length = len(text)
    if (
        index + 1 >= length
        or text[index] != "<"
        or not text[index + 1].isascii()
        or not text[index + 1].isalpha()
    ):
        return None
    name_start = index + 1
    cursor = name_start + 1
    while cursor < length and (
        text[cursor].isascii() and (text[cursor].isalnum() or text[cursor] == "-")
    ):
        cursor += 1
    name = text[name_start:cursor].lower()
    attrs_start = cursor
    quote = ""
    while cursor < length:
        ch = text[cursor]
        if ch in "\r\n":
            raise StructureError("multiline HTML tag fails closed")
        if quote:
            if ch == "<":
                raise StructureError("invalid '<' in quoted HTML attribute")
            if ch == quote:
                quote = ""
            cursor += 1
            continue
        if ch in "\"'":
            quote = ch
            cursor += 1
            continue
        if ch == "<":
            raise StructureError("nested '<' in HTML tag fails closed")
        if ch == ">":
            raw_attrs = text[attrs_start:cursor]
            self_closing = raw_attrs.endswith("/")
            if self_closing:
                raw_attrs = raw_attrs[:-1]
            return (cursor + 1, name, raw_attrs, self_closing)
        cursor += 1
    raise StructureError("unclosed HTML opening tag fails closed")


def _decode_html_attribute_value(value: str) -> str:
    """Decode the same closed entity vocabulary used by visible source text."""
    pieces: List[str] = []
    cursor = 0
    length = len(value)
    while cursor < length:
        if value[cursor] == "&":
            match = _ENTITY_RE.match(value, cursor)
            if match is not None:
                pieces.append(_decode_entity(match))
                cursor = match.end()
                continue
        pieces.append(value[cursor])
        cursor += 1
    decoded = "".join(pieces)
    if any(ord(ch) in BIDI_CONTROLS for ch in decoded):
        raise StructureError("HTML attribute contains a Unicode Bidi_Control")
    return decoded


def _parse_html_attributes(raw: str) -> dict[str, Optional[str]]:
    """Parse one exact single-line attribute slice without HTML recovery rules."""
    attributes: dict[str, Optional[str]] = {}
    length = len(raw)
    cursor = 0
    while cursor < length:
        if raw[cursor] not in _HTML_ATTR_SPACE:
            raise StructureError("HTML attribute lacks an ASCII-space separator")
        while cursor < length and raw[cursor] in _HTML_ATTR_SPACE:
            cursor += 1
        if cursor == length:
            break
        match = _HTML_ATTR_NAME_RE.match(raw, cursor)
        if match is None:
            raise StructureError("malformed HTML attribute name")
        name = match.group(0).lower()
        if name in attributes:
            raise StructureError("duplicate HTML attribute name fails closed")
        cursor = match.end()
        while cursor < length and raw[cursor] in _HTML_ATTR_SPACE:
            cursor += 1
        value: Optional[str] = None
        if cursor < length and raw[cursor] == "=":
            cursor += 1
            while cursor < length and raw[cursor] in _HTML_ATTR_SPACE:
                cursor += 1
            if cursor == length:
                raise StructureError("HTML attribute value is missing")
            if raw[cursor] in "\"'":
                quote = raw[cursor]
                value_start = cursor + 1
                value_end = raw.find(quote, value_start)
                if value_end < 0:
                    raise StructureError("unterminated quoted HTML attribute")
                value = raw[value_start:value_end]
                cursor = value_end + 1
            else:
                value_start = cursor
                while cursor < length and raw[cursor] not in _HTML_ATTR_SPACE:
                    if raw[cursor] in _HTML_UNQUOTED_FORBIDDEN:
                        raise StructureError("invalid unquoted HTML attribute value")
                    cursor += 1
                if cursor == value_start:
                    raise StructureError("HTML attribute value is missing")
                value = raw[value_start:cursor]
            value = _decode_html_attribute_value(value)
        attributes[name] = value
    return attributes


def _consume_html_construct(
    text: str, index: int, stack: List[Tuple[str, bool]]
) -> Optional[Tuple[int, int]]:
    """Consume one whole-document HTML construct starting at ``index``.

    Mutates ``stack`` (open elements as ``(lowercase name, hidden-attr flag)``).
    Returns ``(end_index, hidden_depth_delta)`` for a recognized nonvisible
    construct, or ``None`` if the bytes are not an HTML construct (the caller
    then treats ``<`` as literal source).  Crossed, incomplete, unclosed,
    unmodeled, multiline, or too-deeply-nested markup raises ``StructureError``
    so the renderer never silently recovers from an ambiguous HTML stack.
    """
    # HTML comment.
    if text.startswith(_HTML_COMMENT_OPEN, index):
        close = text.find(_HTML_COMMENT_CLOSE, index + len(_HTML_COMMENT_OPEN))
        if close == -1:
            raise StructureError("unclosed HTML comment fails closed")
        end = close + len(_HTML_COMMENT_CLOSE)
        if "\n" in text[index:end]:
            raise StructureError("multiline HTML comment fails closed")
        return (end, 0)
    # CDATA section.
    if text.startswith(_HTML_CDATA_OPEN, index):
        close = text.find(_HTML_CDATA_CLOSE, index + len(_HTML_CDATA_OPEN))
        if close == -1:
            raise StructureError("unclosed HTML CDATA fails closed")
        end = close + len(_HTML_CDATA_CLOSE)
        if "\n" in text[index:end]:
            raise StructureError("multiline HTML CDATA fails closed")
        return (end, 0)
    # Processing instruction.
    if text.startswith("<?", index):
        match = _HTML_PI_RE.match(text, index)
        if match is None:
            raise StructureError("unclosed HTML processing instruction fails closed")
        if "\n" in match.group(0):
            raise StructureError("multiline HTML processing instruction fails closed")
        return (match.end(), 0)
    # Declaration such as <!DOCTYPE html>.
    if text.startswith("<!", index):
        match = _HTML_DECL_RE.match(text, index)
        if match is None:
            raise StructureError("unclosed HTML declaration fails closed")
        if "\n" in match.group(0):
            raise StructureError("multiline HTML declaration fails closed")
        return (match.end(), 0)
    # Closing tag: must match the top of the stack.
    close_match = _HTML_TAG_CLOSE_RE.match(text, index)
    if close_match is not None:
        close_suffix = close_match.group(2)
        if "\n" in close_suffix or "\r" in close_suffix:
            raise StructureError("multiline HTML close tag fails closed")
        if any(ch not in _HTML_ATTR_SPACE for ch in close_suffix):
            raise StructureError("malformed HTML close tag fails closed")
        name = close_match.group(1).lower()
        if not stack or stack[-1][0] != name:
            raise StructureError("crossed or unmatched HTML close tag fails closed")
        was_hidden = stack[-1][1]
        stack.pop()
        return (close_match.end(), -1 if was_hidden else 0)
    # Opening tag.
    open_tag = _scan_html_open_tag(text, index)
    if open_tag is not None:
        end, name, raw_attrs, self_closing = open_tag
        attributes = _parse_html_attributes(raw_attrs)
        # An opening tag is modeled only if its name belongs to the closed
        # A-17.1 vocabulary.  Unknown/legacy elements, contextual-visibility
        # elements, and rendering-affecting attributes all fail closed before
        # any rendering; valid attribute-free visible HTML and hidden/aria
        # subtrees remain modeled below.
        if name not in _HTML_MODELED_ELEMENTS:
            raise StructureError("unmodeled HTML element fails closed")
        if name in _HTML_CONTEXTUAL_VISIBILITY_ELEMENTS:
            raise StructureError("contextual-visibility HTML element fails closed")
        if _HTML_RENDERING_ATTRS.intersection(attributes):
            raise StructureError("rendering-affecting HTML attribute fails closed")
        rel = attributes.get("rel")
        rel_tokens = (
            frozenset(
                part
                for part in _HTML_ASCII_WHITESPACE_RE.split(rel.casefold())
                if part
            )
            if isinstance(rel, str)
            else frozenset()
        )
        if name == "link" and "stylesheet" in rel_tokens:
            raise StructureError("stylesheet link fails closed")
        # Raw-text hidden elements (script/style/template): content is nonvisible
        # and consumed up to the matching close in one whole-document step.
        if name in _HTML_HIDDEN_RAWTEXT:
            close_re = re.compile(r"</" + re.escape(name) + r"\s*>", re.IGNORECASE)
            content_close = close_re.search(text, end)
            if content_close is None:
                raise StructureError("unclosed raw-text HTML element fails closed")
            end = content_close.end()
            if "\n" in text[index:end]:
                raise StructureError("multiline hidden HTML subtree fails closed")
            return (end, 0)
        aria_hidden = attributes.get("aria-hidden")
        hidden_attr = "hidden" in attributes or (
            isinstance(aria_hidden, str) and aria_hidden.casefold() == "true"
        )
        if self_closing or name in _HTML_VOID_ELEMENTS:
            return (end, 0)
        if len(stack) >= MAX_HTML_NESTING:
            raise StructureError("HTML nesting exceeds the frozen depth bound")
        stack.append((name, hidden_attr))
        return (end, 1 if hidden_attr else 0)
    return None


def _make_delim(text: str, start: int, end: int, char: str, length: int) -> dict:
    before = text[start - 1] if start > 0 else ""
    after = text[end] if end < len(text) else ""
    left = (not _is_ws_char(after)) and (
        (not _is_punct_char(after)) or _is_ws_char(before) or _is_punct_char(before)
    )
    right = (not _is_ws_char(before)) and (
        (not _is_punct_char(before)) or _is_ws_char(after) or _is_punct_char(after)
    )
    if char == "_":
        can_open = left and ((not right) or _is_punct_char(before))
        can_close = right and ((not left) or _is_punct_char(after))
    else:  # "*" and "~" have no intraword restriction
        can_open = left
        can_close = right
    return {
        "kind": "delim", "s": start, "e": end, "char": char, "len": length,
        "orig": length, "can_open": can_open, "can_close": can_close,
        "lead": 0, "trail": 0,
    }


def _resolve_emphasis(tokens: List[dict]) -> None:
    """Match emphasis/strikethrough delimiter runs; mark consumed delimiter chars.

    Implements the CommonMark opener/closer algorithm with the rule of three.
    Matched delimiter characters are accounted in each run's ``lead``/``trail``
    counters and dropped at emission; any remaining characters stay literal.
    """
    delim_positions = [i for i, t in enumerate(tokens) if t["kind"] == "delim"]
    stack: List[int] = []  # indices into tokens of potential openers
    for pos in delim_positions:
        node = tokens[pos]
        while node["can_close"] and node["len"] > 0:
            match_pos = None
            for candidate in reversed(stack):
                opener = tokens[candidate]
                if opener["char"] != node["char"] or opener["len"] <= 0:
                    continue
                # Rule of three.
                if (opener["orig"] + node["orig"]) % 3 == 0 and not (
                    opener["orig"] % 3 == 0 and node["orig"] % 3 == 0
                ):
                    continue
                match_pos = candidate
                break
            if match_pos is None:
                break
            opener = tokens[match_pos]
            use = min(opener["len"], node["len"])
            opener["trail"] += use
            node["lead"] += use
            opener["len"] -= use
            node["len"] -= use
            if opener["len"] <= 0:
                stack.remove(match_pos)
        if node["can_open"] and node["len"] > 0:
            stack.append(pos)


def render_visible_v1(source: bytes) -> Visible:
    """Render structural/inline markup to folded semantic text with provenance."""
    if not isinstance(source, (bytes, bytearray)):
        raise StructureError("render_visible_v1 requires bytes")
    text = bytes(source).decode("utf-8")
    offsets = _build_byte_offsets(text)
    tokens = _tokenize_inline(text)
    _resolve_emphasis(tokens)
    chars: List[_Char] = []
    for token in tokens:
        kind = token["kind"]
        if kind == "skip":
            continue
        if kind == "lit":
            _emit_range(chars, text, offsets, token["s"], token["e"], False)
        elif kind == "code":
            _emit_range(chars, text, offsets, token["s"], token["e"], True)
        elif kind == "entity":
            _emit_entity_chars(chars, token["s"], token["e"], token["text"])
        elif kind == "delim":
            # Only the matched (consumed) delimiter characters are removed; any
            # leftover characters in the run remain visible literal source.
            lit_start = token["s"] + token["lead"]
            lit_end = token["e"] - token["trail"]
            if lit_end > lit_start:
                _emit_range(chars, text, offsets, lit_start, lit_end, False)
    chars = _fold_whitespace(chars)
    chars = _nfkc_chars(chars)
    semantic = "".join(c.text for c in chars)
    return Visible(chars=chars, semantic=semantic)


def _masked_text(visible: Visible) -> str:
    return "".join(" " if ch.code else ch.text for ch in visible.chars)


# ---------------------------------------------------------------------------
# Sentence splitter and obligation lexers
# ---------------------------------------------------------------------------

_CANONICAL_ID_PERIOD = re.compile(r"(?:PR|AC|NG|INV)-\d{3}\.$")
_SECTION_REF_PERIOD = re.compile(r"[PA]-\d{2}(?:\.\d+)*\.$")


def split_clauses(visible: Visible) -> List[Tuple[int, int]]:
    """Inclusive semantic-index ranges for each clause (separators excluded)."""
    semantic = visible.semantic
    chars = visible.chars
    total = len(semantic)
    ranges: List[Tuple[int, int]] = []
    start = 0
    index = 0
    while index < total:
        ch = semantic[index]
        if ch in ".;:" and not chars[index].code:
            after = semantic[index + 1] if index + 1 < total else ""
            if (after == " " or index + 1 == total) and _is_real_boundary(semantic, index):
                ranges.append((start, index))
                start = index + 2 if after == " " else index + 1
                index = start
                continue
        index += 1
    if start < total and semantic[start:].strip():
        ranges.append((start, total - 1))
    return ranges


def _is_real_boundary(semantic: str, index: int) -> bool:
    ch = semantic[index]
    if ch in ";:":
        return True
    prefix = semantic[: index + 1]
    if _CANONICAL_ID_PERIOD.search(prefix):
        return False
    if _SECTION_REF_PERIOD.search(prefix):
        return False
    if (
        index > 0
        and semantic[index - 1].isdigit()
        and index + 1 < len(semantic)
        and semantic[index + 1].isdigit()
    ):
        return False
    return True


def is_normative(visible: Visible) -> bool:
    return _RFC_RE.search(_masked_text(visible)) is not None


def is_ambiguous(visible: Visible) -> bool:
    return not is_normative(visible)


# ---------------------------------------------------------------------------
# Ownership tree units
# ---------------------------------------------------------------------------


class Unit:
    __slots__ = (
        "kind", "document", "section_chain", "definition_id", "definition_ordinal",
        "block_ordinal", "block_kind", "leaf_kind", "leaf_ordinal",
        "source_slice", "visible_bytes", "normative", "ambiguous", "parent_index",
        "unit_id", "content_hex",
    )

    def __init__(self, kind: str) -> None:
        self.kind = kind
        self.document = ""
        self.section_chain: List[Tuple[int, int, str]] = []
        self.definition_id = ""
        self.definition_ordinal = 0
        self.block_ordinal = 0
        self.block_kind = ""
        self.leaf_kind = ""
        self.leaf_ordinal = 0
        self.source_slice = b""
        self.visible_bytes = b""
        self.normative = False
        self.ambiguous = False
        self.parent_index = -1
        self.unit_id = ""
        self.content_hex = ""


class Structure:
    __slots__ = ("path", "source", "units")

    def __init__(self, path: str, source: bytes, units: List[Unit]) -> None:
        self.path = path
        self.source = source
        self.units = units


# ---------------------------------------------------------------------------
# Line model and small block lexers
# ---------------------------------------------------------------------------


class _Line:
    __slots__ = ("text", "start", "end")

    def __init__(self, text: str, start: int, end: int) -> None:
        self.text = text
        self.start = start
        self.end = end


def _split_lines(canonical: bytes) -> List[_Line]:
    text = canonical.decode("utf-8")
    lines: List[_Line] = []
    byte_pos = 0
    for part in text.split("\n"):
        part_bytes = part.encode("utf-8")
        start = byte_pos
        end = start + len(part_bytes)
        lines.append(_Line(part, start, end))
        byte_pos = end + 1
    if lines and lines[-1].text == "" and canonical.endswith(b"\n"):
        lines.pop()
    return lines


def _leading_spaces(text: str) -> int:
    count = 0
    for ch in text:
        if ch == " ":
            count += 1
        else:
            break
    return count


def _content_at(line: _Line, column: int) -> Optional[Tuple[str, int, int]]:
    """Return (text, start_byte, end_byte) for a line's content beginning at column."""
    if _leading_spaces(line.text) < column:
        return None
    text = line.text[column:]
    return (text, line.start + column, line.end)


_BULLET_RE = re.compile(r"^([-*+])[ \t]+")
_ORDERED_RE = re.compile(r"^([0-9]{1,9})[.)][ \t]+")
_FENCE_OPEN_RE = re.compile(r"^([`~])\1{2,}")
_TABLE_SEP_RE = re.compile(r"^\s*\|?\s*:?-{1,}:?\s*(\|\s*:?-{1,}:?\s*)*\|?\s*$")
_CLOSING_HASH_RE = re.compile(r"[ \t]+#+[ \t]*$")


def _ordered_interrupts_paragraph(text: str) -> bool:
    """Return whether an ordered marker interrupts an open paragraph."""
    marker = _ORDERED_RE.match(text)
    return marker is not None and int(marker.group(1)) == 1


def _is_h1(text: str) -> bool:
    return (
        text.startswith("# ")
        and len(text) > 2
        and text[2] not in " \t"
        and text[2:].strip() != ""
    )


_HEADINGISH_RE = re.compile(r"^#{2,6} ")


def _atx_marker_depth(text: str) -> int:
    """Return the count of leading '#' markers (0 when the line is not ATX-led)."""
    depth = 0
    for ch in text:
        if ch == "#":
            depth += 1
        else:
            break
    return depth


def _looks_like_atx_heading(text: str) -> bool:
    """True if a line begins with 1-6 ATX markers followed by a space or tab."""
    depth = _atx_marker_depth(text)
    if not 1 <= depth <= 6:
        return False
    return text[depth:depth + 1] in (" ", "\t")


def _inspect_heading(text: str, family_letter: str):
    """Classify a line: 'h1', (depth, id), 'invalid', or None (not heading-like).

    One to six ATX markers followed by a tab, or followed by one ASCII space and
    then an otherwise invalid structural separator/title, is heading-like
    *invalid* input and fails closed rather than becoming ordinary prose.
    Markers immediately followed by another character (e.g. ``#not-a-heading``)
    remain ordinary prose and are not heading-like.
    """
    depth = _atx_marker_depth(text)
    if not 1 <= depth <= 6:
        return None
    after = text[depth:]
    # Markers immediately followed by a non-space, non-tab character are prose.
    if after[:1] not in (" ", "\t"):
        return None
    # Markers followed by a tab are a heading-like invalid structural separator.
    if after[:1] == "\t":
        return "invalid"
    # Exactly one ASCII separator space is frozen; an additional space or tab
    # belongs to an invalid heading-like attempt, not to the title.
    if len(after) == 1 or after[1:2] in (" ", "\t"):
        return "invalid"
    if depth == 1:
        return "h1"
    heading = _detect_heading(text, family_letter)
    return "invalid" if heading is None else heading


def _detect_heading(text: str, family_letter: str) -> Optional[Tuple[int, str]]:
    """Return (depth, identifier) for a structural depth-2..6 heading, else None."""
    if not text.startswith("#"):
        return None
    depth = 0
    while depth < len(text) and text[depth] == "#":
        depth += 1
    if not (2 <= depth <= 6):
        return None
    # The frozen unindented ATX grammar requires exactly one ASCII space after
    # the markers; a tab is not a space.
    if depth >= len(text) or text[depth] != " ":
        return None
    body = text[depth + 1:]
    if body.strip() == "" or _CLOSING_HASH_RE.search(body):
        return None
    match = re.match(rf"^({re.escape(family_letter)}-\d{{2}}(?:\.\d+)*)\.(.*)$", body)
    if match is None:
        return None
    return (depth, match.group(1))


def _definition_id_re(path: str) -> str:
    if path == PRODUCT_PATH:
        return r"(?:PR|AC|NG)-\d{3}"
    if path == ARCHITECTURE_PATH:
        return r"INV-\d{3}"
    return r"(?:PR|AC|NG|INV)-\d{3}"


def _definition_prefix(after_marker: str, path: str) -> Optional["re.Match[str]"]:
    """Match the complete bold definition prefix (``**ID.**`` or ``**ID \u2014 desc.**``)."""
    return re.match(
        rf"^\*\*({_definition_id_re(path)})(?:\.|(?: \u2014 [^\n]*?\.))\*\*", after_marker
    )


def _definition_form(after_marker: str, path: str) -> Optional[str]:
    match = _definition_prefix(after_marker, path)
    return match.group(1) if match is not None else None


def _is_table_start(lines: List[_Line], index: int, column: int) -> bool:
    if index + 1 >= len(lines):
        return False
    first = _content_at(lines[index], column)
    second = _content_at(lines[index + 1], column)
    if first is None or second is None:
        return False
    if "|" not in first[0] or "|" not in second[0]:
        return False
    return _TABLE_SEP_RE.match(second[0]) is not None


def _split_table_cell_sources(row_text: str) -> List[str]:
    body = row_text.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|"):
        body = body[:-1]
    cells: List[str] = []
    current: List[str] = []
    index = 0
    length = len(body)
    code_span_ends = _table_code_span_ends(body)
    while index < length:
        ch = body[index]
        if ch == "\\" and index + 1 < length:
            # An escaped pipe (or any escaped byte) is a frozen nonseparator
            # channel and stays inside its cell.
            current.append(body[index + 1])
            index += 2
            continue
        if ch == "`":
            # A pipe inside a matched inline-code span stays inside its cell.
            # Reuse the table-specific linear span table while retaining the
            # frozen suffix-opener fallback for an unmatched wider run.
            closer_end = code_span_ends.get(index)
            if closer_end is not None:
                current.append(body[index:closer_end])
                index = closer_end
                continue
        if ch == "|":
            cells.append("".join(current))
            current = []
            index += 1
            continue
        current.append(ch)
        index += 1
    cells.append("".join(current))
    return cells


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class _Scope:
    """One 1-based direct-child position sequence per document/section owner.

    A direct-child section, definition, text block, fence, or table each
    consumes exactly one position; a descendant never consumes another position
    in an ancestor.  A definition carries its own scope for the blocks, fences,
    and tables in its body, so those do not consume the owner's positions.
    """

    __slots__ = ("child_position",)

    def __init__(self) -> None:
        self.child_position = 0

    def next_position(self) -> int:
        self.child_position += 1
        return self.child_position


class _SectionEntry:
    __slots__ = ("depth", "ordinal", "id", "unit_index", "scope", "start_line")

    def __init__(self, depth, ordinal, id, unit_index, scope, start_line):
        self.depth = depth
        self.ordinal = ordinal
        self.id = id
        self.unit_index = unit_index
        self.scope = scope
        self.start_line = start_line


class _Parser:
    def __init__(self, canonical: bytes, path: str) -> None:
        self.canonical = canonical
        self.path = path
        self.lines = _split_lines(canonical)
        self.family_letter = "P" if path == PRODUCT_PATH else "A"
        self.units: List[Unit] = []
        self.seen_section_ids: set[str] = set()
        self.section_stack: List[_SectionEntry] = []
        self.doc_scope = _Scope()

    # -- chain / owner helpers -----------------------------------------

    def _chain(self) -> List[Tuple[int, int, str]]:
        return [(e.depth, e.ordinal, e.id) for e in self.section_stack]

    def _container_index(self) -> int:
        return self.section_stack[-1].unit_index if self.section_stack else 0

    def _container_scope(self) -> _Scope:
        return self.section_stack[-1].scope if self.section_stack else self.doc_scope

    # -- document ------------------------------------------------------

    def parse(self) -> Structure:
        if not self.lines:
            raise StructureError("empty canonical document")
        first = self.lines[0]
        if first.start != 0 or not _is_h1(first.text):
            raise StructureError("document must begin with a single H1 title at byte zero")
        if first.text[2:].strip() == "":
            raise StructureError("document H1 title must not be empty")
        document = Unit("document")
        document.document = self.path
        document.source_slice = self.canonical
        document.parent_index = -1
        self.units.append(document)

        index = 1
        total = len(self.lines)
        while index < total:
            line = self.lines[index]
            if line.text.strip() == "":
                index += 1
                continue
            classification = _inspect_heading(line.text, self.family_letter)
            if classification == "h1":
                raise StructureError("a second H1 heading is not allowed")
            if classification == "invalid":
                raise StructureError("invalid structural heading")
            if isinstance(classification, tuple):
                index = self._open_heading(index, classification)
                continue
            index = self._parse_blocks(index, total, 0)
        self._close_all_sections(total)
        document.visible_bytes = self._render(document.source_slice)
        return Structure(self.path, self.canonical, self.units)

    # -- headings ------------------------------------------------------

    def _open_heading(self, index: int, heading: Tuple[int, str]) -> int:
        depth, identifier = heading
        if identifier in self.seen_section_ids:
            if self.path == ARCHITECTURE_PATH and identifier.startswith("A-"):
                raise StructureError(f"duplicate A definition: {identifier}")
            raise StructureError(f"duplicate section identifier {identifier}")
        while self.section_stack and self.section_stack[-1].depth >= depth:
            self._close_section(self.section_stack.pop(), index)
        parent_depth = self.section_stack[-1].depth if self.section_stack else 1
        if depth > parent_depth + 1:
            raise StructureError(f"skipped heading depth from {parent_depth} to {depth}")
        self.seen_section_ids.add(identifier)
        owner_scope = self._container_scope()
        ordinal = owner_scope.next_position()
        section = Unit("section")
        section.document = self.path
        section.section_chain = self._chain() + [(depth, ordinal, identifier)]
        section.parent_index = self._container_index()
        self.units.append(section)
        self.section_stack.append(
            _SectionEntry(depth, ordinal, identifier, len(self.units) - 1, _Scope(), index)
        )
        return index + 1

    def _close_section(self, entry: _SectionEntry, next_index: int) -> None:
        unit = self.units[entry.unit_index]
        end_byte = self._last_non_blank_before(entry.start_line, next_index)
        unit.source_slice = self.canonical[self.lines[entry.start_line].start : end_byte]
        unit.visible_bytes = self._render(unit.source_slice)

    def _close_all_sections(self, total: int) -> None:
        while self.section_stack:
            self._close_section(self.section_stack.pop(), total)

    def _last_non_blank_before(self, start_line: int, next_index: int) -> int:
        end = self.lines[start_line].end
        upper = min(next_index, len(self.lines))
        for index in range(start_line, upper):
            if self.lines[index].text.strip() != "":
                end = self.lines[index].end
        return end

    # -- block sequence ------------------------------------------------

    def _parse_blocks(
        self, index: int, end: int, min_indent: int,
        container_index: Optional[int] = None,
        definition: Optional[Unit] = None, def_index: Optional[int] = None,
        scope: Optional[_Scope] = None,
    ) -> int:
        if container_index is None:
            container_index = self._container_index()
        if scope is None:
            scope = self._container_scope()
        chain = self._chain()
        total = len(self.lines)
        end = min(end, total)
        while index < end:
            line = self.lines[index]
            if line.text.strip() == "":
                index += 1
                continue
            if _leading_spaces(line.text) < min_indent:
                return index
            if definition is None:
                classification = _inspect_heading(line.text, self.family_letter)
                if classification == "h1":
                    raise StructureError("a second H1 heading is not allowed")
                if classification == "invalid":
                    raise StructureError("invalid structural heading")
                if isinstance(classification, tuple):
                    return index
            content = _content_at(line, min_indent)
            if content is None:
                return index
            text = content[0]
            if _HTML_BLOCK_START_RE.match(text):
                index = self._consume_raw_html_block(index, min_indent, chain, container_index, definition, def_index, scope)
            elif _FENCE_OPEN_RE.match(text):
                index = self._consume_fence(index, min_indent, chain, container_index, definition, def_index, scope)
            elif _is_table_start(self.lines, index, min_indent):
                index = self._consume_table(index, min_indent, chain, container_index, definition, def_index, scope)
            elif text.startswith(">"):
                index = self._consume_blockquote(index, min_indent, chain, container_index, definition, def_index, scope)
            elif _BULLET_RE.match(text) or _ORDERED_RE.match(text):
                index = self._consume_list_item(index, min_indent, chain, container_index, definition, def_index, scope)
            else:
                index = self._consume_paragraph(index, min_indent, chain, container_index, definition, def_index, scope)
        return index

    # -- block consumers ----------------------------------------------

    def _block_parent(self, container_index: int, definition: Optional[Unit], def_index: Optional[int]) -> int:
        return def_index if definition is not None else container_index

    def _scan_line_html_into(self, text: str, stack: List[Tuple[str, bool]]) -> None:
        """Update the whole-document HTML stack from one line's constructs."""
        code_ranges = _inline_code_char_ranges(text)
        length = len(text)
        index = 0
        while index < length:
            if text[index] == "<" and not _in_any_range(index, code_ranges):
                result = _consume_html_construct(text, index, stack)
                if result is not None:
                    index = result[0]
                    continue
            index += 1

    def _consume_raw_html_block(self, index, min_indent, chain, container_index, definition, def_index, scope):
        """Consume a modeled raw-HTML structural container as one opaque block.

        Inner Markdown is nonstructural: no heading, definition, table, or
        clause leaves emerge from inside the container.  Once a container opener
        has placed an element on the whole-document stack, the consumer owns
        every inner line -- including ordinary blank lines -- until the matching
        close returns that stack to empty; it does not stop merely because an
        inner source line is blank.  An EOF or structural boundary reached with a
        nonempty stack, or any crossed/unclosed construct scanned into the stack,
        fails closed.
        """
        start_byte = _content_at(self.lines[index], min_indent)[1]
        total = len(self.lines)
        stack: List[Tuple[str, bool]] = []
        cursor = index
        while cursor < total:
            line = self.lines[cursor]
            is_blank = line.text.strip() == ""
            if stack:
                # Inside an open container: own inner blank lines too.  Only a
                # non-blank line dedented out of the container column ends
                # ownership (and then fails closed below on the open stack).
                if not is_blank and _leading_spaces(line.text) < min_indent:
                    break
            elif cursor > index and (is_blank or _leading_spaces(line.text) < min_indent):
                # No open element yet: a blank line or dedent ends the block.
                break
            if is_blank:
                cursor += 1
                continue
            content = _content_at(line, min_indent)
            if content is None:
                break
            self._scan_line_html_into(content[0], stack)
            cursor += 1
            if not stack:
                break
        if stack:
            raise StructureError("unclosed raw-HTML structural container fails closed")
        end_line = cursor - 1 if cursor > index else index
        end_byte = self.lines[end_line].end
        block = self._make_container_block(
            "paragraph", chain, definition, def_index, container_index, scope,
            start_byte, end_byte,
        )
        self._emit_clauses_for(block, empty=True)
        return cursor

    def _consume_fence(self, index, min_indent, chain, container_index, definition, def_index, scope):
        content = _content_at(self.lines[index], min_indent)
        opener = content[0]
        fence_char = opener[0]
        run = 1
        while run < len(opener) and opener[run] == fence_char:
            run += 1
        start_byte = content[1]
        total = len(self.lines)
        close_index = index + 1
        while close_index < total:
            candidate = _content_at(self.lines[close_index], min_indent)
            if candidate is not None and re.match(rf"^\s*{re.escape(fence_char)}{{{run},}}\s*$", candidate[0]):
                break
            close_index += 1
        end_line = close_index if close_index < total else total - 1
        end_byte = self.lines[end_line].end
        block = self._make_container_block(
            "fenced_code", chain, definition, def_index, container_index, scope,
            start_byte, end_byte,
        )
        self._emit_clauses_for(block, empty=True)
        return close_index + 1

    def _consume_table(self, index, min_indent, chain, container_index, definition, def_index, scope):
        rows_start = index + 2
        total = len(self.lines)
        last_body = index + 1
        cursor = rows_start
        while cursor < total:
            candidate = _content_at(self.lines[cursor], min_indent)
            if candidate is None or candidate[0].strip() == "" or "|" not in candidate[0]:
                break
            last_body = cursor
            cursor += 1
        start_byte = _content_at(self.lines[index], min_indent)[1]
        end_byte = self.lines[last_body].end
        table = self._make_container_block(
            "table", chain, definition, def_index, container_index, scope,
            start_byte, end_byte, kind="table",
        )
        table_index = len(self.units) - 1
        leaf = 0
        for row_index in range(rows_start, last_body + 1):
            content = _content_at(self.lines[row_index], min_indent)
            if content is None:
                continue
            row_text, row_start, row_end = content
            leaf += 1
            self._emit_table_row(row_text, row_start, row_end, chain, definition, def_index, table, table_index, leaf, table.block_ordinal)
        return last_body + 1

    def _consume_blockquote(self, index, min_indent, chain, container_index, definition, def_index, scope):
        total = len(self.lines)
        block_lines: List[Tuple[str, int, int]] = []
        cursor = index
        while cursor < total:
            content = _content_at(self.lines[cursor], min_indent)
            if content is None or not content[0].startswith(">"):
                break
            inner = content[0][1:]
            if inner.startswith(" "):
                inner = inner[1:]
            inner_start = content[1] + (len(content[0]) - len(inner))
            block_lines.append((inner, inner_start, content[2]))
            cursor += 1
        ordinal = scope.next_position()
        if len(block_lines) >= 2 and "|" in block_lines[0][0] and _TABLE_SEP_RE.match(block_lines[1][0]):
            last_body = 1
            for j in range(2, len(block_lines)):
                if "|" not in block_lines[j][0]:
                    break
                last_body = j
            start_byte = block_lines[0][1]
            end_byte = block_lines[last_body][2]
            table = self._make_container_block(
                "table", chain, definition, def_index, container_index, scope,
                start_byte, end_byte, kind="table", force_ordinal=ordinal,
            )
            table_index = len(self.units) - 1
            leaf = 0
            for j in range(2, last_body + 1):
                row_text, row_start, row_end = block_lines[j]
                leaf += 1
                self._emit_table_row(row_text, row_start, row_end, chain, definition, def_index, table, table_index, leaf, table.block_ordinal)
            return cursor
        start_byte = self.lines[index].start
        end_byte = self.lines[index + len(block_lines) - 1].end
        block = self._make_container_block(
            "blockquote", chain, definition, def_index, container_index, scope,
            start_byte, end_byte, force_ordinal=ordinal,
        )
        return cursor

    def _consume_list_item(self, index, min_indent, chain, container_index, definition, def_index, scope):
        line = self.lines[index]
        content = _content_at(line, min_indent)
        text = content[0]
        marker = _BULLET_RE.match(text) or _ORDERED_RE.match(text)
        marker_len = marker.end()
        after_marker = text[marker_len:]
        content_indent = min_indent + marker_len
        form = _definition_form(after_marker, self.path)
        # A definition may enter _consume_definition only from a container-depth-
        # zero *unordered* marker; an ordered item whose first inline run happens
        # to be definition-shaped stays an ordinary list block.
        if form is not None and definition is None and min_indent == 0 and _BULLET_RE.match(text) is not None:
            return self._consume_definition(index, min_indent, marker_len, form, chain, container_index, scope)
        total = len(self.lines)
        start_byte = content[1] + marker_len
        cursor = index + 1
        end_byte = content[2]
        while cursor < total:
            nxt = self.lines[cursor]
            if nxt.text.strip() == "" or _leading_spaces(nxt.text) < content_indent:
                break
            cont = _content_at(nxt, content_indent)
            if cont is None:
                break
            end_byte = cont[2]
            cursor += 1
        block = self._make_container_block(
            "list_item", chain, definition, def_index, container_index, scope, start_byte, end_byte
        )
        self._emit_clauses_for(block)
        return cursor

    def _starts_new_block_at_zero(self, cursor: int) -> bool:
        """True if the source-column-zero line at ``cursor`` begins a new block.

        Used to decide whether a dedented continuation line is a lazy paragraph
        continuation (owned by the open item) or an interruptor that ends the
        item.  The frozen block-start set mirrors the block consumer: blockquote,
        fence, unordered/ordered marker, modeled raw-HTML block, an ATX
        heading-like line, or a two-line table start.
        """
        text = self.lines[cursor].text
        if (
            text.startswith(">")
            or _FENCE_OPEN_RE.match(text) is not None
            or _BULLET_RE.match(text) is not None
            or _ordered_interrupts_paragraph(text)
            or _HTML_BLOCK_START_RE.match(text) is not None
            or _looks_like_atx_heading(text)
        ):
            return True
        return _is_table_start(self.lines, cursor, 0)

    def _consume_definition(self, index, min_indent, marker_len, def_id, chain, container_index, scope):
        line = self.lines[index]
        content = _content_at(line, min_indent)
        content_indent = min_indent + marker_len
        ordinal = scope.next_position()
        definition = Unit("definition")
        definition.document = self.path
        definition.section_chain = list(chain)
        definition.definition_id = def_id
        definition.definition_ordinal = ordinal
        definition.parent_index = container_index
        self.units.append(definition)
        def_index = len(self.units) - 1
        def_scope = _Scope()
        total = len(self.lines)
        # First textual child: the body after the list marker and the complete
        # matched bold definition prefix, plus indented soft-wrap continuations.
        # The bullet, bold delimiters, identifier, period, and separator space
        # are structural prefix bytes excluded from every body clause slice.
        # Byte offsets are computed from UTF-8 lengths: a titled prefix (or any
        # multibyte content before the body) means a Python character offset is
        # not a byte offset, so the first body byte is derived explicitly.
        after_marker = content[0][marker_len:]
        prefix_match = _definition_prefix(after_marker, self.path)
        prefix_chars = after_marker[: prefix_match.end()] if prefix_match is not None else ""
        remainder = after_marker[len(prefix_chars):]
        first_text = remainder.lstrip(" \t")
        lead_chars = remainder[: len(remainder) - len(first_text)]
        body_start_byte = content[1]
        body_start_byte += len(content[0][:marker_len].encode("utf-8"))
        body_start_byte += len(prefix_chars.encode("utf-8"))
        body_start_byte += len(lead_chars.encode("utf-8"))
        body: List[Tuple[str, int, int]] = []
        if first_text:
            body.append((first_text, body_start_byte, content[2]))
        cursor = index + 1
        while cursor < total:
            nxt = self.lines[cursor]
            if nxt.text.strip() == "":
                break
            lead = _leading_spaces(nxt.text)
            if lead >= content_indent:
                cont = _content_at(nxt, content_indent)
                if cont is None:
                    break
                ntext = cont[0]
                if (
                    _FENCE_OPEN_RE.match(ntext)
                    or _is_table_start(self.lines, cursor, content_indent)
                    or ntext.startswith(">")
                    or _BULLET_RE.match(ntext)
                    or _ordered_interrupts_paragraph(ntext)
                    or _HTML_BLOCK_START_RE.match(ntext)
                ):
                    break
                body.append(cont)
                cursor += 1
                continue
            # Dedented below the item's content indent.  A source-column-zero
            # line that starts no new block is a lazy paragraph continuation and
            # stays inside this definition's body block (same owner/ordinal); a
            # blank line, a sibling item, a structural heading, or another
            # frozen block-start interruptor still ends or partitions the item.
            if lead == 0 and not self._starts_new_block_at_zero(cursor):
                body.append((nxt.text, nxt.start, nxt.end))
                cursor += 1
                continue
            break
        if any(segment[0].strip() for segment in body):
            self._emit_text_block(body, chain, container_index, definition, def_index, def_scope, "list_item")
        next_index = self._parse_blocks(
            cursor, total, content_indent, container_index, definition, def_index, def_scope
        )
        end_byte = self._last_non_blank_before(index, next_index)
        definition.source_slice = self.canonical[line.start : end_byte]
        definition.visible_bytes = self._render(definition.source_slice)
        return next_index

    def _emit_text_block(self, body, chain, container_index, definition, def_index, scope, block_kind):
        start_byte = body[0][1]
        end_byte = body[-1][2]
        block = self._make_container_block(
            block_kind, chain, definition, def_index, container_index, scope, start_byte, end_byte
        )
        self._emit_clauses_for(block)

    def _consume_paragraph(self, index, min_indent, chain, container_index, definition, def_index, scope):
        total = len(self.lines)
        block_kind = "list_item" if definition is not None else "paragraph"
        body: List[Tuple[str, int, int]] = []
        cursor = index
        while cursor < total:
            line = self.lines[cursor]
            if line.text.strip() == "" or _leading_spaces(line.text) < min_indent:
                break
            content = _content_at(line, min_indent)
            if content is None:
                break
            text = content[0]
            if (
                _FENCE_OPEN_RE.match(text)
                or _is_table_start(self.lines, cursor, min_indent)
                or text.startswith(">")
                or _BULLET_RE.match(text)
                or _ordered_interrupts_paragraph(text)
                or _HTML_BLOCK_START_RE.match(text)
            ):
                break
            if definition is None and _looks_like_atx_heading(text):
                break
            body.append(content)
            cursor += 1
        if not body:
            return cursor
        start_byte = body[0][1]
        end_byte = body[-1][2]
        block = self._make_container_block(
            block_kind, chain, definition, def_index, container_index, scope, start_byte, end_byte
        )
        self._emit_clauses_for(block)
        return cursor

    # -- unit factories ------------------------------------------------

    def _make_container_block(
        self, block_kind, chain, definition, def_index, container_index, scope,
        start_byte, end_byte, *, kind="block", force_ordinal=None,
    ) -> Unit:
        if force_ordinal is None:
            ordinal = scope.next_position()
        else:
            ordinal = force_ordinal
        unit = Unit(kind)
        unit.document = self.path
        unit.section_chain = list(chain)
        unit.definition_id = definition.definition_id if definition else ""
        unit.definition_ordinal = definition.definition_ordinal if definition else 0
        unit.block_ordinal = ordinal
        unit.block_kind = block_kind if kind == "block" else ""
        unit.parent_index = self._block_parent(container_index, definition, def_index)
        unit.source_slice = self.canonical[start_byte:end_byte]
        unit.visible_bytes = self._render(unit.source_slice)
        self.units.append(unit)
        return unit

    def _emit_clauses_for(self, block: Unit, *, empty: bool = False) -> None:
        if empty:
            return
        block_index = len(self.units) - 1
        block_source = block.source_slice
        visible = render_visible_v1(block_source)
        ranges = split_clauses(visible)
        leaf = 0
        for start, stop in ranges:
            first_char = visible.chars[start]
            last_char = visible.chars[stop]
            source_slice = block_source[first_char.start : last_char.end]
            if not source_slice.strip():
                continue
            leaf += 1
            clause_chars = visible.chars[start : stop + 1]
            clause_semantic = visible.semantic[start : stop + 1]
            clause_masked = "".join(" " if c.code else c.text for c in clause_chars)
            clause = Unit("clause")
            clause.document = self.path
            clause.section_chain = list(block.section_chain)
            clause.definition_id = block.definition_id
            clause.definition_ordinal = block.definition_ordinal
            clause.block_ordinal = block.block_ordinal
            clause.block_kind = block.block_kind
            clause.parent_index = block_index
            clause.leaf_kind = "clause"
            clause.leaf_ordinal = leaf
            clause.source_slice = source_slice
            clause.visible_bytes = clause_semantic.encode("utf-8")
            clause.normative = _RFC_RE.search(clause_masked) is not None
            clause.ambiguous = not clause.normative
            self.units.append(clause)

    def _emit_table_row(self, row_text, row_start, row_end, chain, definition, def_index, table, table_index, leaf, block_ordinal):
        cells = _split_table_cell_sources(row_text)
        cell_visibles = [render_visible_v1(cell.encode("utf-8")) for cell in cells]
        visible_bytes = "\x1f".join(v.semantic for v in cell_visibles).encode("utf-8")
        masked = "\x1f".join(_masked_text(v) for v in cell_visibles)
        row = Unit("table_row")
        row.document = self.path
        row.section_chain = list(chain)
        row.definition_id = definition.definition_id if definition else ""
        row.definition_ordinal = definition.definition_ordinal if definition else 0
        row.block_ordinal = block_ordinal
        row.parent_index = table_index
        row.leaf_kind = "table_row"
        row.leaf_ordinal = leaf
        row.source_slice = self.canonical[row_start:row_end]
        row.visible_bytes = visible_bytes
        row.normative = _RFC_RE.search(masked) is not None
        # Each body row is classified atomically from its own rendered cells: a
        # row with an uppercase non-code/non-autolink RFC-2119 token is
        # normative; every other body row is ambiguous, even without an ordinary
        # ambiguity phrase. Classification is never inherited across rows.
        row.ambiguous = not row.normative
        self.units.append(row)

    # -- rendering -----------------------------------------------------

    def _render(self, source_slice: bytes) -> bytes:
        if not source_slice:
            return b""
        return render_visible_v1(source_slice).semantic.encode("utf-8")


_STRUCTURE_PARENT_KINDS = {
    "section": frozenset({"document", "section"}),
    "definition": frozenset({"document", "section"}),
    "block": frozenset({"document", "section", "definition"}),
    "table": frozenset({"document", "section", "definition"}),
    "clause": frozenset({"block"}),
    "table_row": frozenset({"table"}),
}
_CLAUSE_PARENT_BLOCK_KINDS = frozenset({"paragraph", "list_item", "blockquote"})


def validate_structure(struct: Structure) -> None:
    """Authenticate a parsed Structure against its exact source and codec rules.

    Runs after every shared parse, before the result is trusted.  It independently
    recomputes every unit's visible bytes and leaf flags from the unit's own
    source slice (clauses via their parent block's re-derived clause sequence) and
    rejects duplicate/invented/missing units, inconsistent source/visible/flag
    provenance, bad parent links, and malformed ordering.  This catches a parser
    result whose unit IDs and multiplicity are correct but whose visible or
    normative provenance is corrupt; it never calls the public parser a second
    time and never reconstructs Markdown in a consumer.
    """
    units = struct.units
    if not units or units[0].kind != "document":
        raise StructureError("validated structure must begin with a document unit")
    if units[0].parent_index != -1:
        raise StructureError("document unit must have no parent")
    seen_sections: set = set()
    seen_definitions: set[str] = set()
    seen_paths: set = set()
    block_clauses: Dict[int, List[Tuple[int, bytes, bool, bool]]] = {}

    for index, unit in enumerate(units):
        if unit.kind not in UNIT_KINDS:
            raise StructureError("validated unit has an unknown kind")
        if unit.kind == "document":
            if index != 0:
                raise StructureError("document unit must be first")
        else:
            if not (0 <= unit.parent_index < index):
                raise StructureError("unit parent must precede the unit")
            parent = units[unit.parent_index]
            if parent.kind not in _STRUCTURE_PARENT_KINDS[unit.kind]:
                raise StructureError("unit parent kind is inconsistent")

        # Closed structural multiplicity for every unit kind: each emitted unit
        # must occupy a unique structural path -- the same closed signature PATH_V1
        # binds (document, complete section chain, definition owner, block
        # ordinal/kind, leaf kind/ordinal, unit kind).  A duplicate section,
        # definition, table, or any other duplicate unit fails here, independent
        # of any consumer-side set comparison and before any identity hash.
        sig = (
            unit.kind, unit.document, tuple(unit.section_chain),
            unit.definition_id, unit.definition_ordinal, unit.block_ordinal,
            unit.block_kind, unit.leaf_kind, unit.leaf_ordinal,
        )
        if sig in seen_paths:
            raise StructureError("duplicate structural path in validated structure")
        seen_paths.add(sig)

        if unit.kind == "section":
            section_id = unit.section_chain[-1][2] if unit.section_chain else ""
            if section_id in seen_sections:
                raise StructureError("duplicate section identifier in validated structure")
            seen_sections.add(section_id)
        elif unit.kind == "definition":
            if unit.definition_id in seen_definitions:
                family = unit.definition_id.split("-", 1)[0]
                raise StructureError(
                    f"duplicate {family} definition: {unit.definition_id}"
                )
            seen_definitions.add(unit.definition_id)

        if unit.kind not in LEAF_KINDS:
            if unit.normative or unit.ambiguous:
                raise StructureError("container unit must not carry leaf flags")
        elif unit.normative == unit.ambiguous:
            raise StructureError("leaf must carry exactly one classification flag")

        if unit.kind == "table_row":
            cells = _split_table_cell_sources(unit.source_slice.decode("utf-8"))
            cell_visibles = [render_visible_v1(cell.encode("utf-8")) for cell in cells]
            expected = "\x1f".join(v.semantic for v in cell_visibles).encode("utf-8")
            if expected != unit.visible_bytes:
                raise StructureError("table-row visible bytes disagree with its source slice")
            masked = "\x1f".join(_masked_text(v) for v in cell_visibles)
            normative = _RFC_RE.search(masked) is not None
            if unit.normative != normative or unit.ambiguous != (not normative):
                raise StructureError("table-row flags disagree with its cells")
        elif unit.kind == "clause":
            parent = units[unit.parent_index]
            if parent.kind != "block" or parent.block_kind not in _CLAUSE_PARENT_BLOCK_KINDS:
                raise StructureError("clause parent must be a clause-bearing block")
            if unit.parent_index not in block_clauses:
                block_clauses[unit.parent_index] = _rederive_block_clauses(parent)
            sequence = block_clauses[unit.parent_index]
            match = next((c for c in sequence if c[0] == unit.leaf_ordinal), None)
            if (
                match is None
                or match[1] != unit.visible_bytes
                or match[2] != unit.normative
                or match[3] != unit.ambiguous
            ):
                raise StructureError("clause visible bytes or flags disagree with its block")
        else:
            expected = render_visible_v1(unit.source_slice).semantic.encode("utf-8")
            if expected != unit.visible_bytes:
                raise StructureError("unit visible bytes disagree with its source slice")


def _rederive_block_clauses(block: Unit) -> List[Tuple[int, bytes, bool, bool]]:
    """Re-derive a block's clause sequence exactly as the parser emits it."""
    block_source = block.source_slice
    visible = render_visible_v1(block_source)
    ranges = split_clauses(visible)
    sequence: List[Tuple[int, bytes, bool, bool]] = []
    leaf = 0
    for start, stop in ranges:
        first_char = visible.chars[start]
        last_char = visible.chars[stop]
        source_slice = block_source[first_char.start : last_char.end]
        if not source_slice.strip():
            continue
        leaf += 1
        clause_chars = visible.chars[start : stop + 1]
        clause_semantic = visible.semantic[start : stop + 1]
        clause_masked = "".join(" " if c.code else c.text for c in clause_chars)
        normative = _RFC_RE.search(clause_masked) is not None
        ambiguous = not normative
        sequence.append((leaf, clause_semantic.encode("utf-8"), normative, ambiguous))
    return sequence


def parse_spec_structure_v1(canonical_document: bytes, canonical_path: str) -> Structure:
    """Parse release-canonical bytes into the frozen ownership tree."""
    if not isinstance(canonical_document, (bytes, bytearray)):
        raise StructureError("canonical_document must be bytes")
    if not isinstance(canonical_path, str) or not canonical_path:
        raise StructureError("canonical_path must be a non-empty string")
    canonical = bytes(canonical_document)
    text = _enforce_source_bounds(canonical)
    _reject_bidi_controls(text)
    parser = _Parser(canonical, canonical_path)
    structure = parser.parse()
    validate_structure(structure)
    return structure
