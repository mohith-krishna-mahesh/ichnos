"""PDF forensics tools for extracting hidden content.

Provides stream decompression, text extraction, hidden-text detection,
metadata parsing, and incremental-update discovery — all using only the
standard library.
"""

from __future__ import annotations

import re

from ichnos.core.security import safe_decompress_zlib

# ---------------------------------------------------------------------------
# Stream extraction
# ---------------------------------------------------------------------------

# Regex to capture the object number (``N 0 obj``), the dictionary portion
# (for filter detection), and the raw stream bytes.
_OBJ_RE = re.compile(
    rb"(\d+)\s+\d+\s+obj\b"       # object header  → group 1 (obj number)
    rb"(.*?)"                       # dict / attrs   → group 2
    rb"stream\r?\n"                 # stream keyword
    rb"(.*?)"                       # stream body    → group 3
    rb"\r?\nendstream",
    re.DOTALL,
)


def extract_streams(data: bytes) -> list[dict]:
    """Extract and optionally decompress all ``stream…endstream`` objects.

    For each stream whose object dictionary contains ``/FlateDecode``, the raw
    bytes are inflated via :func:`zlib.decompress`.

    Args:
        data: Raw PDF file bytes.

    Returns:
        A list of dicts, each containing:

        - **object_num** (*int*): The PDF object number.
        - **filter** (*str | None*): The ``/Filter`` value, if present.
        - **raw_data** (*bytes*): The raw (possibly compressed) stream bytes.
        - **decoded_data** (*bytes | None*): Decompressed bytes, or ``None``
          if the filter is unsupported or decompression fails.
    """
    results: list[dict] = []
    for m in _OBJ_RE.finditer(data):
        if len(results) >= 10000:
            break
        obj_num = int(m.group(1))
        obj_dict = m.group(2)
        raw_stream = m.group(3)

        # Determine filter
        filt: str | None = None
        filter_match = re.search(rb"/Filter\s*/(\w+)", obj_dict)
        if filter_match:
            filt = filter_match.group(1).decode("ascii", errors="replace")

        decoded: bytes | None = None
        if filt == "FlateDecode":
            try:
                decoded = safe_decompress_zlib(raw_stream, max_size=32 * 1024 * 1024)
            except Exception:
                # Some PDFs omit the zlib header – try raw Deflate
                try:
                    decoded = safe_decompress_zlib(
                        raw_stream, max_size=32 * 1024 * 1024, wbits=-15
                    )
                except Exception:
                    decoded = None

        results.append(
            {
                "object_num": obj_num,
                "filter": filt,
                "raw_data": raw_stream,
                "decoded_data": decoded,
            }
        )

    return results


# ---------------------------------------------------------------------------
# Text-object extraction
# ---------------------------------------------------------------------------

_BT_ET_RE = re.compile(rb"BT\b(.*?)ET\b", re.DOTALL)

# Tj  – show a single string:  (Hello) Tj
# TJ  – show an array:          [(H) 10 (ello)] TJ
# '   – move to next line and show string:  (Hello) '
_TEXT_OP_RE = re.compile(
    rb"\(([^)]*)\)\s*(?:Tj|')"   # (text) Tj  or  (text) '
    rb"|"
    rb"\[([^\]]*)\]\s*TJ",       # [ … ] TJ
    re.DOTALL,
)

_TJ_ARRAY_STR_RE = re.compile(rb"\(([^)]*)\)")


def _decode_pdf_string(raw: bytes) -> str:
    """Decode a raw PDF string literal, handling common escape sequences."""
    result: list[str] = []
    i = 0
    while i < len(raw):
        ch = raw[i : i + 1]
        if ch == b"\\":
            i += 1
            if i >= len(raw):
                break
            esc = raw[i : i + 1]
            _ESCAPES = {
                b"n": "\n",
                b"r": "\r",
                b"t": "\t",
                b"b": "\b",
                b"f": "\f",
                b"(": "(",
                b")": ")",
                b"\\": "\\",
            }
            if esc in _ESCAPES:
                result.append(_ESCAPES[esc])
            elif esc and esc[0:1] in b"01234567":
                # Octal escape: up to 3 digits
                octal = esc.decode("ascii")
                for _ in range(2):
                    if i + 1 < len(raw) and raw[i + 1 : i + 2] in (
                        b"0", b"1", b"2", b"3", b"4", b"5", b"6", b"7",
                    ):
                        i += 1
                        octal += raw[i : i + 1].decode("ascii")
                    else:
                        break
                result.append(chr(int(octal, 8)))
            else:
                result.append(esc.decode("latin-1", errors="replace"))
        else:
            result.append(ch.decode("latin-1", errors="replace"))
        i += 1
    return "".join(result)


def extract_text_objects(data: bytes) -> list[str]:
    """Extract text strings from all ``BT … ET`` blocks in the PDF.

    Handles the ``Tj``, ``TJ``, and ``'`` text-showing operators.

    Args:
        data: Raw PDF file bytes.

    Returns:
        A list of extracted text strings.
    """
    # We search both in the raw data and in decoded streams.
    sources: list[bytes] = [data]
    for stream_info in extract_streams(data):
        if stream_info["decoded_data"]:
            sources.append(stream_info["decoded_data"])

    texts: list[str] = []
    for src in sources:
        for bt_match in _BT_ET_RE.finditer(src):
            block = bt_match.group(1)
            for tm in _TEXT_OP_RE.finditer(block):
                if tm.group(1) is not None:
                    texts.append(_decode_pdf_string(tm.group(1)))
                elif tm.group(2) is not None:
                    parts: list[str] = []
                    for sm in _TJ_ARRAY_STR_RE.finditer(tm.group(2)):
                        parts.append(_decode_pdf_string(sm.group(1)))
                    if parts:
                        texts.append("".join(parts))

    return texts


# ---------------------------------------------------------------------------
# Hidden-text detection
# ---------------------------------------------------------------------------

# White colour setters:  1 1 1 rg  (RGB white)  or  0 0 0 0 k  (CMYK black=0)
_WHITE_COLOR_RE = re.compile(
    rb"(?:1\s+1\s+1\s+rg|0\s+0\s+0\s+0\s+k)"
)

# Large negative coordinates in Td/Tm operators
_OFF_SCREEN_RE = re.compile(
    rb"(-\d{4,})\s+(-?\d+)\s+Td"
    rb"|"
    rb"(-?\d+)\s+(-\d{4,})\s+Td"
)

# Zero font size:  0 Tf  (or /Font 0 Tf)
_ZERO_FONT_RE = re.compile(rb"(?:^|\s)0(?:\.0+)?\s+Tf", re.MULTILINE)


def find_hidden_text(data: bytes) -> list[str]:
    """Find text that may be intentionally hidden within the PDF.

    Heuristics used:
    - White text colour (``1 1 1 rg`` or ``0 0 0 0 k``).
    - Text positioned far outside the visible area (large negative ``Td``).
    - Zero font size.

    Args:
        data: Raw PDF file bytes.

    Returns:
        A list of suspicious text strings extracted from hidden blocks.
    """
    sources: list[bytes] = [data]
    for stream_info in extract_streams(data):
        if stream_info["decoded_data"]:
            sources.append(stream_info["decoded_data"])

    hidden: list[str] = []

    for src in sources:
        for bt_match in _BT_ET_RE.finditer(src):
            block = bt_match.group(1)

            is_suspicious = bool(
                _WHITE_COLOR_RE.search(block)
                or _OFF_SCREEN_RE.search(block)
                or _ZERO_FONT_RE.search(block)
            )

            if not is_suspicious:
                continue

            for tm in _TEXT_OP_RE.finditer(block):
                if tm.group(1) is not None:
                    hidden.append(_decode_pdf_string(tm.group(1)))
                elif tm.group(2) is not None:
                    parts: list[str] = []
                    for sm in _TJ_ARRAY_STR_RE.finditer(tm.group(2)):
                        parts.append(_decode_pdf_string(sm.group(1)))
                    if parts:
                        hidden.append("".join(parts))

    return hidden


# ---------------------------------------------------------------------------
# Metadata extraction
# ---------------------------------------------------------------------------

_INFO_KEYS = (
    "Title",
    "Author",
    "Subject",
    "Keywords",
    "Creator",
    "Producer",
    "CreationDate",
    "ModDate",
)

_INFO_RE = {
    key: re.compile(
        rb"/" + key.encode() + rb"\s*\(([^)]*)\)",
    )
    for key in _INFO_KEYS
}

# Hex-string variant:  /Title <hex>
_INFO_HEX_RE = {
    key: re.compile(
        rb"/" + key.encode() + rb"\s*<([0-9A-Fa-f\s]*)>",
    )
    for key in _INFO_KEYS
}


def extract_metadata(data: bytes) -> dict:
    """Extract standard PDF info-dictionary metadata.

    Searches for ``/Title``, ``/Author``, ``/Subject``, ``/Keywords``,
    ``/Creator``, ``/Producer``, ``/CreationDate``, and ``/ModDate``.

    Both parenthesised-string and hex-string encodings are handled.

    Args:
        data: Raw PDF file bytes.

    Returns:
        A dict mapping metadata key names to their string values.  Keys with
        no value found are omitted.
    """
    meta: dict = {}
    for key in _INFO_KEYS:
        m = _INFO_RE[key].search(data)
        if m:
            meta[key] = _decode_pdf_string(m.group(1))
            continue
        mh = _INFO_HEX_RE[key].search(data)
        if mh:
            hex_str = mh.group(1).replace(b" ", b"").replace(b"\n", b"").replace(b"\r", b"")
            try:
                meta[key] = bytes.fromhex(hex_str.decode("ascii")).decode("latin-1", errors="replace")
            except (ValueError, UnicodeDecodeError):
                meta[key] = hex_str.decode("ascii", errors="replace")

    return meta


# ---------------------------------------------------------------------------
# Incremental-update detection
# ---------------------------------------------------------------------------

def find_incremental_updates(data: bytes) -> list[int]:
    """Find all ``%%EOF`` markers in the PDF, indicating incremental updates.

    A well-formed PDF has exactly one ``%%EOF`` at the end.  Multiple markers
    suggest the file was incrementally updated — each revision appends a new
    cross-reference section and ``%%EOF``.  Hidden or deleted content may
    persist in earlier revisions.

    Args:
        data: Raw PDF file bytes.

    Returns:
        A list of byte offsets where each ``%%EOF`` marker begins.
    """
    marker = b"%%EOF"
    offsets: list[int] = []
    pos = 0
    while True:
        idx = data.find(marker, pos)
        if idx == -1:
            break
        offsets.append(idx)
        pos = idx + len(marker)
    return offsets
