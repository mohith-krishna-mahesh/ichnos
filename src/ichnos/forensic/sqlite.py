"""SQLite database freeblock, freelist, and unallocated page space carver.

Scans SQLite 3 database files for deleted cell records, unallocated byte ranges,
and freelist pages to recover dropped tables, deleted rows, and hidden flags.
"""

from __future__ import annotations

import re
import struct
from typing import Any

SQLITE_HEADER = b"SQLite format 3\x00"


def is_sqlite3(data: bytes) -> bool:
    """Returns True if the data starts with the standard SQLite 3 header."""
    return data.startswith(SQLITE_HEADER)


def carve_sqlite_deleted_records(data: bytes) -> dict[str, Any]:
    """Scans an SQLite database for unallocated spaces and deleted records.

    Returns:
        Dict with: 'page_size', 'leaf_pages_count', 'carved_strings', 'freeblocks_count'.
    """
    if not is_sqlite3(data):
        return {"error": "Not an SQLite 3 database"}

    raw_page_size = struct.unpack(">H", data[16:18])[0]
    page_size = 65536 if raw_page_size == 1 else raw_page_size

    total_pages = len(data) // page_size
    leaf_pages = 0
    freeblocks_found = 0
    carved_strings: list[str] = []

    text_regex = re.compile(rb"[\x20-\x7E]{4,}")

    for p_idx in range(total_pages):
        page_offset = p_idx * page_size
        page_data = data[page_offset : page_offset + page_size]

        header_offset = 100 if p_idx == 0 else 0
        if len(page_data) < header_offset + 8:
            continue

        page_type = page_data[header_offset]
        if page_type in (0x0D, 0x0A):  # Leaf table (0x0d) or leaf index (0x0a)
            leaf_pages += 1
            first_freeblock = struct.unpack(">H", page_data[header_offset + 1 : header_offset + 3])[0]
            cell_count = struct.unpack(">H", page_data[header_offset + 3 : header_offset + 5])[0]
            content_start = struct.unpack(">H", page_data[header_offset + 5 : header_offset + 7])[0]
            if content_start == 0:
                content_start = 65536

            # 1. Inspect unallocated gap: between end of cell pointers and start of cell content
            pointer_array_end = header_offset + 8 + (cell_count * 2)
            if pointer_array_end < content_start and content_start <= page_size:
                gap_data = page_data[pointer_array_end:content_start]
                for match in text_regex.finditer(gap_data):
                    s = match.group(0).decode("ascii", errors="replace")
                    if any(kw in s for kw in ("FLAG", "NNS", "CTF", "{", "admin", "user", "pass", "key")):
                        carved_strings.append(s)

            # 2. Walk freeblock linked list
            fb_curr = first_freeblock
            while fb_curr != 0 and fb_curr + 4 <= len(page_data):
                freeblocks_found += 1
                next_fb, fb_size = struct.unpack(">HH", page_data[fb_curr : fb_curr + 4])
                fb_data = page_data[fb_curr + 4 : fb_curr + fb_size] if fb_size >= 4 else b""
                for match in text_regex.finditer(fb_data):
                    s = match.group(0).decode("ascii", errors="replace")
                    carved_strings.append(s)
                fb_curr = next_fb

    # Deduplicate carved strings
    unique_strings = list(dict.fromkeys(carved_strings))

    return {
        "page_size": page_size,
        "total_pages": total_pages,
        "leaf_pages_count": leaf_pages,
        "freeblocks_count": freeblocks_found,
        "carved_strings_count": len(unique_strings),
        "carved_strings": unique_strings,
    }
