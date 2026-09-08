"""Pure-Python signature-based file carver.

Carves intact embedded files (PNG, JPEG, GIF, PDF, ZIP, ELF) from memory dumps,
disk images, or corrupted carrier files without external dependencies.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass
class CarvedFile:
    """Represents a carved file extracted from raw data."""

    file_type: str
    offset: int
    size: int
    data: bytes


def carve_png(data: bytes) -> list[CarvedFile]:
    """Carves PNG files by locating the PNG signature and IEND trailer."""
    results: list[CarvedFile] = []
    sig = b"\x89PNG\r\n\x1a\n"
    iend_marker = b"IEND\xaeB`\x82"
    start = 0

    while True:
        pos = data.find(sig, start)
        if pos == -1:
            break
        iend_pos = data.find(iend_marker, pos)
        if iend_pos != -1:
            end_offset = iend_pos + len(iend_marker)
            file_data = data[pos:end_offset]
            results.append(
                CarvedFile(
                    file_type="png",
                    offset=pos,
                    size=len(file_data),
                    data=file_data,
                )
            )
            start = end_offset
        else:
            start = pos + len(sig)

    return results


def carve_jpeg(data: bytes) -> list[CarvedFile]:
    """Carves JPEG files by locating SOI (\\xFF\\xD8\\xFF) and EOI (\\xFF\\xD9)."""
    results: list[CarvedFile] = []
    soi = b"\xff\xd8\xff"
    eoi = b"\xff\xd9"
    start = 0

    while True:
        pos = data.find(soi, start)
        if pos == -1:
            break
        eoi_pos = data.find(eoi, pos + 3)
        if eoi_pos != -1:
            end_offset = eoi_pos + len(eoi)
            file_data = data[pos:end_offset]
            results.append(
                CarvedFile(
                    file_type="jpeg",
                    offset=pos,
                    size=len(file_data),
                    data=file_data,
                )
            )
            start = end_offset
        else:
            start = pos + len(soi)

    return results


def carve_pdf(data: bytes) -> list[CarvedFile]:
    """Carves PDF documents by locating %PDF- header and %%EOF trailer."""
    results: list[CarvedFile] = []
    header = b"%PDF-"
    trailer = b"%%EOF"
    start = 0

    while True:
        pos = data.find(header, start)
        if pos == -1:
            break
        eof_pos = data.find(trailer, pos + 5)
        if eof_pos != -1:
            # Advance past trailing newlines
            end_offset = eof_pos + len(trailer)
            while end_offset < len(data) and data[end_offset] in (b"\r"[0], b"\n"[0]):
                end_offset += 1
            file_data = data[pos:end_offset]
            results.append(
                CarvedFile(
                    file_type="pdf",
                    offset=pos,
                    size=len(file_data),
                    data=file_data,
                )
            )
            start = end_offset
        else:
            start = pos + len(header)

    return results


def carve_zip(data: bytes) -> list[CarvedFile]:
    """Carves ZIP archives by locating local file header PK\\x03\\x04 and EOCD PK\\x05\\x06."""
    results: list[CarvedFile] = []
    header = b"PK\x03\x04"
    eocd_sig = b"PK\x05\x06"
    start = 0

    while True:
        pos = data.find(header, start)
        if pos == -1:
            break
        eocd_pos = data.find(eocd_sig, pos + 4)
        if eocd_pos != -1 and eocd_pos + 22 <= len(data):
            # EOCD is at least 22 bytes: 20 bytes up to comment_len, plus 2-byte comment_len
            comment_len = struct.unpack("<H", data[eocd_pos + 20 : eocd_pos + 22])[0]
            end_offset = eocd_pos + 22 + comment_len
            file_data = data[pos:end_offset]
            results.append(
                CarvedFile(
                    file_type="zip",
                    offset=pos,
                    size=len(file_data),
                    data=file_data,
                )
            )
            start = end_offset
        else:
            start = pos + len(header)

    return results


def carve_gif(data: bytes) -> list[CarvedFile]:
    """Carves GIF images by locating GIF87a/GIF89a and 0x3B trailer."""
    results: list[CarvedFile] = []
    headers = [b"GIF87a", b"GIF89a"]
    start = 0

    while start < len(data):
        found_pos = -1
        for h in headers:
            pos = data.find(h, start)
            if pos != -1 and (found_pos == -1 or pos < found_pos):
                found_pos = pos

        if found_pos == -1:
            break

        trailer_pos = data.find(b";", found_pos + 6)
        if trailer_pos != -1:
            end_offset = trailer_pos + 1
            file_data = data[found_pos:end_offset]
            results.append(
                CarvedFile(
                    file_type="gif",
                    offset=found_pos,
                    size=len(file_data),
                    data=file_data,
                )
            )
            start = end_offset
        else:
            start = found_pos + 6

    return results


def carve_all(data: bytes, types: list[str] | None = None) -> list[CarvedFile]:
    """Carves all supported file types from raw binary data.

    Returns results sorted by file offset.
    """
    carvers = {
        "png": carve_png,
        "jpeg": carve_jpeg,
        "pdf": carve_pdf,
        "zip": carve_zip,
        "gif": carve_gif,
    }

    selected = types if types else list(carvers.keys())
    results: list[CarvedFile] = []

    for t in selected:
        fn = carvers.get(t.lower())
        if fn:
            results.extend(fn(data))

    results.sort(key=lambda c: c.offset)
    return results
