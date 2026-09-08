"""
PNG parser module for Ichnos stego toolkit.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from ichnos.core.security import safe_decompress_zlib

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_CHUNKS = 10_000


@dataclass
class PNGChunk:
    chunk_type: str
    data: bytes
    crc: int
    offset: int
    length: int

    def __getitem__(self, index: int | str) -> Any:
        if index == 0 or index == "type":
            return self.chunk_type.encode("ascii") if isinstance(index, int) else self.chunk_type
        if index == 1 or index == "data":
            return self.data
        if index == 2 or index == "crc":
            return self.crc
        if index == 3 or index == "offset":
            return self.offset
        if index == 4 or index == "length":
            return self.length
        raise IndexError(f"PNGChunk index {index} out of range")


def parse_chunks(data: bytes) -> list[PNGChunk]:
    """Parse a PNG file into chunks."""
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("Invalid PNG signature")

    chunks = []
    offset = 8
    while offset < len(data) and len(chunks) < MAX_CHUNKS:
        if offset + 8 > len(data):
            break
        try:
            length, chunk_type = struct.unpack(">I4s", data[offset : offset + 8])
        except struct.error:
            break
        chunk_type_str = chunk_type.decode("ascii", errors="replace")

        # Boundary check: length + 4 (crc) must not overflow remaining buffer
        if length < 0 or offset + 8 + length + 4 > len(data):
            break

        chunk_data = data[offset + 8 : offset + 8 + length]
        try:
            crc = struct.unpack(">I", data[offset + 8 + length : offset + 8 + length + 4])[0]
        except struct.error:
            break

        chunks.append(
            PNGChunk(
                chunk_type=chunk_type_str, data=chunk_data, crc=crc, offset=offset, length=length
            )
        )
        offset += 8 + length + 4
        if chunk_type_str == "IEND":
            break
    return chunks


def parse_ihdr(data: bytes) -> dict[str, Any]:
    """Parse IHDR chunk."""
    if len(data) != 13:
        raise ValueError("Invalid IHDR length")
    width, height, bit_depth, color_type, compression, filter_method, interlace = struct.unpack(
        ">IIBBBBB", data
    )
    if width > 65536 or height > 65536 or width == 0 or height == 0:
        raise ValueError(f"PNG dimensions out of supported range (1..65536): {width}x{height}")
    return {
        "width": width,
        "height": height,
        "bit_depth": bit_depth,
        "color_type": color_type,
        "compression": compression,
        "filter": filter_method,
        "interlace": interlace,
    }


def find_text_chunks(data: bytes) -> list[dict[str, str]]:
    """Extract tEXt, zTXt, iTXt chunks."""
    chunks = parse_chunks(data)
    results = []
    for chunk in chunks:
        if chunk.chunk_type == "tEXt":
            parts = chunk.data.split(b"\x00", 1)
            if len(parts) == 2:
                results.append(
                    {
                        "type": "tEXt",
                        "keyword": parts[0].decode(errors="replace"),
                        "text": parts[1].decode(errors="replace"),
                    }
                )
        elif chunk.chunk_type == "zTXt":
            parts = chunk.data.split(b"\x00", 1)
            if len(parts) == 2 and len(parts[1]) > 1:
                comp_method = parts[1][0]
                if comp_method == 0:
                    try:
                        decompressed = safe_decompress_zlib(parts[1][1:], max_size=16 * 1024 * 1024)
                        results.append(
                            {
                                "type": "zTXt",
                                "keyword": parts[0].decode(errors="replace"),
                                "text": decompressed.decode(errors="replace"),
                            }
                        )
                    except Exception:
                        pass
        elif chunk.chunk_type == "iTXt":
            parts = chunk.data.split(b"\x00", 1)
            if len(parts) == 2 and len(parts[1]) >= 4:
                keyword = parts[0].decode(errors="replace")
                comp_flag = parts[1][0]
                comp_method = parts[1][1]
                rem = parts[1][2:].split(b"\x00", 2)
                if len(rem) == 3:
                    lang, trans_key, text = rem
                    if comp_flag == 1:
                        try:
                            dec_text = safe_decompress_zlib(text, max_size=16 * 1024 * 1024)
                            text_str = dec_text.decode("utf-8", errors="replace")
                        except Exception:
                            text_str = text.decode("utf-8", errors="replace")
                    else:
                        text_str = text.decode("utf-8", errors="replace")
                    results.append({"type": "iTXt", "keyword": keyword, "text": text_str})
    return results


def detect_trailing_data(data: bytes) -> bytes | None:
    """Find data after IEND chunk."""
    if not data.startswith(PNG_SIGNATURE):
        return None
    offset = 8
    while offset < len(data):
        if offset + 8 > len(data):
            break
        length, chunk_type = struct.unpack(">I4s", data[offset : offset + 8])
        if chunk_type == b"IEND":
            end_offset = offset + 8 + length + 4
            if end_offset < len(data):
                return data[end_offset:]
            return None
        offset += 8 + length + 4
    return None


def inspect(data: bytes) -> dict[str, Any]:
    """Full PNG inspection returning all metadata."""
    res = {}
    try:
        chunks = parse_chunks(data)
    except ValueError as e:
        return {"error": str(e)}

    for chunk in chunks:
        if chunk.chunk_type == "IHDR":
            res["ihdr"] = parse_ihdr(chunk.data)

    res["text_chunks"] = find_text_chunks(data)
    trailing = detect_trailing_data(data)
    if trailing:
        res["trailing_data_length"] = len(trailing)
        res["trailing_preview"] = trailing[:32].hex()

    res["chunks"] = [{"type": c.chunk_type, "offset": c.offset, "length": c.length} for c in chunks]
    return res
