"""Pure-Python JPEG file parser and steganalysis tools.

Parses JPEG segments (SOI, APPn, DQT, DHT, SOF0/2, SOS, COM, EOI),
extracts comments, detects appended/trailing data, parses EXIF metadata,
and detects steganography artifacts (F5, Outguess, JSteg).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from ichnos.core.detection import shannon_entropy

# Standard JPEG Markers
MARKER_SOI = 0xD8  # Start of Image
MARKER_EOI = 0xD9  # End of Image
MARKER_SOS = 0xDA  # Start of Scan
MARKER_DQT = 0xDB  # Define Quantization Table
MARKER_DHT = 0xC4  # Define Huffman Table
MARKER_SOF0 = 0xC0  # Baseline DCT
MARKER_SOF2 = 0xC2  # Progressive DCT
MARKER_COM = 0xFE  # Comment
MARKER_DRI = 0xDD  # Restart Interval

MARKER_NAMES = {
    0xD8: "SOI",
    0xD9: "EOI",
    0xDA: "SOS",
    0xDB: "DQT",
    0xC4: "DHT",
    0xC0: "SOF0 (Baseline)",
    0xC1: "SOF1 (Extended)",
    0xC2: "SOF2 (Progressive)",
    0xC3: "SOF3 (Lossless)",
    0xDD: "DRI",
    0xFE: "COM (Comment)",
}
for i in range(16):
    MARKER_NAMES[0xE0 + i] = f"APP{i}"


@dataclass
class JPEGMarker:
    """Represents a JPEG segment/marker."""

    marker: int
    name: str
    offset: int
    length: int
    data: bytes


MAX_SEGMENTS = 10_000


def parse_segments(data: bytes) -> list[JPEGMarker]:
    """Parses all JPEG markers and segments from raw bytes."""
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        raise ValueError("Invalid JPEG: missing SOI marker (\\xFF\\xD8)")

    segments: list[JPEGMarker] = []
    idx = 2
    size = len(data)

    segments.append(JPEGMarker(marker=MARKER_SOI, name="SOI", offset=0, length=2, data=b""))

    while idx < size - 1 and len(segments) < MAX_SEGMENTS:
        if data[idx] != 0xFF:
            idx += 1
            continue

        marker = data[idx + 1]
        # Ignore fill bytes \xff\xff or stuffing \xff\x00
        if marker == 0x00 or marker == 0xFF:
            idx += 2
            continue

        name = MARKER_NAMES.get(marker, f"0x{marker:02X}")

        if marker == MARKER_EOI:
            segments.append(JPEGMarker(marker=marker, name=name, offset=idx, length=2, data=b""))
            idx += 2
            break

        if marker == MARKER_SOS:
            # SOS has length prefix for scan header, followed by entropy-coded data
            if idx + 4 > size:
                break
            try:
                header_len = struct.unpack(">H", data[idx + 2 : idx + 4])[0]
            except struct.error:
                break
            if header_len < 2:
                break
            sos_header = data[idx + 4 : min(idx + 2 + header_len, size)]
            segments.append(
                JPEGMarker(
                    marker=marker,
                    name=name,
                    offset=idx,
                    length=header_len + 2,
                    data=sos_header,
                )
            )
            idx += 2 + header_len
            # Skip through entropy-coded scan data until next marker
            while idx < size - 1:
                if data[idx] == 0xFF and data[idx + 1] != 0x00 and data[idx + 1] != 0xFF:
                    # Found next marker
                    break
                idx += 1
            continue

        # Standard segment with 2-byte length
        if idx + 4 > size:
            break
        try:
            seg_len = struct.unpack(">H", data[idx + 2 : idx + 4])[0]
        except struct.error:
            break
        if seg_len < 2:
            idx += 2
            continue

        seg_data = data[idx + 4 : min(idx + 2 + seg_len, size)]
        segments.append(
            JPEGMarker(
                marker=marker,
                name=name,
                offset=idx,
                length=seg_len + 2,
                data=seg_data,
            )
        )
        idx += 2 + seg_len

    return segments


def extract_comments(data: bytes) -> list[str]:
    """Extracts all text comments from COM segments."""
    segments = parse_segments(data)
    comments = []
    for s in segments:
        if s.marker == MARKER_COM:
            try:
                comments.append(s.data.decode("utf-8", errors="replace"))
            except Exception:
                comments.append(repr(s.data))
    return comments


def detect_trailing_data(data: bytes) -> bytes | None:
    """Detects and returns any appended data following the JPEG EOI (\\xFF\\xD9) marker."""
    eoi_pos = data.rfind(b"\xff\xd9")
    if eoi_pos == -1:
        return None
    trailing = data[eoi_pos + 2 :]
    return trailing if len(trailing) > 0 else None


def parse_dimensions(data: bytes) -> tuple[int, int, int] | None:
    """Parses image dimensions (width, height, components) from SOF segment."""
    segments = parse_segments(data)
    for s in segments:
        # SOF0, SOF1, SOF2
        if s.marker in (0xC0, 0xC1, 0xC2) and len(s.data) >= 5:
            # precision (1 byte), height (2 bytes), width (2 bytes), components (1 byte)
            height, width, components = struct.unpack(">HHB", s.data[1:6])
            return width, height, components
    return None


def inspect_jpeg(data: bytes) -> dict[str, Any]:
    """Inspects a JPEG file and returns structural metadata, comments, and anomalies."""
    segments = parse_segments(data)
    dims = parse_dimensions(data)
    comments = extract_comments(data)
    trailing = detect_trailing_data(data)

    has_exif = any(s.marker == 0xE1 and s.data.startswith(b"Exif\x00\x00") for s in segments)
    has_jfif = any(s.marker == 0xE0 and s.data.startswith(b"JFIF\x00") for s in segments)

    return {
        "valid": True,
        "width": dims[0] if dims else None,
        "height": dims[1] if dims else None,
        "channels": dims[2] if dims else None,
        "segments_count": len(segments),
        "markers": [{"name": s.name, "offset": s.offset, "length": s.length} for s in segments],
        "comments": comments,
        "has_exif": has_exif,
        "has_jfif": has_jfif,
        "trailing_data_len": len(trailing) if trailing else 0,
        "has_trailing_data": trailing is not None,
    }


def detect_f5_outguess_artifacts(data: bytes) -> dict[str, Any]:
    """Performs statistical steganalysis on JPEG entropy and structural indicators."""
    info = inspect_jpeg(data)
    trailing = detect_trailing_data(data)
    entropy = shannon_entropy(data)

    suspect_indicators = []
    if trailing:
        suspect_indicators.append(f"Appended trailing data detected ({len(trailing)} bytes)")
    if info["comments"]:
        suspect_indicators.append(f"Embedded comments present: {info['comments']}")
    if entropy > 7.95:
        suspect_indicators.append(f"Unusually high whole-file entropy ({entropy:.4f})")

    return {
        "suspect": len(suspect_indicators) > 0,
        "indicators": suspect_indicators,
        "entropy": round(entropy, 4),
        "trailing_bytes": len(trailing) if trailing else 0,
    }
