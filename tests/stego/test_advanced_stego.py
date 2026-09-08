"""Tests for advanced steganography analyzers.

Covers:
- Animated PNG (APNG) animation chunk parser and frame extraction
- Multi-frame GIF comment extraction and frame timing steganography
- PNG IDAT deflate compression anomaly scanner
"""

import struct
import zlib

from ichnos.stego.image.apng import is_apng, parse_apng
from ichnos.stego.image.deflate_anomaly import analyze_idat_deflate
from ichnos.stego.image.gif_frames import (
    extract_gif_comments,
    extract_gif_frame_delays,
    is_gif,
)


def _make_chunk(chunk_type: bytes, data: bytes) -> bytes:
    length = struct.pack(">I", len(data))
    crc = struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
    return length + chunk_type + data + crc


def _make_minimal_png() -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"
    # IHDR: 1x1, 8-bit RGBA
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    ihdr = _make_chunk(b"IHDR", ihdr_data)
    # Raw pixel: filter 0 + 4 bytes RGBA (0, 0, 0, 0)
    raw_scanline = b"\x00\x00\x00\x00\x00"
    idat = _make_chunk(b"IDAT", zlib.compress(raw_scanline))
    iend = _make_chunk(b"IEND", b"")
    return sig + ihdr + idat + iend


def test_apng_parsing():
    png_bytes = _make_minimal_png()
    assert is_apng(png_bytes) is False

    # Inject acTL and fcTL chunks into the PNG
    sig = png_bytes[:8]
    ihdr_len = struct.unpack(">I", png_bytes[8:12])[0]
    ihdr_chunk = png_bytes[8 : 8 + 12 + ihdr_len]
    rest = png_bytes[8 + 12 + ihdr_len :]

    actl_data = struct.pack(">II", 2, 0)  # 2 frames, infinite loop
    actl = _make_chunk(b"acTL", actl_data)

    fctl_data = struct.pack(">IIIIIIIBB", 0, 1, 1, 0, 0, 10, 100, 0, 0)
    fctl = _make_chunk(b"fcTL", fctl_data)

    apng_bytes = sig + ihdr_chunk + actl + fctl + rest
    assert is_apng(apng_bytes) is True

    parsed = parse_apng(apng_bytes)
    assert parsed["is_animated"] is True
    assert parsed["num_frames"] == 2
    assert len(parsed["frame_headers"]) == 1


def test_gif_comments_and_delays():
    assert is_gif(b"NOT_A_GIF") is False

    # Synthetic GIF89a: Header (6) + Screen Descriptor (7)
    # flags = 0 (no global color table)
    header = b"GIF89a"
    lsd = struct.pack("<HHBBB", 10, 10, 0x00, 0, 0)

    # Comment Extension: 0x21 0xFE, sub-block length, comment, terminator 0x00
    comment_text = b"FLAG{gif_comment_extracted}"
    comment_ext = b"\x21\xfe" + bytes([len(comment_text)]) + comment_text + b"\x00"

    # Graphic Control Extension: 0x21 0xF9, block size 4, packed (1), delay (2), transparent (1), term 0x00
    # delay = 50 (0.50 seconds)
    gce_ext = b"\x21\xf9\x04\x00" + struct.pack("<H", 50) + b"\x00\x00"

    trailer = b"\x3b"
    gif_bytes = header + lsd + comment_ext + gce_ext + trailer

    assert is_gif(gif_bytes) is True
    comments = extract_gif_comments(gif_bytes)
    assert len(comments) == 1
    assert comments[0] == "FLAG{gif_comment_extracted}"

    delays = extract_gif_frame_delays(gif_bytes)
    assert delays == [50]


def test_deflate_anomaly_clean():
    png_bytes = _make_minimal_png()
    res = analyze_idat_deflate(png_bytes)
    assert "has_anomalies" in res
