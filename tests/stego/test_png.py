import struct
import zlib

import pytest

from ichnos.stego.image.png import detect_trailing_data, find_text_chunks, parse_chunks, parse_ihdr


def _make_chunk(chunk_type, data):
    length = struct.pack(">I", len(data))
    crc = struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
    return length + chunk_type + data + crc


@pytest.fixture
def minimal_png():
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr = _make_chunk(b"IHDR", ihdr_data)
    raw = b"\x00\xff\x00\x00"
    idat_data = zlib.compress(raw)
    idat = _make_chunk(b"IDAT", idat_data)
    iend = _make_chunk(b"IEND", b"")
    return sig + ihdr + idat + iend


def test_parse_chunks(minimal_png):
    chunks = parse_chunks(minimal_png)
    assert len(chunks) == 3
    assert chunks[0][0] == b"IHDR"
    assert chunks[1][0] == b"IDAT"
    assert chunks[2][0] == b"IEND"


def test_parse_ihdr(minimal_png):
    chunks = parse_chunks(minimal_png)
    ihdr = parse_ihdr(chunks[0][1])
    assert ihdr["width"] == 1
    assert ihdr["height"] == 1
    assert ihdr["bit_depth"] == 8
    assert ihdr["color_type"] == 2


def test_detect_trailing_data(minimal_png):
    png_with_trailing = minimal_png + b"SECRET"
    trailing = detect_trailing_data(png_with_trailing)
    assert trailing == b"SECRET"


def test_no_trailing_data(minimal_png):
    trailing = detect_trailing_data(minimal_png)
    assert trailing is None


def test_text_chunks(minimal_png):
    sig = b"\x89PNG\r\n\x1a\n"
    chunks = parse_chunks(minimal_png)
    text_data = b"Author\x00Ichnos"
    text_chunk = _make_chunk(b"tEXt", text_data)
    # inject after IHDR
    new_png = (
        sig
        + _make_chunk(b"IHDR", chunks[0][1])
        + text_chunk
        + _make_chunk(b"IDAT", chunks[1][1])
        + _make_chunk(b"IEND", chunks[2][1])
    )
    texts = find_text_chunks(new_png)
    assert len(texts) == 1
    assert texts[0]["keyword"] == "Author"
    assert texts[0]["text"] == "Ichnos"
