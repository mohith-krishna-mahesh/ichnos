"""Tests for deep forensics tools: Acropalypse, ZIP repair, PDF hidden streams, memory carver."""

from __future__ import annotations

import struct
import zlib

from ichnos.forensic.acropalypse import analyze_acropalypse, detect_png_trailing_data
from ichnos.forensic.memory import carve_env_variables, carve_ipv4, carve_pem_keys
from ichnos.forensic.pdf import extract_metadata, extract_text_objects, find_hidden_text
from ichnos.forensic.repair import detect_zip_pseudo_encryption, fix_zip_pseudo_encryption
from ichnos.stego.image.repair import detect_ihdr_crc_mismatch, repair_png_dimensions


def test_acropalypse_png_detection():
    # Construct a minimal PNG with trailing data after IEND
    # PNG signature: 8 bytes
    png_sig = b"\x89PNG\r\n\x1a\n"
    # IHDR: length=13, type=IHDR, data=..., crc=...
    ihdr_data = struct.pack(">IIBBBBB", 10, 10, 8, 2, 0, 0, 0)
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data)
    ihdr_chunk = struct.pack(">I", 13) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)

    # IEND: length=0, type=IEND, crc=...
    iend_crc = zlib.crc32(b"IEND")
    iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)

    trailing = b"SECRET_LEFTOVER_IMAGE_DATA_12345"
    full_data = png_sig + ihdr_chunk + iend_chunk + trailing

    has_trailing, off, trailed = detect_png_trailing_data(full_data)
    assert has_trailing is True
    assert trailed == trailing

    analysis = analyze_acropalypse(full_data)
    assert analysis["vulnerable"] is True
    assert analysis["trailing_size"] == len(trailing)


def test_zip_pseudo_encryption():
    # Minimal ZIP local header with bit 0 set
    # PK\x03\x04 + version (2) + flags (2) with bit 0 set
    zip_header = b"PK\x03\x04\x14\x00\x01\x00\x00\x00" + b"\x00" * 20
    assert detect_zip_pseudo_encryption(zip_header) is True

    fixed = fix_zip_pseudo_encryption(zip_header)
    assert detect_zip_pseudo_encryption(fixed) is False


def test_png_ihdr_crc_repair():
    png_sig = b"\x89PNG\r\n\x1a\n"
    orig_w, orig_h = 100, 200
    ihdr_data = struct.pack(">IIBBBBB", orig_w, orig_h, 8, 2, 0, 0, 0)
    correct_crc = zlib.crc32(b"IHDR" + ihdr_data)

    # Tamper height to 50 but keep correct_crc to trigger mismatch
    tampered_data = struct.pack(">IIBBBBB", orig_w, 50, 8, 2, 0, 0, 0)
    tampered_ihdr = struct.pack(">I", 13) + b"IHDR" + tampered_data + struct.pack(">I", correct_crc)
    iend_crc = zlib.crc32(b"IEND")
    iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)
    tampered_png = png_sig + tampered_ihdr + iend_chunk

    assert detect_ihdr_crc_mismatch(tampered_png) is True
    repaired_bytes, info = repair_png_dimensions(tampered_png)
    assert info.get("repaired") is True
    assert info.get("correct_height") == orig_h


def test_memory_carving():
    mem_dump = (
        b"Some random binary memory content \x00\xff\xee"
        b"FLAG=NNS{memory_carved_flag}\x00"
        b"TOKEN=abcdef123456\n"
        b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n"
        b"Connecting to 192.168.1.100 on port 80\x00"
    )

    envs = carve_env_variables(mem_dump)
    assert envs.get("FLAG") == "NNS{memory_carved_flag}"
    assert envs.get("TOKEN") == "abcdef123456"

    pem_keys = carve_pem_keys(mem_dump)
    assert len(pem_keys) == 1
    assert pem_keys[0]["type"] == "RSA PRIVATE KEY"

    ips = carve_ipv4(mem_dump)
    assert "192.168.1.100" in ips


def test_pdf_hidden_text():
    pdf_content = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Title (Confidential Document) >>\nendobj\n"
        b"2 0 obj\n<<>>\nstream\nBT\n/F1 12 Tf\n(Visible Text) Tj\n1 1 1 rg\n(FLAG{white_on_white_hidden}) Tj\nET\nendstream\nendobj\n"
        b"%%EOF\n"
    )

    meta = extract_metadata(pdf_content)
    assert meta.get("Title") == "Confidential Document"

    texts = extract_text_objects(pdf_content)
    assert "Visible Text" in texts
    assert "FLAG{white_on_white_hidden}" in texts

    hidden = find_hidden_text(pdf_content)
    assert any("FLAG{white_on_white_hidden}" in h for h in hidden)
