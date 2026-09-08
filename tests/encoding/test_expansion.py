"""Unit tests for Phase D: Encodings, Numerals, Telecom, Checksums, Advanced Esolangs, and Barcodes."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from ichnos.cli.main import app
from ichnos.encoding import (
    barcode,
    bases,
    numerals,
    telecom,
)
from ichnos.encoding import (
    compression_checksums as chk,
)
from ichnos.encoding import (
    esolang_advanced as esolang_adv,
)
from ichnos.encoding import (
    text_extended as text_ext,
)

runner = CliRunner()


# =============================================================================
# 1. Base Encodings Expansion
# =============================================================================


def test_bases_expansion():
    sample = b"CTF{expanded_bases_rock}"

    # Crockford Base32
    crock = bases.encode_base32_crockford(sample)
    assert bases.decode_base32_crockford(crock) == sample

    # Z-base-32
    zb32 = bases.encode_zbase32(sample)
    assert bases.decode_zbase32(zb32) == sample

    # Base45 (RFC 9285)
    b45 = bases.encode_base45(sample)
    assert bases.decode_base45(b45) == sample

    # Base62
    b62 = bases.encode_base62(sample)
    assert bases.decode_base62(b62) == sample

    # Base92
    b92 = bases.encode_base92(sample)
    assert bases.decode_base92(b92) == sample

    # Base100 (Emoji)
    b100 = bases.encode_base100(sample)
    assert bases.decode_base100(b100) == sample

    # Base26 & Base36
    b26 = bases.encode_base26(sample)
    assert bases.decode_base26(b26) == sample
    b36 = bases.encode_base36(sample)
    assert bases.decode_base36(b36) == sample


# =============================================================================
# 2. Numerals
# =============================================================================


def test_numerals():
    # Ternary
    assert numerals.to_ternary(27) == "1000"
    assert numerals.from_ternary("1000") == 27

    # Balanced ternary
    assert numerals.to_balanced_ternary(11) == "11T"
    assert numerals.from_balanced_ternary("11T") == 11
    assert numerals.to_balanced_ternary(-11) == "TT1"
    assert numerals.from_balanced_ternary("TT1") == -11

    # Negabinary (base -2)
    for v in [0, 1, -1, 5, -5, 42, -42]:
        nb = numerals.to_negabinary(v)
        assert numerals.from_negabinary(nb) == v

    # Gray code
    gray_val = numerals.to_gray_code(13)  # 13 is 1101_2 -> gray is 1011_2 = 11
    assert gray_val == 11
    assert numerals.from_gray_code(gray_val) == 13

    # BCD
    bcd_str = numerals.to_bcd(1234)
    assert bcd_str == "0001 0010 0011 0100"
    assert numerals.from_bcd(bcd_str) == 1234
    assert numerals.from_bcd("0001001000110100") == 1234

    # Excess-3
    ex3 = numerals.to_excess3(12)
    assert numerals.from_excess3(ex3) == 12


# =============================================================================
# 3. Telecom
# =============================================================================


def test_telecom():
    # Baudot (ITA2)
    msg = "HELLO 123"
    baud = telecom.encode_baudot(msg)
    dec_baud = telecom.decode_baudot(baud)
    assert dec_baud == msg

    # Manchester (IEEE 802.3)
    bin_str = "10110"
    manch = telecom.encode_manchester(bin_str)
    assert telecom.decode_manchester(manch) == bin_str

    # Alternate Mark Inversion (AMI)
    ami_str = telecom.encode_ami(bin_str)
    assert telecom.decode_ami(ami_str) == bin_str

    # T9 / Multi-tap
    t9_enc = telecom.encode_t9("HELLO")
    assert telecom.decode_t9(t9_enc) == "HELLO"


# =============================================================================
# 4. Compression & Checksums
# =============================================================================


def test_compression_checksums():
    # RLE
    uncompressed = "AAABBBCCCCCDD"
    rle = chk.rle_compress(uncompressed)
    assert chk.rle_decompress(rle) == uncompressed

    # CRC32
    assert chk.crc32(b"123456789") == 0xCBF43926

    # Luhn algorithm
    card = "7992739871"
    check = chk.luhn_checksum(card)
    assert check == 3
    assert chk.luhn_generate(card) == f"{card}{check}"
    assert chk.luhn_validate(f"{card}{check}") is True
    assert chk.luhn_validate(f"{card}4") is False

    # Verhoeff D5 algorithm
    num = "236"
    v_check = chk.verhoeff_generate(num)
    assert chk.verhoeff_validate(f"{num}{v_check}") is True
    assert chk.verhoeff_validate(f"{num}9") is False


# =============================================================================
# 5. Extended Text Encodings
# =============================================================================


def test_text_extended():
    # Punycode
    domain = "münchen"
    p_enc = text_ext.punycode_encode(domain, add_prefix=True)
    assert p_enc.startswith("xn--")
    assert text_ext.punycode_decode(p_enc) == domain

    # UUencode
    raw = b"FLAG{uuencode_master}"
    uu = text_ext.uuencode(raw, filename="secret.txt")
    assert "begin " in uu and "end" in uu
    assert text_ext.uudecode(uu) == raw

    # Quoted-Printable
    qp_input = b"Hello = World\nSecret!"
    qp_enc = text_ext.quoted_printable_encode(qp_input)
    assert text_ext.quoted_printable_decode(qp_enc) == qp_input

    # LEB128: ULEB128
    for u in [0, 1, 127, 128, 624485]:
        b = text_ext.encode_uleb128(u)
        val, n = text_ext.decode_uleb128(b)
        assert val == u
        assert n == len(b)

    # LEB128: SLEB128
    for s in [0, 1, -1, 127, -128, 128, 624485, -624485]:
        b = text_ext.encode_sleb128(s)
        val, n = text_ext.decode_sleb128(b)
        assert val == s
        assert n == len(b)

    # Zero-Width Stego
    secret = "FLAG{invisible_text}"
    cover = "This is a normal looking cover text."
    stego_text = text_ext.encode_zero_width(secret, cover=cover)
    assert text_ext.has_zero_width(stego_text) is True
    assert text_ext.decode_zero_width(stego_text) == secret


# =============================================================================
# 6. Advanced Esolangs (Malbolge & AAEncode)
# =============================================================================


def test_esolang_advanced():
    # Malbolge Hello World
    malbolge_hello = (
        "(=<`#9]~6ZY327Uv4-QsqpMn&+Ij\"'E%e{Ab~w=_:]Kw%o44Uqp0/Q?xNvL:`H%c#DD2^WV>gY;dts76qKJImZkj"
    )
    output = esolang_adv.interpret_malbolge(malbolge_hello, max_steps=50000)
    assert output == "Hello, world."

    # AAEncode
    js_code = 'alert("FLAG{aaencode_passed}")'
    encoded_aa = esolang_adv.aaencode(js_code)
    assert esolang_adv.is_aaencoded(encoded_aa) is True
    decoded_aa = esolang_adv.decode_aaencode(encoded_aa)
    assert decoded_aa == js_code


# =============================================================================
# 7. Barcode Module (Code 39 & zxing-cpp check)
# =============================================================================


def test_barcode_module():
    # Check availability function exists
    assert isinstance(barcode.is_zxing_available(), bool)

    # Test pure Python Code 39 SVG generation
    text = "FLAG123"
    svg = barcode.generate_code39_svg(text)
    assert "<svg" in svg and "</svg>" in svg
    assert f"*{text}*" in svg

    # Invalid character in Code 39 raises ValueError
    with pytest.raises(ValueError, match="not supported"):
        barcode.encode_code39_pattern("flag~lowercase_unsupported")


# =============================================================================
# 8. CLI Commands Smoke Tests
# =============================================================================


def test_cli_encoding_commands():
    # Encode & Decode Crockford
    r1 = runner.invoke(app, ["encoding", "encode", "HELLO", "--format", "crockford"])
    assert r1.exit_code == 0
    enc_val = r1.output.strip()

    r2 = runner.invoke(app, ["encoding", "decode", enc_val, "--format", "crockford"])
    assert r2.exit_code == 0
    assert "HELLO" in r2.output

    # Numeral
    r3 = runner.invoke(app, ["encoding", "numeral", "11", "--mode", "balanced-ternary"])
    assert r3.exit_code == 0
    assert "11T" in r3.output

    # Telecom
    r4 = runner.invoke(app, ["encoding", "telecom", "HELLO", "--proto", "t9", "--encode"])
    assert r4.exit_code == 0
    assert "44 33 555 555 666" in r4.output

    # Checksum CRC32
    r5 = runner.invoke(app, ["encoding", "checksum", "123456789", "--algo", "crc32"])
    assert r5.exit_code == 0
    assert "0xcbf43926" in r5.output

    # Barcode SVG
    r6 = runner.invoke(app, ["encoding", "barcode", "TEST", "--generate"])
    assert r6.exit_code == 0
    assert "<svg" in r6.output
