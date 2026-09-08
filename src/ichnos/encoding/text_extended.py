"""Extended text encoding utilities.

Supports Punycode (RFC 3492), UUencode/UUdecode, Quoted-Printable (RFC 2045),
LEB128 (Unsigned and Signed Little Endian Base 128), and Zero-Width steganography.
"""

from __future__ import annotations

import binascii
import codecs
import quopri

# =============================================================================
# Punycode (RFC 3492 / IDNA)
# =============================================================================


def punycode_encode(text: str, add_prefix: bool = False) -> str:
    """Encodes a unicode string using Punycode.

    If add_prefix is True, prepends 'xn--'.
    """
    encoded = codecs.encode(text, "punycode").decode("ascii")
    return f"xn--{encoded}" if add_prefix else encoded


def punycode_decode(encoded: str) -> str:
    """Decodes a Punycode string back to unicode.

    Handles optional 'xn--' prefix.
    """
    s = encoded.strip()
    if s.lower().startswith("xn--"):
        s = s[4:]
    return codecs.decode(s.encode("ascii"), "punycode")


# =============================================================================
# UUencode / UUdecode
# =============================================================================


def uuencode(data: bytes, filename: str = "data.bin", mode: int = 0o644) -> str:
    """Encodes raw bytes to standard UUencoded ASCII text format."""
    lines = [f"begin {mode:03o} {filename}"]
    chunk_size = 45
    for i in range(0, len(data), chunk_size):
        chunk = data[i : i + chunk_size]
        line = binascii.b2a_uu(chunk).decode("ascii")
        lines.append(line.rstrip("\r\n"))
    lines.append("`")
    lines.append("end")
    return "\n".join(lines) + "\n"


def uudecode(text: str) -> bytes:
    """Decodes UUencoded text back to raw bytes."""
    lines = text.strip().splitlines()
    out = bytearray()
    started = False

    for line in lines:
        stripped = line.strip()
        if not started:
            if stripped.startswith("begin "):
                started = True
            continue

        if stripped in ("end", "`", ""):
            if stripped == "end":
                break
            continue

        try:
            raw_line = line.encode("ascii")
            if not raw_line.endswith(b"\n"):
                raw_line += b"\n"
            out.extend(binascii.a2b_uu(raw_line))
        except (binascii.Error, ValueError):
            continue

    if not started and lines:
        for line in lines:
            if not line:
                continue
            try:
                raw_line = line.encode("ascii")
                if not raw_line.endswith(b"\n"):
                    raw_line += b"\n"
                out.extend(binascii.a2b_uu(raw_line))
            except (binascii.Error, ValueError):
                pass

    return bytes(out)


# =============================================================================
# Quoted-Printable (RFC 2045)
# =============================================================================


def quoted_printable_encode(data: bytes | str) -> str:
    """Encodes bytes or string to Quoted-Printable format."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return quopri.encodestring(data).decode("latin-1")


def quoted_printable_decode(text: str) -> bytes:
    """Decodes Quoted-Printable text back to raw bytes."""
    return quopri.decodestring(text.encode("latin-1"))


# =============================================================================
# LEB128 (Little Endian Base 128)
# =============================================================================


def encode_uleb128(val: int) -> bytes:
    """Encodes a non-negative integer using Unsigned LEB128."""
    if val < 0:
        raise ValueError("Cannot encode negative integer with ULEB128")
    res = bytearray()
    while True:
        byte = val & 0x7F
        val >>= 7
        if val != 0:
            byte |= 0x80
        res.append(byte)
        if val == 0:
            break
    return bytes(res)


def decode_uleb128(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decodes an Unsigned LEB128 integer from data at given offset.

    Returns (value, bytes_consumed).
    """
    result = 0
    shift = 0
    idx = offset
    size = len(data)
    while idx < size:
        byte = data[idx]
        idx += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, idx - offset
        shift += 7
    raise ValueError("Incomplete ULEB128 sequence")


def encode_sleb128(val: int) -> bytes:
    """Encodes a signed integer using Signed LEB128."""
    res = bytearray()
    more = True
    while more:
        byte = val & 0x7F
        val >>= 7
        sign_bit = bool(byte & 0x40)
        if (val == 0 and not sign_bit) or (val == -1 and sign_bit):
            more = False
        else:
            byte |= 0x80
        res.append(byte)
    return bytes(res)


def decode_sleb128(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decodes a Signed LEB128 integer from data at given offset.

    Returns (value, bytes_consumed).
    """
    result = 0
    shift = 0
    idx = offset
    size = len(data)
    while idx < size:
        byte = data[idx]
        idx += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            if byte & 0x40:
                result |= -(1 << shift)
            return result, idx - offset
    raise ValueError("Incomplete SLEB128 sequence")


# =============================================================================
# Zero-Width Steganography
# =============================================================================

ZW_ZERO = "\u200b"
ZW_ONE = "\u200c"
ZW_CHARS = {"\u200b", "\u200c", "\u200d", "\ufeff"}


def has_zero_width(text: str) -> bool:
    """Checks whether the text contains zero-width unicode characters."""
    return any(ch in ZW_CHARS for ch in text)


def encode_zero_width(secret: str | bytes, cover: str = "") -> str:
    """Hides a secret message within cover text using zero-width characters.

    Each byte is converted to an 8-bit binary string where 0 is \\u200B and 1 is \\u200C.
    """
    if isinstance(secret, str):
        secret_bytes = secret.encode("utf-8")
    else:
        secret_bytes = secret

    zw_stream = []
    for b in secret_bytes:
        bits = f"{b:08b}"
        for bit in bits:
            zw_stream.append(ZW_ONE if bit == "1" else ZW_ZERO)

    hidden = "".join(zw_stream)
    if not cover:
        return hidden

    parts = cover.split(" ", 1)
    if len(parts) == 2:
        return f"{parts[0]}{hidden} {parts[1]}"
    return f"{cover}{hidden}"


def decode_zero_width(text: str) -> str:
    """Extracts and decodes zero-width hidden characters into a UTF-8 string."""
    bits = []
    for ch in text:
        if ch == ZW_ZERO:
            bits.append("0")
        elif ch == ZW_ONE:
            bits.append("1")

    if not bits:
        return ""

    bit_str = "".join(bits)
    bytes_list = []
    for i in range(0, len(bit_str) - (len(bit_str) % 8), 8):
        byte_val = int(bit_str[i : i + 8], 2)
        bytes_list.append(byte_val)

    try:
        return bytes(bytes_list).decode("utf-8")
    except UnicodeDecodeError:
        return bytes(bytes_list).decode("latin-1")
