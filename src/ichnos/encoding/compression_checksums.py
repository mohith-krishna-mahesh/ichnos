"""Compression (RLE) and checksum algorithms (CRC-32, Luhn, Verhoeff)."""

from __future__ import annotations

import re
import zlib

# =============================================================================
# 1. Run-Length Encoding (RLE)
# =============================================================================


def encode_rle(text: str) -> str:
    """Encodes string using Run-Length Encoding (e.g. 'AAABBC' -> '3A2B1C')."""
    if not text:
        return ""
    res = []
    curr = text[0]
    count = 1
    for c in text[1:]:
        if c == curr:
            count += 1
        else:
            res.append(f"{count}{curr}")
            curr = c
            count = 1
    res.append(f"{count}{curr}")
    return "".join(res)


def decode_rle(encoded: str) -> str:
    """Decodes Run-Length Encoded string (e.g. '3A2B1C' -> 'AAABBC')."""
    pairs = re.findall(r"(\d+)(.)", encoded)
    res = []
    for count_str, char in pairs:
        res.append(char * int(count_str))
    return "".join(res)


# =============================================================================
# 2. CRC-32 Checksum
# =============================================================================


def compute_crc32(data: bytes) -> int:
    """Computes standard IEEE 802.3 CRC-32 checksum (returns unsigned 32-bit integer)."""
    return zlib.crc32(data) & 0xFFFFFFFF


def compute_crc32_hex(data: bytes) -> str:
    """Computes standard CRC-32 checksum formatted as 8-character hex string."""
    return f"{compute_crc32(data):08x}"


# =============================================================================
# 3. Luhn Algorithm (Mod 10 Checksum)
# =============================================================================


def luhn_checksum(digits: str) -> int:
    """Computes the Luhn check digit for a string of digits."""
    clean = re.sub(r"\D", "", digits)
    total = 0
    reverse_digits = [int(d) for d in reversed(clean)]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 0:
            doubled = d * 2
            total += (doubled - 9) if doubled > 9 else doubled
        else:
            total += d
    return (10 - (total % 10)) % 10


def luhn_validate(number_str: str) -> bool:
    """Validates whether a number string satisfies the Luhn algorithm."""
    clean = re.sub(r"\D", "", number_str)
    if not clean:
        return False
    total = 0
    reverse_digits = [int(d) for d in reversed(clean)]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            total += (doubled - 9) if doubled > 9 else doubled
        else:
            total += d
    return total % 10 == 0


def luhn_generate(payload: str) -> str:
    """Appends the Luhn check digit to a number string."""
    check = luhn_checksum(payload)
    return payload + str(check)


# =============================================================================
# 4. Verhoeff Algorithm (Dihedral Group D5 Checksum)
# =============================================================================

# Multiplication table d
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

# Permutation table p
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

# Inverse table inv
_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_checksum(digits: str) -> int:
    """Computes the Verhoeff check digit for a string of digits."""
    clean = re.sub(r"\D", "", digits)
    c = 0
    reversed_digits = [int(d) for d in reversed(clean)]
    for i, d in enumerate(reversed_digits):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][d]]
    return _VERHOEFF_INV[c]


def verhoeff_validate(number_str: str) -> bool:
    """Validates whether a number string satisfies the Verhoeff algorithm."""
    clean = re.sub(r"\D", "", number_str)
    if not clean:
        return False
    c = 0
    reversed_digits = [int(d) for d in reversed(clean)]
    for i, d in enumerate(reversed_digits):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][d]]
    return c == 0


# Friendly aliases
rle_compress = encode_rle
rle_decompress = decode_rle
crc32 = compute_crc32
verhoeff_generate = verhoeff_checksum
verhoeff_verify = verhoeff_validate
