"""Numeral systems: binary, octal, ternary, balanced ternary, negabinary, Gray code, BCD, Excess-3."""

from __future__ import annotations


def to_binary(n: int) -> str:
    """Converts integer to binary string."""
    return bin(n)[2:] if n >= 0 else "-" + bin(n)[3:]


def from_binary(s: str) -> int:
    """Converts binary string to integer."""
    return int(s.strip(), 2)


def to_octal(n: int) -> str:
    """Converts integer to octal string."""
    return oct(n)[2:] if n >= 0 else "-" + oct(n)[3:]


def from_octal(s: str) -> int:
    """Converts octal string to integer."""
    return int(s.strip(), 8)


def to_ternary(n: int) -> str:
    """Converts integer to standard ternary (base 3) string."""
    if n == 0:
        return "0"
    sign = "-" if n < 0 else ""
    n = abs(n)
    digits = []
    while n > 0:
        digits.append(str(n % 3))
        n //= 3
    return sign + "".join(reversed(digits))


def from_ternary(s: str) -> int:
    """Converts ternary string to integer."""
    return int(s.strip(), 3)


def to_balanced_ternary(n: int) -> str:
    """Converts integer to balanced ternary (digits: 'T'=-1, '0'=0, '1'=1)."""
    if n == 0:
        return "0"
    digits = []
    val = n
    while val != 0:
        rem = val % 3
        if rem == 0:
            digits.append("0")
            val //= 3
        elif rem == 1:
            digits.append("1")
            val //= 3
        else:  # rem == 2 -> representation is -1 (T) and carry 1
            digits.append("T")
            val = (val + 1) // 3
    return "".join(reversed(digits))


def from_balanced_ternary(s: str) -> int:
    """Converts balanced ternary string to integer."""
    res = 0
    val_map = {"T": -1, "-": -1, "0": 0, "1": 1}
    for c in s.strip():
        if c in val_map:
            res = res * 3 + val_map[c]
    return res


def to_negabinary(n: int) -> str:
    """Converts integer to base -2 (negabinary) string."""
    if n == 0:
        return "0"
    digits = []
    val = n
    while val != 0:
        rem = val % (-2)
        val //= -2
        if rem < 0:
            rem += 2
            val += 1
        digits.append(str(rem))
    return "".join(reversed(digits))


def from_negabinary(s: str) -> int:
    """Converts negabinary string to integer."""
    res = 0
    for c in s.strip():
        if c in ("0", "1"):
            res = res * (-2) + int(c)
    return res


def encode_gray(n: int) -> int:
    """Encodes binary integer to Gray code integer (n ^ (n >> 1))."""
    return n ^ (n >> 1)


def decode_gray(g: int) -> int:
    """Decodes Gray code integer to binary integer."""
    n = g
    mask = n >> 1
    while mask != 0:
        n ^= mask
        mask >>= 1
    return n


def encode_bcd(n: int) -> str:
    """Encodes integer to Binary-Coded Decimal (4-bit nibbles)."""
    s = str(abs(n))
    return " ".join(f"{int(d):04b}" for d in s)


def decode_bcd(s: str) -> int:
    """Decodes Binary-Coded Decimal string to integer."""
    tokens = s.replace(" ", "")
    digits = []
    for i in range(0, len(tokens), 4):
        chunk = tokens[i : i + 4]
        if len(chunk) == 4:
            digits.append(str(int(chunk, 2)))
    return int("".join(digits)) if digits else 0


def encode_excess3(n: int) -> str:
    """Encodes integer to Excess-3 (Stibitz) code (d + 3 as 4-bit binary)."""
    s = str(abs(n))
    return " ".join(f"{(int(d) + 3):04b}" for d in s)


def decode_excess3(s: str) -> int:
    """Decodes Excess-3 binary string to decimal integer."""
    nibbles = s.strip().split()
    res = []
    for nib in nibbles:
        val = int(nib, 2) - 3
        res.append(str(val))
    return int("".join(res))


# Convenient aliases
to_gray_code = encode_gray
from_gray_code = decode_gray
to_bcd = encode_bcd
from_bcd = decode_bcd
to_excess3 = encode_excess3
from_excess3 = decode_excess3
