"""Miscellaneous binary utilities."""

from __future__ import annotations


def swap_endian(data: bytes, word_size: int = 4) -> bytes:
    res = bytearray()
    for i in range(0, len(data), word_size):
        chunk = data[i : i + word_size]
        res.extend(chunk[::-1])
    return bytes(res)


def hamming_distance(a: bytes, b: bytes) -> int:
    dist = 0
    for byte_a, byte_b in zip(a, b):
        diff = byte_a ^ byte_b
        dist += diff.bit_count()
    return dist + (abs(len(a) - len(b)) * 8)


def hamming_weight(data: bytes) -> int:
    return sum(b.bit_count() for b in data)
