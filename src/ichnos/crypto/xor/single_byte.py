from __future__ import annotations

from ichnos.core.models import Candidate

CHAR_FREQ = {
    " ": 0.18,
    "e": 0.127,
    "t": 0.091,
    "a": 0.082,
    "o": 0.075,
    "i": 0.070,
    "n": 0.067,
    "s": 0.063,
    "h": 0.061,
    "r": 0.060,
    "d": 0.043,
    "l": 0.040,
    "c": 0.028,
    "u": 0.028,
    "m": 0.024,
    "w": 0.024,
    "f": 0.022,
    "g": 0.020,
    "y": 0.020,
    "p": 0.019,
    "b": 0.015,
    "v": 0.010,
    "k": 0.008,
    "j": 0.002,
    "x": 0.002,
    "q": 0.001,
    "z": 0.001,
}


def xor_single(data: bytes, key: int) -> bytes:
    """XOR every byte in data with the given key."""
    return bytes(b ^ key for b in data)


def score_plaintext(data: bytes) -> float:
    """Score candidate plaintext based on English character frequencies."""
    if not data:
        return 0.0
    score = 0.0
    for b in data:
        if b < 32 and b not in (9, 10, 13):
            score -= 10.0
            continue
        c = chr(b).lower()
        if c in CHAR_FREQ:
            score += CHAR_FREQ[c]
        elif 32 <= b <= 126:
            score += 0.005
        else:
            score -= 5.0
    norm = score / len(data)
    if norm <= 0:
        return 0.0
    return min(1.0, norm / 0.08)


def brute_force(data: bytes) -> list[Candidate]:
    """Try all 256 keys, score by English character frequency."""
    candidates = []
    for key in range(256):
        dec = xor_single(data, key)
        conf = score_plaintext(dec)
        candidates.append(
            Candidate(
                decoded=dec,
                method="single_byte_xor",
                confidence=conf,
                layers=["single_byte_xor"],
                key=hex(key),
            )
        )
    candidates.sort(key=lambda x: x.confidence, reverse=True)
    return candidates
