from __future__ import annotations

from ichnos.core.detection import english_score
from ichnos.core.models import Candidate
from ichnos.crypto.numtheory import gcd, mod_inverse


def encrypt(text: str, a: int, b: int) -> str:
    """Encrypt text using Affine cipher: E(x) = (ax + b) mod 26."""
    result = []
    for c in text:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            x = ord(c) - base
            result.append(chr((a * x + b) % 26 + base))
        else:
            result.append(c)
    return "".join(result)


def decrypt(text: str, a: int, b: int) -> str:
    """Decrypt text using Affine cipher."""
    try:
        a_inv = mod_inverse(a, 26)
    except ValueError:
        return text
    result = []
    for c in text:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            x = ord(c) - base
            result.append(chr((a_inv * (x - b)) % 26 + base))
        else:
            result.append(c)
    return "".join(result)


def brute_force(text: str) -> list[Candidate]:
    """Try all valid (a, b) pairs and return candidates sorted by English score."""
    candidates = []
    for a in range(1, 26):
        if gcd(a, 26) == 1:
            for b in range(26):
                dec = decrypt(text, a, b)
                score = english_score(dec)
                candidates.append(
                    Candidate(
                        decoded=dec.encode(),
                        method="affine",
                        confidence=score,
                        layers=["affine"],
                        key=f"a={a},b={b}",
                    )
                )
    candidates.sort(key=lambda x: x.confidence, reverse=True)
    return candidates
