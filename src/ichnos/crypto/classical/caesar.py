from __future__ import annotations

from ichnos.core.detection import english_score
from ichnos.core.models import Candidate


def encrypt(text: str, shift: int) -> str:
    """Encrypt text using Caesar cipher with the given shift."""
    result = []
    for c in text:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            result.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            result.append(c)
    return "".join(result)


def decrypt(text: str, shift: int) -> str:
    """Decrypt text using Caesar cipher with the given shift."""
    return encrypt(text, -shift)


def brute_force(text: str) -> list[Candidate]:
    """Try all 26 shifts and return candidates sorted by English score."""
    candidates = []
    for shift in range(26):
        decrypted = decrypt(text, shift)
        score = english_score(decrypted)
        candidates.append(
            Candidate(
                decoded=decrypted.encode(),
                method="caesar",
                confidence=score,
                layers=["caesar"],
                key=str(shift),
            )
        )
    candidates.sort(key=lambda x: x.confidence, reverse=True)
    return candidates


def auto_detect(text: str) -> Candidate:
    """Return the best brute_force result."""
    return brute_force(text)[0]
