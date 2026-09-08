from __future__ import annotations

import random

from ichnos.core.models import Candidate

_QUADGRAMS: dict[str, float] | None = None
_FLOOR: float | None = None


def _get_quadgrams() -> tuple[dict[str, float], float]:
    global _QUADGRAMS, _FLOOR
    if _QUADGRAMS is None:
        from ichnos.crypto.classical.quadgrams import FLOOR, QUADGRAMS

        _QUADGRAMS = QUADGRAMS
        _FLOOR = FLOOR
    return _QUADGRAMS, _FLOOR


def score_text(text: str) -> float:
    """Score text using quadgram probabilities."""
    letters = [c.upper() for c in text if c.isalpha()]
    if len(letters) < 4:
        return 0.0

    quadgrams, floor = _get_quadgrams()
    score = 0.0
    for i in range(len(letters) - 3):
        q = "".join(letters[i : i + 4])
        score += quadgrams.get(q, floor)
    return score


def decrypt_with_key(text: str, key: str) -> str:
    """Apply substitution key. Key is 26 letters mapping A-Z to ciphertext."""
    if len(key) != 26:
        raise ValueError("Key must be 26 letters.")

    # In hill climbing, the "key" often maps ciphertext to plaintext
    # Let's assume `key` maps A-Z (ciphertext) to Plaintext
    key = key.upper()
    mapping = {chr(i + ord("A")): key[i] for i in range(26)}

    result = []
    for c in text:
        if c.isalpha():
            is_upper = c.isupper()
            pt = mapping[c.upper()]
            result.append(pt.upper() if is_upper else pt.lower())
        else:
            result.append(c)
    return "".join(result)


def solve(ciphertext: str, iterations: int = 5000, restarts: int = 5) -> Candidate:
    """Hill-climbing solver for substitution cipher."""
    best_key = ""
    best_score = -float("inf")

    alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    letters_in_ct = set(c.upper() for c in ciphertext if c.isalpha())
    if not letters_in_ct:
        return Candidate(
            decoded=ciphertext.encode(), method="substitution", confidence=0.0, layers=[], key=""
        )

    for _ in range(restarts):
        current_key = list(alphabet)
        random.shuffle(current_key)
        current_score = score_text(decrypt_with_key(ciphertext, "".join(current_key)))

        improved = True
        while improved:
            improved = False
            for _ in range(iterations):
                a, b = random.sample(range(26), 2)
                current_key[a], current_key[b] = current_key[b], current_key[a]

                new_score = score_text(decrypt_with_key(ciphertext, "".join(current_key)))
                if new_score > current_score:
                    current_score = new_score
                    improved = True
                else:
                    current_key[a], current_key[b] = current_key[b], current_key[a]

        if current_score > best_score:
            best_score = current_score
            best_key = "".join(current_key)

    decrypted = decrypt_with_key(ciphertext, best_key)
    _, floor = _get_quadgrams()
    return Candidate(
        decoded=decrypted.encode(),
        method="substitution",
        confidence=min(
            1.0,
            max(0.0, (best_score - floor * len(ciphertext)) / (abs(floor) * len(ciphertext) + 1)),
        ),
        layers=["substitution"],
        key=best_key,
    )


def __getattr__(name: str):
    if name in ("QUADGRAMS", "FLOOR"):
        quadgrams, floor = _get_quadgrams()
        if name == "QUADGRAMS":
            return quadgrams
        return floor
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
