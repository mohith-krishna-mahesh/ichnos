from __future__ import annotations

from ichnos.core.detection import english_score
from ichnos.core.models import Candidate
from ichnos.crypto.xor.single_byte import brute_force as single_byte_brute


def xor_repeating(data: bytes, key: bytes) -> bytes:
    """XOR data with a repeating key."""
    if not key:
        return data
    key_len = len(key)
    return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))


def hamming_distance(a: bytes, b: bytes) -> int:
    """Compute bitwise Hamming distance between two byte sequences."""
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def detect_key_length(data: bytes, max_len: int = 40) -> list[int]:
    """Estimate repeating key length using normalized Hamming distance."""
    distances = []
    for length in range(2, min(max_len + 1, len(data) // 2 + 1)):
        blocks = [data[i : i + length] for i in range(0, len(data), length)]
        if len(blocks) < 2:
            break
        # Average Hamming distance between consecutive blocks
        dist = 0
        pairs = 0
        for i in range(len(blocks) - 1):
            if len(blocks[i]) == length and len(blocks[i + 1]) == length:
                dist += hamming_distance(blocks[i], blocks[i + 1])
                pairs += 1
        if pairs > 0:
            norm_dist = dist / pairs / length
            distances.append((length, norm_dist))

    distances.sort(key=lambda x: x[1])
    return [d[0] for d in distances]


def crack(data: bytes, key_length: int | None = None) -> Candidate:
    """Crack repeating-key XOR."""
    if not data:
        return Candidate(decoded=b"", method="repeating_key_xor", confidence=0.0, layers=[], key="")

    if key_length is not None:
        lengths_to_try = [key_length]
    else:
        detected = detect_key_length(data, max_len=30)[:10]
        # Always include small reasonable key lengths 2..15
        lengths_to_try = list(detected)
        for l in range(2, min(16, len(data) // 2 + 1)):
            if l not in lengths_to_try:
                lengths_to_try.append(l)

    candidates = []
    for klen in lengths_to_try:
        key_bytes = []
        for i in range(klen):
            block = bytes(data[j] for j in range(i, len(data), klen))
            cands = single_byte_brute(block)
            if not cands:
                break
            key_bytes.append(int(cands[0].key, 16))
        if len(key_bytes) != klen:
            continue
        k = bytes(key_bytes)
        dec = xor_repeating(data, k)
        score = english_score(dec.decode("ascii", errors="ignore"))
        candidates.append((score, klen, k, dec))

    if not candidates:
        return Candidate(
            decoded=data, method="repeating_key_xor", confidence=0.0, layers=[], key=""
        )

    max_score = max(c[0] for c in candidates)
    # Among top scorers, prefer shortest key length to avoid harmonic multiples
    top_scorers = [c for c in candidates if c[0] >= max_score * 0.95 and c[0] > 0.3]
    if top_scorers:
        top_scorers.sort(key=lambda c: c[1])
        best = top_scorers[0]
    else:
        candidates.sort(key=lambda c: c[0], reverse=True)
        best = candidates[0]

    return Candidate(
        decoded=best[3],
        method="repeating_key_xor",
        confidence=best[0],
        layers=["repeating_key_xor"],
        key=best[2].hex(),
    )
