from __future__ import annotations

import collections

from ichnos.core.detection import english_score
from ichnos.core.models import Candidate


def encrypt(text: str, key: str) -> str:
    """Encrypt text using Vigenere cipher."""
    if not key:
        return text
    key_upper = [c for c in key.upper() if c.isalpha()]
    if not key_upper:
        return text
    result = []
    k_idx = 0
    for c in text:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            shift = ord(key_upper[k_idx % len(key_upper)]) - ord("A")
            result.append(chr((ord(c) - base + shift) % 26 + base))
            k_idx += 1
        else:
            result.append(c)
    return "".join(result)


def decrypt(text: str, key: str) -> str:
    """Decrypt text using Vigenere cipher."""
    if not key:
        return text
    key_upper = [c for c in key.upper() if c.isalpha()]
    if not key_upper:
        return text
    result = []
    k_idx = 0
    for c in text:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            shift = ord(key_upper[k_idx % len(key_upper)]) - ord("A")
            result.append(chr((ord(c) - base - shift) % 26 + base))
            k_idx += 1
        else:
            result.append(c)
    return "".join(result)


def index_of_coincidence(text: str) -> float:
    """Calculate Index of Coincidence on letters only."""
    letters = [c.upper() for c in text if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    freqs = collections.Counter(letters)
    ioc = sum(f * (f - 1) for f in freqs.values()) / (n * (n - 1))
    return ioc


def kasiski_examination(text: str) -> list[int]:
    """Find repeated trigrams to estimate key length."""
    letters = [c.upper() for c in text if c.isalpha()]
    text_alpha = "".join(letters)
    seqs = collections.defaultdict(list)
    for i in range(len(text_alpha) - 2):
        seqs[text_alpha[i : i + 3]].append(i)

    distances = []
    for seq, pos in seqs.items():
        if len(pos) > 1:
            for i in range(len(pos) - 1):
                distances.append(pos[i + 1] - pos[i])

    factors = collections.Counter()
    for d in distances:
        for i in range(2, d + 1):
            if d % i == 0:
                factors[i] += 1

    return [f[0] for f in factors.most_common(5)]


def detect_key_length(text: str, max_len: int = 20) -> int:
    """Detect key length using IoC and Kasiski examination."""
    letters = [c.upper() for c in text if c.isalpha()]
    if not letters:
        return 1

    kasiski_factors = kasiski_examination(text)

    scored_lengths: list[tuple[float, int]] = []
    for l in range(2, min(max_len + 1, len(letters))):
        iocs = []
        for i in range(l):
            col = "".join(letters[i::l])
            if len(col) > 1:
                iocs.append(index_of_coincidence(col))
        if iocs:
            avg_ioc = sum(iocs) / len(iocs)
            kasiski_bonus = 0.015 if l in kasiski_factors else 0.0
            scored_lengths.append((avg_ioc + kasiski_bonus, l))

    if not scored_lengths:
        return 1

    scored_lengths.sort(key=lambda x: x[0], reverse=True)
    best_score, best_len = scored_lengths[0]
    for score, l in scored_lengths:
        if best_len % l == 0 and score > 0.055 and l < best_len:
            best_len = l
            break

    return best_len


def crack(text: str) -> Candidate:
    """Crack Vigenere cipher by trying candidate key lengths and ranking by English score."""
    letters = [c.upper() for c in text if c.isalpha()]
    if not letters:
        return Candidate(
            decoded=text.encode(), method="vigenere", confidence=0.0, layers=[], key=""
        )

    from ichnos.core.detection import ENGLISH_FREQ

    candidate_lengths = [detect_key_length(text)]
    candidate_lengths.extend(kasiski_examination(text))
    candidate_lengths.extend(range(2, min(15, len(letters))))
    seen = set()
    unique_lengths = sorted(
        [l for l in candidate_lengths if not (l in seen or seen.add(l)) and l >= 2]
    )

    candidates = []
    for key_len in unique_lengths:
        key_chars = []
        for i in range(key_len):
            col = "".join(letters[i::key_len])
            best_shift = 0
            best_score = -1.0
            for shift in range(26):
                dec_col = "".join(chr((ord(c) - ord("A") - shift) % 26 + ord("A")) for c in col)
                score = sum(ENGLISH_FREQ.get(c, 0.0) for c in dec_col)
                if score > best_score:
                    best_score = score
                    best_shift = shift
            key_chars.append(chr(best_shift + ord("A")))

        key = "".join(key_chars)
        decrypted = decrypt(text, key)
        score = english_score(decrypted)
        candidates.append((score, key_len, key, decrypted))

    if not candidates:
        return Candidate(
            decoded=text.encode(), method="vigenere", confidence=0.0, layers=[], key=""
        )

    max_score = max(c[0] for c in candidates)
    top_scorers = [c for c in candidates if c[0] >= max_score * 0.95 and c[0] > 0.4]
    if top_scorers:
        top_scorers.sort(key=lambda c: c[1])
        best = top_scorers[0]
    else:
        candidates.sort(key=lambda c: c[0], reverse=True)
        best = candidates[0]

    return Candidate(
        decoded=best[3].encode(),
        method="vigenere",
        confidence=best[0],
        layers=["vigenere"],
        key=best[2],
    )
