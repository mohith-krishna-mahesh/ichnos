"""Hashcat/John-style rule-based password mutator."""

from __future__ import annotations

import itertools

LEET_MAP: dict[str, list[str]] = {
    "a": ["@", "4"],
    "b": ["8"],
    "e": ["3"],
    "i": ["1", "!"],
    "l": ["1"],
    "o": ["0"],
    "s": ["$", "5"],
    "t": ["7"],
}

COMMON_SUFFIXES = ["1", "123", "!", "?", "2024", "2025", "01", "@", "#", "123!"]
COMMON_PREFIXES = ["!", "@", "#", "1", "123"]


def apply_leetspeak(word: str) -> set[str]:
    """Generates leetspeak combinations of the given word."""
    variations: set[str] = {word}
    chars = []
    for c in word:
        lower_c = c.lower()
        subs = [c]
        if lower_c in LEET_MAP:
            subs.extend(LEET_MAP[lower_c])
        chars.append(subs)

    # Limit combinations to prevent explosion on very long words
    if len(chars) <= 8:
        for combo in itertools.product(*chars):
            variations.add("".join(combo))
    else:
        # For longer words, apply deterministic substitutions
        w1 = "".join(LEET_MAP.get(c.lower(), [c])[0] for c in word)
        variations.add(w1)
        w2 = "".join(LEET_MAP.get(c.lower(), [c])[-1] for c in word)
        variations.add(w2)

    return variations


def mutate_word(
    word: str,
    include_leet: bool = True,
    include_casing: bool = True,
    include_affixes: bool = True,
) -> list[str]:
    """Generates mutations for a single word according to cracking rules."""
    results: set[str] = {word}

    # 1. Casing mutations
    if include_casing:
        cased = {
            word.lower(),
            word.upper(),
            word.capitalize(),
            word.swapcase(),
            word.title(),
        }
        results.update(cased)

    # 2. Leetspeak mutations
    if include_leet:
        leet_set: set[str] = set()
        for w in list(results):
            leet_set.update(apply_leetspeak(w))
        results.update(leet_set)

    # 3. Affix mutations (prefixes and suffixes)
    if include_affixes:
        affixed: set[str] = set()
        for w in list(results):
            for s in COMMON_SUFFIXES:
                affixed.add(w + s)
            for p in COMMON_PREFIXES:
                affixed.add(p + w)
        results.update(affixed)

    # 4. Reversal and duplication
    results.add(word[::-1])
    results.add(word + word)

    return sorted(results)
