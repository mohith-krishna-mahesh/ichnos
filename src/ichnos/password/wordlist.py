"""Wordlist generation, filtering, and combination utilities."""

from __future__ import annotations

import itertools
import re


def deduplicate(words: list[str]) -> list[str]:
    """Deduplicates a list of words preserving original order."""
    seen: set[str] = set()
    out: list[str] = []
    for w in words:
        if w not in seen:
            seen.add(w)
            out.append(w)
    return out


def combine_lists(lists: list[list[str]], delimiter: str = "") -> list[str]:
    """Generates the Cartesian product of multiple wordlists joined by delimiter."""
    if not lists:
        return []
    combos = itertools.product(*lists)
    return [delimiter.join(c) for c in combos]


def filter_wordlist(
    words: list[str],
    min_length: int = 0,
    max_length: int = 128,
    must_contain_digit: bool = False,
    must_contain_special: bool = False,
) -> list[str]:
    """Filters wordlist based on policy criteria (length, digits, special characters)."""
    filtered: list[str] = []
    for w in words:
        if not (min_length <= len(w) <= max_length):
            continue
        if must_contain_digit and not any(c.isdigit() for c in w):
            continue
        if must_contain_special and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", w):
            continue
        filtered.append(w)
    return filtered
