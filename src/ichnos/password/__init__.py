"""Password cracking and wordlist manipulation module for Ichnos."""

from __future__ import annotations

from ichnos.password import crack, mutator, wordlist
from ichnos.password.crack import compute_hash, crack_hash, crack_hashes
from ichnos.password.mutator import apply_leetspeak, mutate_word
from ichnos.password.wordlist import combine_lists, deduplicate, filter_wordlist

__all__ = [
    "apply_leetspeak",
    "combine_lists",
    "compute_hash",
    "crack",
    "crack_hash",
    "crack_hashes",
    "deduplicate",
    "filter_wordlist",
    "mutate_word",
    "mutator",
    "wordlist",
]
