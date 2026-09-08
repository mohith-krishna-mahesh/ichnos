"""Pseudo-Random Number Generator (PRNG) Cryptanalysis: LCG, MT19937."""

from __future__ import annotations

from ichnos.crypto.prng.lcg import compose_lcg, crack_time_seeded_lcg
from ichnos.crypto.prng.mersenne import clone_mt19937_generator, untemper

__all__ = [
    "compose_lcg",
    "crack_time_seeded_lcg",
    "untemper",
    "clone_mt19937_generator",
]
