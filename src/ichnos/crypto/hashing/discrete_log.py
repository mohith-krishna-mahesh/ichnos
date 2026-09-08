"""Discrete logarithm algorithms: Baby-Step Giant-Step and Pohlig-Hellman."""

from __future__ import annotations

import math
from collections import Counter

from ichnos.crypto.numtheory import crt, mod_inverse, prime_factorization


def baby_step_giant_step(g: int, h: int, p: int, order: int | None = None) -> int | None:
    """Solves g^x = h (mod p) using Shank's Baby-Step Giant-Step algorithm."""
    n = order or (p - 1)
    m = math.isqrt(n) + 1

    # Baby steps: table of g^j mod p for j = 0..m-1
    table: dict[int, int] = {}
    cur = 1
    for j in range(m):
        table[cur] = j
        cur = (cur * g) % p

    # Giant steps: factor = g^(-m) mod p
    g_m = pow(g, m, p)
    inv_g_m = mod_inverse(g_m, p)

    cur = h
    for i in range(m):
        if cur in table:
            x = i * m + table[cur]
            return x % n
        cur = (cur * inv_g_m) % p

    return None


def pohlig_hellman(g: int, h: int, p: int, order: int | None = None) -> int | None:
    """Solves g^x = h (mod p) when group order is smooth using Pohlig-Hellman algorithm."""
    n = order or (p - 1)
    factors = prime_factorization(n)
    counts = Counter(factors)

    remainders = []
    moduli = []

    for pi, ei in counts.items():
        qi = pow(pi, ei)
        # Solve x mod q_i
        # Determine base-pi digits z_0, z_1, ..., z_{ei-1}
        gamma = pow(g, n // pi, p)
        x_mod_qi = 0

        for k in range(ei):
            # h_k = (h * g^(-x_prev))^(n / pi^(k+1)) mod p
            inv_g_x = mod_inverse(pow(g, x_mod_qi, p), p)
            hk = pow((h * inv_g_x) % p, n // pow(pi, k + 1), p)
            # Solve gamma^d = hk (mod p) in prime subgroup of order pi
            d = baby_step_giant_step(gamma, hk, p, order=pi)
            if d is None:
                return None
            x_mod_qi += d * pow(pi, k)

        remainders.append(x_mod_qi)
        moduli.append(qi)

    return crt(remainders, moduli)
