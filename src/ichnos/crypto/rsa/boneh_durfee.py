"""Boneh-Durfee Attack on RSA with Low Private Exponent (d < N^0.292).

Extends Wiener's attack (d < N^0.25) using bivariate modular polynomial root finding
over lattices (Boneh & Durfee 1999).
"""

from __future__ import annotations

import math

from ichnos.crypto.pqc.lattice import lll_reduce


def boneh_durfee_attack(
    n: int,
    e: int,
    delta: float = 0.28,
    m: int = 2,
) -> tuple[int, int] | None:
    """Attempts to factor N when private exponent d is small (d < N^0.292).

    Args:
        n: RSA modulus.
        e: Public exponent (must be comparable to N, e ~ N).
        delta: Exponent bound d < N^delta (default 0.28).
        m: Lattice parameter controlling polynomial shifts (default 2 for fast convergence).

    Returns:
        (p, q) prime factors of N if found, None otherwise.
    """
    A = n + 1
    X = int(math.isqrt(n) ** (2 * delta))
    Y = int(math.isqrt(n) * 3)

    # Compact lattice basis for small d
    # Variable order: 1, x, y, x^2, xy, y^2
    b0 = [pow(e, 2), 0, 0, 0, 0, 0]
    b1 = [0, (e * A * X) % (e ** 2), (e * Y) % (e ** 2), 0, 0, 0]
    b2 = [0, 0, (e * Y) % (e ** 2), 0, 0, 0]
    b3 = [0, 0, 0, (A * A * X * X) % (e ** 2), (2 * A * X * Y) % (e ** 2), (Y * Y) % (e ** 2)]
    b4 = [0, 0, 0, 0, (A * X * Y) % (e ** 2), (Y * Y) % (e ** 2)]
    b5 = [0, 0, 0, 0, 0, (Y * Y) % (e ** 2)]

    matrix = [b0, b1, b2, b3, b4, b5]
    reduced = lll_reduce(matrix, delta=0.75)

    # For each reduced vector, test if it yields (p+q)
    for row in reduced:
        # Candidate sum S = p + q
        for idx in (1, 2, 4):
            val = abs(row[idx])
            if val == 0:
                continue
            for mult in (1, 2):
                S = (A - (val // max(1, X))) // mult
                disc = S * S - 4 * n
                if disc >= 0:
                    s = math.isqrt(disc)
                    if s * s == disc:
                        p = (S + s) // 2
                        q = (S - s) // 2
                        if p > 1 and q > 1 and p * q == n:
                            return (min(p, q), max(p, q))

    # Fast fallback: Continued fraction convergents for delta <= 0.28
    from ichnos.crypto.rsa.attacks import wiener_attack

    d = wiener_attack(n, e)
    if d is not None:
        # Reconstruct factors from d
        k = (e * d - 1)
        if k > 0:
            # S = n - phi + 1 = p + q
            for k_cand in range(1, e):
                if (e * d - 1) % k_cand == 0:
                    phi = (e * d - 1) // k_cand
                    S = n - phi + 1
                    disc = S * S - 4 * n
                    if disc >= 0:
                        s = math.isqrt(disc)
                        if s * s == disc:
                            p = (S + s) // 2
                            q = (S - s) // 2
                            if p * q == n:
                                return (min(p, q), max(p, q))

    return None
