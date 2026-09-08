"""Franklin-Reiter Related Message Attack on RSA.

When two messages are related by an affine relation m2 = (a*m1 + b) mod N
and encrypted under the same RSA public key (N, e), polynomial GCD
recovers the message in O(e^2) modular operations.
"""

from __future__ import annotations

import math


def _poly_mod(poly: list[int], n: int) -> list[int]:
    """Reduces polynomial coefficients modulo n and strips leading zeros."""
    res = [c % n for c in poly]
    while len(res) > 1 and res[-1] == 0:
        res.pop()
    return res


def _poly_divmod(p1: list[int], p2: list[int], n: int) -> tuple[list[int], list[int]]:
    """Polynomial division p1 / p2 in Z_n[x]. Returns (quotient, remainder)."""
    p1 = _poly_mod(p1, n)
    p2 = _poly_mod(p2, n)
    d1 = len(p1) - 1
    d2 = len(p2) - 1

    if d1 < d2:
        return [0], p1

    rem = list(p1)
    quot = [0] * (d1 - d2 + 1)
    lead2 = p2[-1]
    inv_lead2 = pow(lead2, -1, n)

    for i in range(d1 - d2, -1, -1):
        if len(rem) - 1 < i + d2:
            continue
        coeff = (rem[i + d2] * inv_lead2) % n
        quot[i] = coeff
        for j in range(d2 + 1):
            rem[i + j] = (rem[i + j] - coeff * p2[j]) % n
        while len(rem) > 1 and rem[-1] == 0:
            rem.pop()

    return _poly_mod(quot, n), _poly_mod(rem, n)


def _poly_gcd(p1: list[int], p2: list[int], n: int) -> list[int]:
    """Euclidean algorithm for monic polynomial GCD in Z_n[x]."""
    a = _poly_mod(p1, n)
    b = _poly_mod(p2, n)

    while len(b) > 1 or (len(b) == 1 and b[0] != 0):
        _, rem = _poly_divmod(a, b, n)
        a, b = b, rem

    # Make monic
    if a and a[-1] != 0:
        lead_inv = pow(a[-1], -1, n)
        a = [(c * lead_inv) % n for c in a]
    return a


def franklin_reiter_poly_attack(
    n: int,
    e: int,
    c1: int,
    c2: int,
    a: int = 1,
    b: int = 0,
) -> int | None:
    """Recovers m1 from c1 = m1^e (mod n) and c2 = (a*m1 + b)^e (mod n).

    Args:
        n: RSA modulus.
        e: Public exponent.
        c1: Ciphertext of m1.
        c2: Ciphertext of m2 = (a*m1 + b) mod n.
        a: Multiplier in affine relation.
        b: Offset in affine relation.

    Returns:
        The recovered message m1 as an integer, or None if attack fails.
    """
    if b == 0 and a == 1:
        return None

    # f1(x) = x^e - c1 (mod n)
    f1 = [-c1 % n] + [0] * (e - 1) + [1]

    # f2(x) = (a*x + b)^e - c2 (mod n)
    f2 = [0] * (e + 1)
    for k in range(e + 1):
        binom = math.comb(e, k)
        f2[k] = (binom * pow(a, k, n) * pow(b, e - k, n)) % n
    f2[0] = (f2[0] - c2) % n

    gcd_poly = _poly_gcd(f1, f2, n)

    # If gcd is linear: x - m1 => root is -gcd_poly[0] mod n
    if len(gcd_poly) == 2 and gcd_poly[1] == 1:
        m1 = (-gcd_poly[0]) % n
        if pow(m1, e, n) == c1 % n:
            return m1

    return None
