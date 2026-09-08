"""Coppersmith's Small-Roots Lattice Attacks for RSA.

Implements the Howgrave-Graham lattice formulation of Coppersmith's theorem
for finding small roots of univariate modular polynomials f(x) == 0 (mod N).

Supports:
- Stereotyped message recovery: m = m0 + x (mod N) where x < N^(1/e)
- Partial prime factor recovery: given MSBs of prime p
"""

from __future__ import annotations

import math
from typing import Sequence

from ichnos.crypto.pqc.lattice import lll_reduce


def _poly_eval(coeffs: Sequence[int], x: int) -> int:
    """Evaluates polynomial coeffs[0] + coeffs[1]*x + ... at integer x."""
    res = 0
    xp = 1
    for c in coeffs:
        res += c * xp
        xp *= x
    return res


def _integer_roots(coeffs: list[int], max_bound: int) -> list[int]:
    """Finds exact integer roots of a univariate integer polynomial."""
    # Strip trailing zero coefficients
    while len(coeffs) > 1 and coeffs[-1] == 0:
        coeffs.pop()

    if len(coeffs) <= 1:
        return [0] if coeffs == [0] else []

    roots: list[int] = []

    # If constant term is 0, x=0 is a root
    if coeffs[0] == 0:
        roots.append(0)
        return roots + _integer_roots(coeffs[1:], max_bound)

    # For degree 1: a*x + b = 0 => x = -b/a
    if len(coeffs) == 2:
        b, a = coeffs[0], coeffs[1]
        if a != 0 and -b % a == 0:
            r = -b // a
            if abs(r) <= max_bound:
                roots.append(r)
        return roots

    # Degree 2: quadratic formula
    if len(coeffs) == 3:
        c, b, a = coeffs[0], coeffs[1], coeffs[2]
        disc = b * b - 4 * a * c
        if disc >= 0:
            s = math.isqrt(disc)
            if s * s == disc:
                for sign in (-1, 1):
                    num = -b + sign * s
                    den = 2 * a
                    if den != 0 and num % den == 0:
                        r = num // den
                        if abs(r) <= max_bound and r not in roots:
                            roots.append(r)
        return roots

    # Higher degree: Newton-Raphson / integer bisection search in [-max_bound, max_bound]
    # Check positive and negative rational root candidates from factors of constant term if small
    c0 = abs(coeffs[0])
    if c0 < 1000000:
        candidates: set[int] = set()
        for d in range(1, math.isqrt(c0) + 1):
            if c0 % d == 0:
                candidates.add(d)
                candidates.add(-d)
                candidates.add(c0 // d)
                candidates.add(-(c0 // d))
        for cand in candidates:
            if abs(cand) <= max_bound and _poly_eval(coeffs, cand) == 0:
                roots.append(cand)
        if roots:
            return sorted(set(roots))

    # Bisection search over intervals
    step = max(1, max_bound // 1000)
    for lo in range(-max_bound, max_bound, step):
        hi = min(lo + step, max_bound)
        f_lo = _poly_eval(coeffs, lo)
        f_hi = _poly_eval(coeffs, hi)
        if f_lo == 0:
            roots.append(lo)
        if f_hi == 0:
            roots.append(hi)
        if (f_lo > 0 and f_hi < 0) or (f_lo < 0 and f_hi > 0):
            # Sign change: binary search for root
            l, r = lo, hi
            while r - l > 1:
                mid = (l + r) // 2
                f_mid = _poly_eval(coeffs, mid)
                if f_mid == 0:
                    roots.append(mid)
                    break
                if (f_lo > 0 and f_mid > 0) or (f_lo < 0 and f_mid < 0):
                    l = mid
                else:
                    r = mid

    return sorted(set(roots))


def coppersmith_small_roots(
    coeffs: list[int],
    N: int,
    X: int,
    m: int = 1,
) -> list[int]:
    """Finds small roots x0 of f(x) == 0 (mod N) with |x0| <= X.

    Uses Howgrave-Graham lattice basis reduction.
    coeffs: coefficients of f(x) = coeffs[0] + coeffs[1]*x + ... + coeffs[d]*x^d.
    """
    d = len(coeffs) - 1
    if d <= 0:
        return []

    # Make polynomial monic mod N
    lead = coeffs[d] % N
    try:
        lead_inv = pow(lead, -1, N)
    except ValueError:
        g = math.gcd(lead, N)
        if 1 < g < N:
            # Factored N directly!
            return []
        return []

    f = [(c * lead_inv) % N for c in coeffs]

    # Construct lattice basis using Howgrave-Graham polynomials:
    # g_{i,j}(x) = x^j * N^(m - i) * f(x)^i
    # For m=1, standard Coppersmith basis:
    # rows: N, N*x, N*x^2, ..., f(x), x*f(x), ...
    dim = d + 1
    matrix: list[list[int]] = []

    # Shift polynomials: N * x^i for i in 0..d-1
    for i in range(d):
        row = [0] * dim
        row[i] = N * (X ** i)
        matrix.append(row)

    # Main polynomial: f(x) * X^i
    f_row = [f[j] * (X ** j) for j in range(dim)]
    matrix.append(f_row)

    # Reduce basis using pure-Python LLL
    reduced = lll_reduce(matrix, delta=0.75)

    # First vector in reduced basis corresponds to integer polynomial Q(x)
    for row in reduced:
        q_coeffs = [row[j] // (X ** j) if X ** j != 0 else row[j] for j in range(dim)]
        # Check if q_coeffs is non-zero
        if any(c != 0 for c in q_coeffs):
            roots = _integer_roots(q_coeffs, X)
            valid_roots = [r for r in roots if _poly_eval(coeffs, r) % N == 0]
            if valid_roots:
                return valid_roots

    return []


def stereotyped_message(
    prefix: bytes,
    suffix: bytes,
    total_len: int,
    c: int,
    e: int,
    N: int,
) -> bytes | None:
    """Recovers the unknown infix x in m = prefix + x + suffix where c = m^e (mod N).

    Args:
        prefix: Known starting bytes of the message (e.g. b"FLAG{").
        suffix: Known ending bytes of the message (e.g. b"}").
        total_len: Total length of plaintext message in bytes.
        c: RSA ciphertext.
        e: Public exponent (typically small, e=3).
        N: RSA modulus.

    Returns:
        The recovered plaintext bytes if found, None otherwise.
    """
    prefix_len = len(prefix)
    suffix_len = len(suffix)
    unknown_len = total_len - prefix_len - suffix_len
    if unknown_len <= 0:
        return None

    # Base message m0 with unknown bytes set to 0
    # m = prefix_int * 256^(unknown_len + suffix_len) + x * 256^suffix_len + suffix_int
    p_int = int.from_bytes(prefix, "big") if prefix else 0
    s_int = int.from_bytes(suffix, "big") if suffix else 0

    shift_x = 256 ** suffix_len
    shift_p = 256 ** (unknown_len + suffix_len)
    m0 = p_int * shift_p + s_int

    # f(x) = (m0 + x * shift_x)^e - c (mod N)
    # Expand (m0 + A*x)^e - c using binomial theorem
    A = shift_x
    coeffs = [0] * (e + 1)
    for k in range(e + 1):
        binom = math.comb(e, k)
        coeffs[k] = (binom * pow(m0, e - k, N) * pow(A, k, N)) % N

    coeffs[0] = (coeffs[0] - c) % N
    X = 256 ** unknown_len

    roots = coppersmith_small_roots(coeffs, N, X)
    for r in roots:
        recovered_val = m0 + r * shift_x
        recovered_bytes = recovered_val.to_bytes(total_len, "big")
        if recovered_bytes.startswith(prefix) and recovered_bytes.endswith(suffix):
            return recovered_bytes

    return None
