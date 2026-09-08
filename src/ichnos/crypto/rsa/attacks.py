"""RSA Attacks: Wiener, Common Modulus, Hastad Broadcast, Franklin-Reiter, Auto."""

from __future__ import annotations

import math
from typing import Any

from ichnos.crypto.numtheory import (
    continued_fraction,
    convergents,
    crt,
    extended_gcd,
    mod_inverse,
)
from ichnos.crypto.rsa.factor import factor


def integer_nth_root(val: int, n: int) -> int | None:
    """Computes exact integer n-th root of val, or None if not an exact power."""
    if val < 0:
        return None
    if val == 0:
        return 0
    if n == 1:
        return val
    if n == 2:
        r = math.isqrt(val)
        return r if r * r == val else None

    # Binary search for exact root
    low = 1
    high = 1 << ((val.bit_length() + n - 1) // n + 1)
    while low <= high:
        mid = (low + high) // 2
        p = pow(mid, n)
        if p == val:
            return mid
        elif p < val:
            low = mid + 1
        else:
            high = mid - 1
    return None


def wiener_attack(n: int, e: int) -> int | None:
    """Wiener's continued fractions attack for small private exponent d < 1/3 * n^(1/4).

    Returns private exponent d if found, None otherwise.
    """
    cf = continued_fraction(e, n)
    convs = convergents(cf)

    for k, d in convs:
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue

        phi = (e * d - 1) // k
        s = n - phi + 1
        # Solve x^2 - s*x + n = 0
        delta = s * s - 4 * n
        if delta < 0:
            continue

        t = math.isqrt(delta)
        if t * t != delta:
            continue

        p = (s + t) // 2
        q = (s - t) // 2
        if p * q == n and p > 1 and q > 1:
            return d

    return None


def common_modulus_attack(n: int, e1: int, e2: int, c1: int, c2: int) -> int:
    """Common modulus attack when the same plaintext is encrypted under coprime exponents e1, e2.

    Returns the recovered plaintext integer m.
    """
    g, s, t = extended_gcd(e1, e2)
    if g != 1:
        raise ValueError(f"Exponents e1 and e2 are not coprime: gcd={g}")

    if s < 0:
        c1 = mod_inverse(c1, n)
        s = -s
    if t < 0:
        c2 = mod_inverse(c2, n)
        t = -t

    m = (pow(c1, s, n) * pow(c2, t, n)) % n
    return m


def common_factor_attack(
    n1: int,
    n2: int,
    c: int | None = None,
    e: int = 65537,
) -> dict[str, Any]:
    """Common factor attack when two RSA moduli share a prime factor gcd(n1, n2) > 1.

    Recovers shared factor q, factors p1 = n1//q and p2 = n2//q, and if ciphertext c
    is provided, computes private key d and decrypts the plaintext message.
    """
    q = math.gcd(n1, n2)
    if q == 1:
        raise ValueError("Moduli n1 and n2 do not share a common factor (gcd=1)")
    if q == n1 or q == n2:
        raise ValueError("One modulus divides the other; not distinct composite moduli")

    p1 = n1 // q
    p2 = n2 // q
    result: dict[str, Any] = {
        "shared_factor": q,
        "p1": p1,
        "p2": p2,
    }

    if c is not None:
        phi1 = (p1 - 1) * (q - 1)
        d = mod_inverse(e, phi1)
        m = pow(c, d, n1)
        result["phi"] = phi1
        result["d"] = d
        result["m"] = m
        byte_len = (m.bit_length() + 7) // 8
        m_bytes = m.to_bytes(byte_len, "big")
        try:
            result["plaintext"] = m_bytes.decode("utf-8")
        except UnicodeDecodeError:
            result["plaintext"] = m_bytes.decode("latin-1", errors="replace")

    return result


def hastad_broadcast_attack(ciphertexts: list[int], moduli: list[int], e: int) -> int:
    """Hastad's broadcast attack for small public exponent e.

    Given e ciphertexts encrypted under different coprime moduli n_i with exponent e,
    uses CRT to solve m^e mod prod(n_i), then computes exact integer e-th root.
    """
    if len(ciphertexts) < e or len(moduli) < e:
        raise ValueError(f"Hastad attack requires at least {e} ciphertexts and moduli")

    c_sub = ciphertexts[:e]
    n_sub = moduli[:e]

    combined = crt(c_sub, n_sub)
    root = integer_nth_root(combined, e)
    if root is None:
        raise ValueError("Could not extract exact e-th root from CRT result")
    return root


def poly_sub_mod(p1: list[int], p2: list[int], n: int) -> list[int]:
    """Subtracts polynomial p2 from p1 modulo n."""
    deg = max(len(p1), len(p2))
    res = [0] * deg
    for i in range(deg):
        c1 = p1[i] if i < len(p1) else 0
        c2 = p2[i] if i < len(p2) else 0
        res[i] = (c1 - c2) % n
    while len(res) > 1 and res[-1] == 0:
        res.pop()
    return res


def franklin_reiter_attack(n: int, e: int, c1: int, c2: int, a: int, b: int) -> int:
    """Franklin-Reiter related-message attack for m2 = (a*m1 + b) mod n and e=3."""
    if e != 3:
        raise NotImplementedError("Franklin-Reiter attack currently implemented for e=3")

    # For e=3:
    # f1(x) = x^3 - c1
    # f2(x) = (a*x + b)^3 - c2 = a^3*x^3 + 3*a^2*b*x^2 + 3*a*b^2*x + (b^3 - c2)
    # Eliminate x^3:
    # a^3 * f1(x) = a^3 * x^3 - a^3 * c1
    # diff(x) = f2(x) - a^3 * f1(x)
    # = 3*a^2*b*x^2 + 3*a*b^2*x + (b^3 - c2 + a^3 * c1)
    # Using the standard resultant / gcd formula for e=3:
    # m = b * (c2 + 2*a^3*c1 - b^3) / (a * (c2 - a^3*c1 + 2*b^3)) mod n
    a3 = pow(a, 3, n)
    b3 = pow(b, 3, n)
    num = (b * (c2 + 2 * a3 * c1 - b3)) % n
    den = (a * (c2 - a3 * c1 + 2 * b3)) % n
    inv_den = mod_inverse(den, n)
    return (num * inv_den) % n


def auto_attack(n: int, e: int, c: int) -> int | None:
    """Automated RSA attack dispatcher.

    Tries:
    1. Direct small-e root (m^e < n)
    2. Wiener's attack (small d)
    3. Factorization (trial, Fermat, p-1, rho)
    """
    # 1. Direct root
    root = integer_nth_root(c, e)
    if root is not None:
        return root

    # 2. Wiener
    d = wiener_attack(n, e)
    if d is not None:
        return pow(c, d, n)

    # 3. Factorization
    factors = factor(n)
    if factors:
        p, q = factors
        phi = (p - 1) * (q - 1)
        try:
            d = mod_inverse(e, phi)
            return pow(c, d, n)
        except ValueError:
            pass

    return None
