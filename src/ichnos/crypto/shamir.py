"""Shamir's Secret Sharing Scheme.

Splits a secret into *n* shares such that any *k* (threshold) shares can
reconstruct the secret, but fewer than *k* shares reveal no information.

Operates over a prime field F_p to guarantee information-theoretic security.
"""

from __future__ import annotations

import random

from ichnos.crypto.numtheory import mod_inverse


def lagrange_interpolate(shares: list[tuple[int, int]], prime: int) -> int:
    """Recover f(0) from *k* shares via Lagrange interpolation over F_p.

    Parameters
    ----------
    shares : list[tuple[int, int]]
        A list of ``(x_i, y_i)`` evaluation points of the secret polynomial.
        All *x_i* must be distinct and non-zero.
    prime : int
        The prime modulus defining the finite field.

    Returns
    -------
    int
        The reconstructed secret ``f(0) mod prime``.
    """
    secret = 0
    k = len(shares)

    for i in range(k):
        x_i, y_i = shares[i]
        numerator = 1
        denominator = 1

        for j in range(k):
            if i == j:
                continue
            x_j = shares[j][0]
            numerator = (numerator * (-x_j)) % prime
            denominator = (denominator * (x_i - x_j)) % prime

        lagrange_coeff = (numerator * mod_inverse(denominator, prime)) % prime
        secret = (secret + y_i * lagrange_coeff) % prime

    return secret


def split_secret(
    secret: int,
    k: int,
    n: int,
    prime: int,
) -> list[tuple[int, int]]:
    """Split *secret* into *n* shares with a *k*-of-*n* threshold.

    Constructs a random polynomial of degree ``k - 1`` with
    ``f(0) = secret`` and evaluates it at ``x = 1, 2, …, n``.

    Parameters
    ----------
    secret : int
        The secret to share.  Must satisfy ``0 <= secret < prime``.
    k : int
        The reconstruction threshold (minimum shares needed).
    n : int
        The total number of shares to generate.  Must satisfy ``n >= k``.
    prime : int
        A prime larger than *secret* and larger than *n*.

    Returns
    -------
    list[tuple[int, int]]
        A list of *n* shares ``(x_i, y_i)`` with ``x_i`` in ``{1, …, n}``.

    Raises
    ------
    ValueError
        If ``k < 2``, ``n < k``, or ``secret >= prime``.
    """
    if k < 2:
        raise ValueError("Threshold k must be at least 2")
    if n < k:
        raise ValueError("Number of shares n must be >= threshold k")
    if secret >= prime or secret < 0:
        raise ValueError("Secret must satisfy 0 <= secret < prime")

    # Random polynomial coefficients a_1 … a_{k-1}; a_0 = secret
    coefficients = [secret] + [random.randrange(1, prime) for _ in range(k - 1)]

    shares: list[tuple[int, int]] = []
    for x in range(1, n + 1):
        # Evaluate polynomial using Horner's method
        y = 0
        for coeff in reversed(coefficients):
            y = (y * x + coeff) % prime
        shares.append((x, y))

    return shares


def recover_secret(shares: list[tuple[int, int]], prime: int) -> int:
    """Recover the secret from a sufficient set of shares.

    Convenience wrapper around :func:`lagrange_interpolate`.

    Parameters
    ----------
    shares : list[tuple[int, int]]
        At least *k* shares ``(x_i, y_i)`` produced by :func:`split_secret`.
    prime : int
        The same prime used when the shares were generated.

    Returns
    -------
    int
        The reconstructed secret.
    """
    return lagrange_interpolate(shares, prime)
