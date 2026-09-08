"""RSA factorization algorithms: Trial Division, Fermat, Pollard p-1, Pollard rho."""

from __future__ import annotations

import math

from ichnos.crypto.numtheory import gcd, is_prime


def trial_division(n: int, limit: int = 1_000_000) -> tuple[int, int] | None:
    """Check for small prime factors up to limit."""
    if n % 2 == 0:
        return 2, n // 2
    if n % 3 == 0:
        return 3, n // 3

    d = 5
    diff = 2
    while d * d <= n and d <= limit:
        if n % d == 0:
            return d, n // d
        d += diff
        diff = 6 - diff
    return None


def fermat_factor(n: int, max_steps: int = 1_000_000) -> tuple[int, int] | None:
    """Fermat's factorization for close primes (|p - q| is small)."""
    if n <= 0 or n % 2 == 0:
        return (2, n // 2) if n % 2 == 0 else None

    a = math.isqrt(n)
    if a * a < n:
        a += 1

    b2 = a * a - n
    step = 0
    while step < max_steps:
        b = math.isqrt(b2)
        if b * b == b2:
            p = a - b
            q = a + b
            if 1 < p < n and p * q == n:
                return min(p, q), max(p, q)
        a += 1
        b2 = a * a - n
        step += 1

    return None


def pollard_p_minus_1(n: int, b_limit: int = 100_000) -> int | None:
    """Pollard's p-1 algorithm for factoring when p-1 has only small prime factors."""
    a = 2
    for j in range(2, b_limit):
        a = pow(a, j, n)
        if j % 100 == 0 or j == b_limit - 1:
            g = gcd(a - 1, n)
            if 1 < g < n:
                return g
            if g == n:
                return None
    return None


def pollard_rho(n: int, max_steps: int = 100_000) -> int | None:
    """Pollard's rho algorithm using Floyd's cycle-finding."""
    if n % 2 == 0:
        return 2
    if is_prime(n):
        return None

    for c in [1, 3, 5]:
        x = 2
        y = 2
        d = 1

        def f(val: int) -> int:
            return (pow(val, 2, n) + c) % n

        steps = 0

        while d == 1 and steps < max_steps:
            x = f(x)
            y = f(f(y))
            d = gcd(abs(x - y), n)
            steps += 1

        if 1 < d < n:
            return d
    return None


_PRIMES_CACHE_24: list[int] | None = None
_CHUNK_PRODUCTS_24: list[tuple[int, list[int]]] | None = None


def get_primes_up_to(limit: int = 1 << 24) -> list[int]:
    """Returns all prime numbers up to limit using an optimized bytearray sieve."""
    global _PRIMES_CACHE_24
    if limit == (1 << 24) and _PRIMES_CACHE_24 is not None:
        return _PRIMES_CACHE_24

    sieve = bytearray(b"\x01") * limit
    sieve[0] = sieve[1] = 0
    for i in range(2, int(math.isqrt(limit)) + 1):
        if sieve[i]:
            sieve[i * i : limit : i] = b"\x00" * len(range(i * i, limit, i))

    primes = [i for i in range(2, limit) if sieve[i]]
    if limit == (1 << 24):
        _PRIMES_CACHE_24 = primes
    return primes


def _get_chunk_products_24() -> list[tuple[int, list[int]]]:
    """Precomputes and caches prime chunk products for fast batch GCD."""
    global _CHUNK_PRODUCTS_24
    if _CHUNK_PRODUCTS_24 is not None:
        return _CHUNK_PRODUCTS_24

    primes = get_primes_up_to(1 << 24)
    chunk_size = 200
    products: list[tuple[int, list[int]]] = []
    for i in range(0, len(primes), chunk_size):
        chunk = primes[i : i + chunk_size]
        prod = 1
        for p in chunk:
            prod *= p
        products.append((prod, chunk))
    _CHUNK_PRODUCTS_24 = products
    return _CHUNK_PRODUCTS_24


def find_small_prime_factors(n: int, max_prime_bits: int = 24) -> dict[int, int]:
    """Finds all prime factors of n up to 2^max_prime_bits using batch GCD.

    Returns a dict mapping prime -> multiplicity.
    """
    factors: dict[int, int] = {}
    rem = n

    if max_prime_bits == 24:
        chunk_items = _get_chunk_products_24()
    else:
        limit = 1 << max_prime_bits
        primes = get_primes_up_to(limit)
        chunk_size = 200
        chunk_items = []
        for i in range(0, len(primes), chunk_size):
            chunk = primes[i : i + chunk_size]
            prod = 1
            for p in chunk:
                prod *= p
            chunk_items.append((prod, chunk))

    for prod, chunk in chunk_items:
        g = math.gcd(prod, rem)
        if g > 1:
            for p in chunk:
                if rem % p == 0:
                    cnt = 0
                    while rem % p == 0:
                        cnt += 1
                        rem //= p
                    factors[p] = cnt
            if rem == 1:
                break
    return factors


def factor(n: int) -> tuple[int, int] | None:
    """Multi-method factorization attempt: small prime batch GCD -> Fermat -> p-1 -> rho."""
    # 1. Batch GCD for primes up to 2^24
    small_factors = find_small_prime_factors(n, max_prime_bits=24)
    if small_factors:
        p = next(iter(small_factors.keys()))
        return min(p, n // p), max(p, n // p)

    # 2. Fermat (fast for close primes)
    res = fermat_factor(n, max_steps=100_000)
    if res:
        return res

    # 3. Pollard p - 1
    p = pollard_p_minus_1(n, b_limit=50_000)
    if p:
        return min(p, n // p), max(p, n // p)

    # 4. Pollard rho
    p = pollard_rho(n, max_steps=100_000)
    if p:
        return min(p, n // p), max(p, n // p)

    return None
