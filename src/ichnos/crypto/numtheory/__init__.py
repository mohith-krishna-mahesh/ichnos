from __future__ import annotations

import math


def gcd(a: int, b: int) -> int:
    """Euclidean algorithm for Greatest Common Divisor."""
    return math.gcd(a, b)


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean Algorithm. Returns (g, x, y) such that a*x + b*y = g."""
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extended_gcd(b % a, a)
        return g, x - (b // a) * y, y


def lcm(a: int, b: int) -> int:
    """Least Common Multiple."""
    return abs(a * b) // gcd(a, b) if a and b else 0


def mod_inverse(a: int, m: int) -> int:
    """Modular inverse. Raises ValueError if inverse doesn't exist."""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
    else:
        return x % m


def mod_pow(base: int, exp: int, mod: int) -> int:
    """Modular exponentiation."""
    return pow(base, exp, mod)


def crt(remainders: list[int], moduli: list[int]) -> int:
    """Chinese Remainder Theorem."""
    sum_res = 0
    prod = math.prod(moduli)
    for n_i, a_i in zip(moduli, remainders):
        p = prod // n_i
        sum_res += a_i * mod_inverse(p, n_i) * p
    return sum_res % prod


def is_prime(n: int) -> bool:
    """Miller-Rabin primality test."""
    if n == 2 or n == 3:
        return True
    if n < 2 or n % 2 == 0:
        return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # Witnesses for n < 3.3x10^24
    witnesses = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41]

    for a in witnesses:
        if n <= a:
            break
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def prime_factorization(n: int) -> list[int]:
    """Prime factorization using trial division and Pollard's rho."""
    factors = []
    while n % 2 == 0:
        factors.append(2)
        n //= 2

    d = 3
    while d * d <= n and d < 10000:
        while n % d == 0:
            factors.append(d)
            n //= d
        d += 2

    if n > 1:
        if is_prime(n):
            factors.append(n)
        else:
            # Simple Pollard's rho for the rest (simplified)
            def pollards_rho(n: int) -> int:
                if n % 2 == 0:
                    return 2
                x = 2
                y = 2
                d = 1
                c = 1

                def f(v: int) -> int:
                    return (v * v + c) % n

                while d == 1:
                    x = f(x)
                    y = f(f(y))
                    d = gcd(abs(x - y), n)
                    if d == n:
                        return pollards_rho(n)
                return d

            p = pollards_rho(n)
            factors.extend(prime_factorization(p))
            factors.extend(prime_factorization(n // p))

    return sorted(factors)


def euler_totient(n: int) -> int:
    """Compute Euler's totient function."""
    res = n
    factors = set(prime_factorization(n))
    for p in factors:
        res -= res // p
    return res


def continued_fraction(numerator: int, denominator: int) -> list[int]:
    """Compute continued fraction expansion."""
    cf = []
    while denominator != 0:
        quotient = numerator // denominator
        cf.append(quotient)
        numerator, denominator = denominator, numerator - quotient * denominator
    return cf


def convergents(cf: list[int]) -> list[tuple[int, int]]:
    """Compute convergents from continued fraction."""
    convs = []
    n0, n1 = 0, 1
    d0, d1 = 1, 0
    for q in cf:
        n2 = q * n1 + n0
        d2 = q * d1 + d0
        convs.append((n2, d2))
        n0, n1 = n1, n2
        d0, d1 = d1, d2
    return convs


def discrete_log(g: int, h: int, p: int) -> int | None:
    """Baby-step giant-step algorithm for discrete log."""
    m = math.isqrt(p) + 1

    # Baby steps
    table = {}
    for j in range(m):
        table[pow(g, j, p)] = j

    # Giant steps
    c = pow(g, m * (p - 2), p)
    for i in range(m):
        y = (h * pow(c, i, p)) % p
        if y in table:
            return i * m + table[y]

    return None
