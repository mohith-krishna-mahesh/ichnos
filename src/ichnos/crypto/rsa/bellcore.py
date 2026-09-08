"""Bellcore Fault Injection Attack on RSA-CRT (Boneh-DeMillo-Lipton 1997).

Factors RSA modulus N given a faulty RSA-CRT signature and either:
1. The message and public exponent e, OR
2. A valid signature on the same message.
"""

from __future__ import annotations

import math


def bellcore_fault_attack(
    n: int,
    faulty_sig: int,
    valid_sig: int | None = None,
    message: int | None = None,
    e: int = 65537,
) -> tuple[int, int] | None:
    """Recovers factors (p, q) of N using RSA-CRT fault analysis.

    Args:
        n: RSA modulus N = p * q.
        faulty_sig: Corrupted signature s' from an RSA-CRT computation.
        valid_sig: (Optional) Correct signature s on the same message.
        message: (Optional) Original message hash or integer m.
        e: Public exponent (default 65537).

    Returns:
        (p, q) if factorization succeeds, None otherwise.
    """
    # Case 1: Both valid and faulty signatures are available
    if valid_sig is not None:
        diff = abs(valid_sig - faulty_sig)
        g = math.gcd(diff, n)
        if 1 < g < n:
            return g, n // g

    # Case 2: Message and public exponent are available
    if message is not None:
        val = (pow(faulty_sig, e, n) - message) % n
        g = math.gcd(val, n)
        if 1 < g < n:
            return g, n // g

    return None
