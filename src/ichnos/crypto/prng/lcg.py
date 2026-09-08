"""Linear Congruential Generator (LCG) closed-form reduction & fast timestamp brute-forcer.

Given an LCG: s_{i+1} = (a * s_i + b) mod m
Iterated n times:
[s_n, 1]^T = [[a, b], [0, 1]]^n * [s_0, 1]^T (mod m)
Reduces n iterations to a single affine transform s_n = (A * s_0 + B) mod m in O(log n).
"""

from __future__ import annotations

import ctypes
import hashlib
import time

from ichnos.core.harvester import FLAG_PATTERN
from ichnos.crypto.symmetric.aes import _get_common_crypto, decrypt_ecb


def _mat_mul_2x2(m1: tuple[tuple[int, int], tuple[int, int]], m2: tuple[tuple[int, int], tuple[int, int]], mod: int) -> tuple[tuple[int, int], tuple[int, int]]:
    return (
        ((m1[0][0] * m2[0][0] + m1[0][1] * m2[1][0]) % mod, (m1[0][0] * m2[0][1] + m1[0][1] * m2[1][1]) % mod),
        ((m1[1][0] * m2[0][0] + m1[1][1] * m2[1][0]) % mod, (m1[1][0] * m2[0][1] + m1[1][1] * m2[1][1]) % mod),
    )


def compose_lcg(a: int, b: int, m: int, n: int) -> tuple[int, int]:
    """Computes equivalent (A, B) such that s_n = (A * s_0 + B) mod m after n steps in O(log n)."""
    res = ((1, 0), (0, 1))
    base = ((a % m, b % m), (0, 1))
    p = n
    while p > 0:
        if p & 1:
            res = _mat_mul_2x2(res, base, m)
        base = _mat_mul_2x2(base, base, m)
        p >>= 1
    return res[0][0], res[0][1]


def crack_time_seeded_lcg(
    ct_bytes: bytes,
    a: int,
    b: int,
    m: int,
    iterations: int,
    ref_time: float | None = None,
    search_window: int = 1500000,
    hash_algo: str = "sha256",
) -> tuple[int, int, bytes, str] | None:
    """Brute-forces integer timestamp seeds for an LCG with hash-derived symmetric keys.

    Returns (timestamp, winning_seed, key, decrypted_text) if found, None otherwise.
    """
    now = time.time()
    # Normalize ref_time: if None, 0.0, or prior to year 2001, default to current time
    if ref_time is None or ref_time < 1000000000:
        ref_time = now

    candidate_centers = [int(ref_time)]
    if abs(int(now) - int(ref_time)) > 100000:
        candidate_centers.append(int(now))

    A, B = compose_lcg(a, b, m, iterations)
    target_ct_block = ct_bytes[:16]

    cc = _get_common_crypto()

    for center in candidate_centers:
        start_t = center + 86400
        end_t = center - search_window

        if cc:
            ct_buf = (ctypes.c_char * 16).from_buffer_copy(target_ct_block)
            out_buf = (ctypes.c_char * 16)()
            num_bytes = ctypes.c_size_t(0)

            for t in range(start_t, end_t, -1):
                seed = (A * (t % m) + B) % m
                seed_str = str(seed).encode()

                if hash_algo == "sha256":
                    key = hashlib.sha256(seed_str).digest()
                elif hash_algo == "md5":
                    key = hashlib.md5(seed_str).digest()
                else:
                    key = hashlib.new(hash_algo, seed_str).digest()

                cc(1, 0, 2, key, len(key), None, ct_buf, 16, out_buf, 16, ctypes.byref(num_bytes))
                dec_block = out_buf.raw

                # Fast check: first 16 bytes must contain '{' and be printable ASCII
                if b"{" in dec_block[:8] and all(32 <= b <= 126 for b in dec_block[:16]):
                    full_pt = decrypt_ecb(key, ct_bytes)
                    pt_str = full_pt.decode("latin-1", errors="replace")
                    match = FLAG_PATTERN.search(pt_str)
                    if match:
                        return t, seed, key, match.group(0)
        else:
            for t in range(start_t, end_t, -1):
                seed = (A * (t % m) + B) % m
                seed_str = str(seed).encode()

                if hash_algo == "sha256":
                    key = hashlib.sha256(seed_str).digest()
                elif hash_algo == "md5":
                    key = hashlib.md5(seed_str).digest()
                else:
                    key = hashlib.new(hash_algo, seed_str).digest()

                dec_block = decrypt_ecb(key, target_ct_block)
                if b"{" in dec_block[:8] and all(32 <= b <= 126 for b in dec_block[:16]):
                    full_pt = decrypt_ecb(key, ct_bytes)
                    pt_str = full_pt.decode("latin-1", errors="replace")
                    match = FLAG_PATTERN.search(pt_str)
                    if match:
                        return t, seed, key, match.group(0)

    return None
