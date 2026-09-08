"""Dictionary and rule-based password hash cracking engine."""

from __future__ import annotations

import hashlib
import struct

from ichnos.password.mutator import mutate_word


def md4_hash(data: bytes) -> str:
    """Pure-Python MD4 hash implementation (RFC 1320)."""

    def F(x, y, z):
        return (x & y) | (~x & z)

    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def H(x, y, z):
        return x ^ y ^ z

    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    msg = bytearray(data)
    orig_len_bits = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += struct.pack("<Q", orig_len_bits)

    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for i in range(0, len(msg), 64):
        X = struct.unpack("<16I", msg[i : i + 64])
        a, b, c, d = A, B, C, D

        # Round 1
        s1 = [3, 7, 11, 19]
        for j in range(16):
            r = j % 4
            if r == 0:
                a = rol((a + F(b, c, d) + X[j]) & 0xFFFFFFFF, s1[0])
            elif r == 1:
                d = rol((d + F(a, b, c) + X[j]) & 0xFFFFFFFF, s1[1])
            elif r == 2:
                c = rol((c + F(d, a, b) + X[j]) & 0xFFFFFFFF, s1[2])
            elif r == 3:
                b = rol((b + F(c, d, a) + X[j]) & 0xFFFFFFFF, s1[3])

        # Round 2
        s2 = [3, 5, 9, 13]
        order2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        for j, k in enumerate(order2):
            r = j % 4
            if r == 0:
                a = rol((a + G(b, c, d) + X[k] + 0x5A827999) & 0xFFFFFFFF, s2[0])
            elif r == 1:
                d = rol((d + G(a, b, c) + X[k] + 0x5A827999) & 0xFFFFFFFF, s2[1])
            elif r == 2:
                c = rol((c + G(d, a, b) + X[k] + 0x5A827999) & 0xFFFFFFFF, s2[2])
            elif r == 3:
                b = rol((b + G(c, d, a) + X[k] + 0x5A827999) & 0xFFFFFFFF, s2[3])

        # Round 3
        s3 = [3, 9, 11, 15]
        order3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for j, k in enumerate(order3):
            r = j % 4
            if r == 0:
                a = rol((a + H(b, c, d) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s3[0])
            elif r == 1:
                d = rol((d + H(a, b, c) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s3[1])
            elif r == 2:
                c = rol((c + H(d, a, b) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s3[2])
            elif r == 3:
                b = rol((b + H(c, d, a) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s3[3])

        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF

    return struct.pack("<4I", A, B, C, D).hex()


def compute_hash(plaintext: str, algorithm: str) -> str:
    """Computes hex digest of plaintext for the specified algorithm."""
    algo = algorithm.lower().replace("-", "")
    data = plaintext.encode("utf-8")

    if algo == "ntlm":
        return md4_hash(plaintext.encode("utf-16le"))
    if algo == "md5":
        return hashlib.md5(data).hexdigest()
    if algo == "sha1":
        return hashlib.sha1(data).hexdigest()
    if algo == "sha224":
        return hashlib.sha224(data).hexdigest()
    if algo == "sha256":
        return hashlib.sha256(data).hexdigest()
    if algo == "sha384":
        return hashlib.sha384(data).hexdigest()
    if algo == "sha512":
        return hashlib.sha512(data).hexdigest()

    raise ValueError(f"Unsupported algorithm: {algorithm}")


def guess_algorithm_from_hash(h: str) -> list[str]:
    """Guesses candidate hash algorithm based on hex length."""
    h_len = len(h.strip())
    if h_len == 32:
        return ["md5", "ntlm"]
    if h_len == 40:
        return ["sha1"]
    if h_len == 56:
        return ["sha224"]
    if h_len == 64:
        return ["sha256"]
    if h_len == 96:
        return ["sha384"]
    if h_len == 128:
        return ["sha512"]
    return ["sha256", "md5", "sha1"]


def crack_hash(
    target_hash: str,
    wordlist: list[str],
    algorithm: str = "auto",
    apply_rules: bool = False,
) -> str | None:
    """Cracks a single hash against wordlist candidates."""
    target_clean = target_hash.strip().lower()

    if algorithm.lower() == "auto":
        algos = guess_algorithm_from_hash(target_clean)
    else:
        algos = [algorithm.lower().replace("-", "")]

    candidates: list[str] = []
    if apply_rules:
        seen = set()
        for w in wordlist:
            for mut in mutate_word(w):
                if mut not in seen:
                    seen.add(mut)
                    candidates.append(mut)
    else:
        candidates = wordlist

    for candidate in candidates:
        for algo in algos:
            try:
                if compute_hash(candidate, algo) == target_clean:
                    return candidate
            except Exception:
                continue

    return None


def crack_hashes(
    target_hashes: list[str],
    wordlist: list[str],
    algorithm: str = "auto",
    apply_rules: bool = False,
) -> dict[str, str]:
    """Cracks multiple hashes against a wordlist."""
    results: dict[str, str] = {}
    for h in target_hashes:
        cracked = crack_hash(h, wordlist, algorithm=algorithm, apply_rules=apply_rules)
        if cracked:
            results[h] = cracked
    return results
