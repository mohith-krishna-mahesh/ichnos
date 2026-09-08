"""Non-cryptographic hash identification and pre-image recovery.

Recognizes common hashing algorithms used in malware and CTFs for API hashing
and string obfuscation (FNV-1a, djb2, sdbm, MurmurHash3, Jenkins, CRC32).
"""

from __future__ import annotations

import binascii
import zlib


def fnv1_32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h = (h * 0x01000193) & 0xFFFFFFFF
        h ^= b
    return h


def fnv1a_32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def fnv1_64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for b in data:
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
        h ^= b
    return h


def fnv1a_64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def djb2(data: bytes) -> int:
    h = 5381
    for b in data:
        h = (((h << 5) + h) + b) & 0xFFFFFFFF
    return h


def djb2a(data: bytes) -> int:
    h = 5381
    for b in data:
        h = (((h << 5) + h) ^ b) & 0xFFFFFFFF
    return h


def sdbm(data: bytes) -> int:
    h = 0
    for b in data:
        h = (b + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
    return h


def jenkins_one_at_a_time(data: bytes) -> int:
    h = 0
    for b in data:
        h = (h + b) & 0xFFFFFFFF
        h = (h + (h << 10)) & 0xFFFFFFFF
        h ^= (h >> 6)
    h = (h + (h << 3)) & 0xFFFFFFFF
    h ^= (h >> 11)
    h = (h + (h << 15)) & 0xFFFFFFFF
    return h


def murmur3_32(data: bytes, seed: int = 0) -> int:
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    h = seed & 0xFFFFFFFF
    length = len(data)
    nblocks = length // 4

    for i in range(nblocks):
        k = int.from_bytes(data[i * 4 : i * 4 + 4], "little")
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF

        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = data[nblocks * 4 :]
    k1 = 0
    if len(tail) == 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h ^= k1

    h ^= length
    h ^= (h >> 16)
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= (h >> 13)
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= (h >> 16)
    return h


HASH_FUNCTIONS = {
    "fnv1_32": fnv1_32,
    "fnv1a_32": fnv1a_32,
    "fnv1_64": fnv1_64,
    "fnv1a_64": fnv1a_64,
    "djb2": djb2,
    "djb2a": djb2a,
    "sdbm": sdbm,
    "jenkins": jenkins_one_at_a_time,
    "murmur3_32": murmur3_32,
    "crc32": lambda d: binascii.crc32(d) & 0xFFFFFFFF,
    "adler32": lambda d: zlib.adler32(d) & 0xFFFFFFFF,
}

COMMON_API_NAMES = [
    "VirtualAlloc", "VirtualProtect", "LoadLibraryA", "LoadLibraryW",
    "GetProcAddress", "CreateProcessA", "CreateProcessW", "WinExec",
    "URLDownloadToFileA", "InternetOpenA", "HttpOpenRequestA", "HttpSendRequestA",
    "CreateFileA", "ReadFile", "WriteFile", "CloseHandle", "ExitProcess",
    "system", "execve", "popen", "mprotect", "dlopen", "dlsym",
]


def identify_noncrypto_hash(
    target_hash: int,
    wordlist: list[str] | None = None,
) -> list[dict]:
    """Identifies candidate hash algorithms and matching preimages for a target integer.

    Returns list of dicts with: 'algorithm', 'preimage', 'matched'.
    """
    results: list[dict] = []
    candidates = list(wordlist) if wordlist else list(COMMON_API_NAMES)

    for algo_name, fn in HASH_FUNCTIONS.items():
        for cand in candidates:
            cand_bytes = cand.encode("utf-8")
            h = fn(cand_bytes)
            if h == target_hash:
                results.append({
                    "algorithm": algo_name,
                    "preimage": cand,
                    "matched": True,
                })

    return results
