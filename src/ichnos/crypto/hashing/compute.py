from __future__ import annotations

import hashlib

SUPPORTED_ALGORITHMS = [
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3_224",
    "sha3_256",
    "sha3_384",
    "sha3_512",
    "blake2b",
    "blake2s",
]


def compute_hash(data: bytes, algorithm: str) -> str:
    """Compute a specific hash for the given data."""
    if algorithm not in hashlib.algorithms_available:
        raise ValueError(f"Algorithm {algorithm} not supported by hashlib")

    h = hashlib.new(algorithm)
    h.update(data)
    return h.hexdigest()


def compute_all(data: bytes) -> dict[str, str]:
    """Compute all supported hashes for the given data."""
    results = {}
    for algo in SUPPORTED_ALGORITHMS:
        try:
            results[algo] = compute_hash(data, algo)
        except ValueError:
            pass
    return results
