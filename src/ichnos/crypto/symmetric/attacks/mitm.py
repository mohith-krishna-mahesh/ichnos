"""Meet-in-the-Middle (MITM) attack engine for double and multiple encryption.

Generalizes 2DES-style MITM to any cipher where an intermediate state can be
matched: E_{k1}(P) == D_{k2}(C).
"""

from __future__ import annotations

from typing import Callable


def meet_in_the_middle(
    known_pairs: list[tuple[bytes, bytes]],
    encrypt_fn: Callable[[bytes, bytes], bytes],
    decrypt_fn: Callable[[bytes, bytes], bytes],
    candidate_keys1: list[bytes],
    candidate_keys2: list[bytes],
) -> tuple[bytes, bytes] | None:
    """Recovers (key1, key2) such that C = encrypt(key2, encrypt(key1, P)).

    Args:
        known_pairs: List of at least one (plaintext, ciphertext) tuple. If multiple
            pairs are provided, candidate matches are validated against them to rule out
            false positive collisions.
        encrypt_fn: Callable (key, plaintext) -> ciphertext.
        decrypt_fn: Callable (key, ciphertext) -> plaintext.
        candidate_keys1: Iterable of candidate keys for the first encryption stage.
        candidate_keys2: Iterable of candidate keys for the second encryption stage.

    Returns:
        (key1, key2) if a matching keypair is recovered, None otherwise.
    """
    if not known_pairs:
        return None

    p0, c0 = known_pairs[0]

    # Forward phase: Build intermediate state table for candidate_keys1
    forward_table: dict[bytes, bytes] = {}
    for k1 in candidate_keys1:
        try:
            intermediate = encrypt_fn(k1, p0)
            forward_table[intermediate] = k1
        except Exception:
            continue

    # Backward phase: Decrypt c0 with candidate_keys2 and search table
    for k2 in candidate_keys2:
        try:
            intermediate = decrypt_fn(k2, c0)
        except Exception:
            continue

        if intermediate in forward_table:
            k1 = forward_table[intermediate]

            # Validate against any additional known pairs
            valid = True
            for p_test, c_test in known_pairs[1:]:
                try:
                    if encrypt_fn(k2, encrypt_fn(k1, p_test)) != c_test:
                        valid = False
                        break
                except Exception:
                    valid = False
                    break

            if valid:
                return k1, k2

    return None
