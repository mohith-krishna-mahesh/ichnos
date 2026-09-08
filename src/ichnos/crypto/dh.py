"""Diffie-Hellman Key Exchange and parameter security checks."""

from __future__ import annotations

import secrets

from ichnos.crypto.numtheory import is_prime


class DiffieHellman:
    """Diffie-Hellman Key Exchange over prime field GF(p)."""

    def __init__(self, p: int, g: int):
        self.p = p
        self.g = g

    def generate_private_key(self) -> int:
        """Generates private key a in [2, p-2]."""
        return secrets.randbelow(self.p - 3) + 2

    def public_key(self, private_key: int) -> int:
        """Computes public key A = g^a mod p."""
        return pow(self.g, private_key, self.p)

    def shared_secret(self, private_key: int, peer_public_key: int) -> int:
        """Computes shared secret s = B^a mod p."""
        return pow(peer_public_key, private_key, self.p)


def is_small_subgroup_element(pubkey: int, p: int) -> bool:
    """Checks if public key belongs to a trivial or dangerous small subgroup."""
    if pubkey <= 1 or pubkey >= p - 1:
        return True
    # Order 2 check: pubkey^2 mod p == 1
    if pow(pubkey, 2, p) == 1:
        return True
    return False


def is_safe_prime(p: int) -> bool:
    """Checks if p is a safe prime, i.e., (p - 1) / 2 is also prime."""
    if not is_prime(p):
        return False
    q = (p - 1) // 2
    return is_prime(q)


def check_dh_parameters(p: int, g: int) -> dict[str, bool | str]:
    """Audits DH parameters for security."""
    p_prime = is_prime(p)
    safe = is_safe_prime(p) if p_prime else False
    bit_len = p.bit_length()

    weak = not p_prime or not safe or bit_len < 2048

    return {
        "is_prime": p_prime,
        "is_safe_prime": safe,
        "bit_length": bit_len,
        "is_weak": weak,
        "recommendation": "Weak or non-safe prime" if weak else "Parameters appear secure",
    }
