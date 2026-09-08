"""ElGamal encryption, decryption, signatures, and nonce-reuse attack."""

from __future__ import annotations

import secrets

from ichnos.crypto.numtheory import gcd, mod_inverse


def generate_keypair(p: int, g: int) -> tuple[int, int]:
    """Generates (private_key, public_key) pair for ElGamal."""
    x = secrets.randbelow(p - 3) + 2
    y = pow(g, x, p)
    return x, y


def elgamal_encrypt(m: int, p: int, g: int, y: int, k: int | None = None) -> tuple[int, int]:
    """Encrypts message integer m < p under public key y."""
    if m >= p:
        raise ValueError("Message m must be less than modulus p")
    if k is None:
        while True:
            k = secrets.randbelow(p - 3) + 2
            if gcd(k, p - 1) == 1:
                break

    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (m * s) % p
    return c1, c2


def elgamal_decrypt(c1: int, c2: int, p: int, x: int) -> int:
    """Decrypts ciphertext (c1, c2) using private key x."""
    s = pow(c1, x, p)
    s_inv = mod_inverse(s, p)
    return (c2 * s_inv) % p


def elgamal_sign(m: int, p: int, g: int, x: int, k: int | None = None) -> tuple[int, int]:
    """Computes ElGamal signature (r, s) on integer message m."""
    if k is None:
        while True:
            k = secrets.randbelow(p - 3) + 2
            if gcd(k, p - 1) == 1:
                break

    r = pow(g, k, p)
    k_inv = mod_inverse(k, p - 1)
    s = ((m - x * r) * k_inv) % (p - 1)
    return r, s


def elgamal_verify(m: int, r: int, s: int, p: int, g: int, y: int) -> bool:
    """Verifies ElGamal signature (r, s)."""
    if not (0 < r < p and 0 < s < p - 1):
        return False
    v1 = pow(g, m, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p
    return v1 == v2


def elgamal_recover_private_key_nonce_reuse(
    m1: int,
    s1: int,
    m2: int,
    s2: int,
    r: int,
    p: int,
    g: int | None = None,
    y: int | None = None,
) -> int | None:
    """Recovers ElGamal private key when the ephemeral key k was reused across two signatures."""
    delta_m = (m1 - m2) % (p - 1)
    delta_s = (s1 - s2) % (p - 1)

    d_s = gcd(delta_s, p - 1)
    if d_s != 1:
        return None

    k = (delta_m * mod_inverse(delta_s, p - 1)) % (p - 1)
    rhs = (m1 - k * s1) % (p - 1)

    d_r = gcd(r, p - 1)
    if rhs % d_r != 0:
        return None

    r_prime = r // d_r
    rhs_prime = rhs // d_r
    mod_prime = (p - 1) // d_r

    x0 = (rhs_prime * mod_inverse(r_prime, mod_prime)) % mod_prime
    if g is not None and y is not None:
        for i in range(d_r):
            cand_x = x0 + i * mod_prime
            if pow(g, cand_x, p) == y:
                return cand_x
    return x0
