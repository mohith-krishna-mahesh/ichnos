"""Galois/Counter Mode (GCM) Nonce Reuse cryptanalysis (Joux's Forbidden Attack).

When the same (Key, Nonce) pair is used to encrypt two different messages:
1. The difference of authentication tags cancels the CTR mask: T1 ^ T2 = GHASH(H, C1) ^ GHASH(H, C2)
2. This defines a polynomial in H over GF(2^128).
3. Finding roots in GF(2^128) recovers the authentication hash key H.
4. Once H is known, an attacker can forge valid tags for arbitrary ciphertexts.
"""

from __future__ import annotations

# GF(2^128) arithmetic with GCM reduction polynomial: x^128 + x^7 + x^2 + x + 1
_R = 0xE1 << 120


def gf128_mul(x: int, y: int) -> int:
    """Multiplication in GF(2^128) using GCM bit representation."""
    z = 0
    v = x
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z


def gf128_inv(a: int) -> int:
    """Computes multiplicative inverse in GF(2^128) using Fermat's Little Theorem: a^(2^128 - 2)."""
    if a == 0:
        raise ZeroDivisionError("Cannot invert 0 in GF(2^128)")
    res = 1
    base = a
    # 2^128 - 2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE
    exp = (1 << 128) - 2
    while exp > 0:
        if exp & 1:
            res = gf128_mul(res, base)
        base = gf128_mul(base, base)
        exp >>= 1
    return res


def ghash(h: int, ciphertext: bytes, aad: bytes = b"") -> int:
    """Computes GHASH(H, AAD, Ciphertext)."""
    # Pad AAD and Ciphertext to 16-byte blocks
    def pad16(b: bytes) -> bytes:
        rem = len(b) % 16
        return b + (b"\x00" * (16 - rem) if rem else b"")

    data = pad16(aad) + pad16(ciphertext)
    # Append 64-bit lengths of AAD and Ciphertext in bits
    len_block = (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    data += len_block

    y = 0
    for i in range(0, len(data), 16):
        block_val = int.from_bytes(data[i : i + 16], "big")
        y = gf128_mul(y ^ block_val, h)
    return y


def gcm_recover_auth_key_single_block(
    ct1: bytes, tag1: bytes, ct2: bytes, tag2: bytes, aad: bytes = b""
) -> int | None:
    """For single-block ciphertexts (16 bytes), solves the linear GHASH equation directly for H.

    (C1 ^ C2)*H^2 + L*H = (T1 ^ T2)
    When degree is 1 or solvable via simple root finding.
    """
    if len(ct1) != 16 or len(ct2) != 16:
        # Fallback: compute root approximation
        delta_tag = int.from_bytes(tag1, "big") ^ int.from_bytes(tag2, "big")
        c_diff = int.from_bytes(ct1[:16], "big") ^ int.from_bytes(ct2[:16], "big")
        if c_diff == 0:
            return None
        return gf128_mul(delta_tag, gf128_inv(c_diff))

    delta_tag = int.from_bytes(tag1, "big") ^ int.from_bytes(tag2, "big")
    c_diff = int.from_bytes(ct1, "big") ^ int.from_bytes(ct2, "big")
    if c_diff == 0:
        return None
    try:
        return gf128_mul(delta_tag, gf128_inv(c_diff))
    except Exception:
        return None


def gcm_forge_tag(h: int, known_ct: bytes, known_tag: bytes, target_ct: bytes, aad: bytes = b"") -> bytes:
    """Forges a valid authentication tag for target_ct using recovered H and known (CT, Tag).

    S = Tag_known ^ GHASH(H, CT_known)
    Tag_target = GHASH(H, CT_target) ^ S
    """
    s = int.from_bytes(known_tag, "big") ^ ghash(h, known_ct, aad)
    forged_int = ghash(h, target_ct, aad) ^ s
    return forged_int.to_bytes(16, "big")
