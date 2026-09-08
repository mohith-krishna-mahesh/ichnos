"""Tests for asymmetric cryptanalysis and hash length extension (ECDSA, Hash Ext, Shamir)."""

from __future__ import annotations

import hashlib

from ichnos.crypto.ecc.ecdsa import recover_private_key_reused_nonce
from ichnos.crypto.hashing.length_extension import md5_length_extension, sha256_length_extension
from ichnos.crypto.numtheory import mod_inverse
from ichnos.crypto.shamir import recover_secret, split_secret


def test_ecdsa_reused_nonce():
    # Curve order (secp256k1)
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    d = 0x1337424213374242
    k = 0xCAFEBABECAFEBABE
    r = 0x123456789ABCDEF0

    z1 = 0xAAAAAAAAAAAAAAAA
    z2 = 0xBBBBBBBBBBBBBBBB

    # s = k^-1 * (z + r*d) mod n
    k_inv = mod_inverse(k, n)
    s1 = (k_inv * (z1 + r * d)) % n
    s2 = (k_inv * (z2 + r * d)) % n

    recovered_d, recovered_k = recover_private_key_reused_nonce(r, s1, s2, z1, z2, n)
    assert recovered_d == d
    assert recovered_k == k


def test_sha256_length_extension():
    secret = b"SECRET_SALT_1234"
    orig_data = b"user=guest&role=user"
    extra_data = b"&admin=true"

    # Compute original MAC
    mac = hashlib.sha256(secret + orig_data).hexdigest()

    # Forged extension
    forged_mac, forged_msg = sha256_length_extension(mac, orig_data, len(secret), extra_data)

    # Verify forged MAC matches real SHA-256 of secret + forged_msg
    real_forged_mac = hashlib.sha256(secret + forged_msg).hexdigest()
    assert forged_mac == real_forged_mac


def test_md5_length_extension():
    secret = b"MY_SECRET_KEY"
    orig_data = b"action=view"
    extra_data = b"&action=delete_all"

    mac = hashlib.md5(secret + orig_data).hexdigest()

    forged_mac, forged_msg = md5_length_extension(mac, orig_data, len(secret), extra_data)

    real_forged_mac = hashlib.md5(secret + forged_msg).hexdigest()
    assert forged_mac == real_forged_mac


def test_shamir_secret_sharing():
    prime = 2**127 - 1  # Mersenne prime
    secret = 9876543210123456789

    shares = split_secret(secret, k=3, n=5, prime=prime)
    assert len(shares) == 5

    # Any 3 shares reconstruct the secret
    assert recover_secret([shares[0], shares[1], shares[2]], prime) == secret
    assert recover_secret([shares[1], shares[3], shares[4]], prime) == secret
    assert recover_secret([shares[0], shares[2], shares[4]], prime) == secret
