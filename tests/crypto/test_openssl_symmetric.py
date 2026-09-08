"""Tests for OpenSSL EVP dynamic binding and symmetric ciphers (AES, ChaCha20, DES, RC4)."""

from __future__ import annotations

from ichnos.crypto.symmetric.aes import (
    crypt_ctr,
    decrypt_cbc,
    decrypt_ecb,
    encrypt_cbc,
    encrypt_ecb,
)
from ichnos.crypto.symmetric.chacha20 import chacha20_crypt
from ichnos.crypto.symmetric.des import des_decrypt_ecb, des_encrypt_ecb
from ichnos.crypto.symmetric.openssl import is_openssl_available
from ichnos.crypto.symmetric.rc4 import is_fms_weak_key, rc4_crypt


def test_openssl_availability():
    # Should evaluate without error on any OS
    avail = is_openssl_available()
    assert isinstance(avail, bool)


def test_aes_ecb_roundtrip():
    key = b"1234567890123456"
    pt = b"Attack at dawn!!"
    ct = encrypt_ecb(key, pt)
    assert ct != pt
    dec = decrypt_ecb(key, ct)
    assert dec == pt


def test_aes_ecb_256():
    key = b"0123456789abcdef0123456789abcdef"
    pt = b"SuperSecretData!"
    ct = encrypt_ecb(key, pt)
    dec = decrypt_ecb(key, ct)
    assert dec == pt


def test_aes_cbc_roundtrip():
    key = b"0123456789abcdef"
    iv = b"fedcba9876543210"
    pt = b"Block1Block1Blk1Block2Block2Blk2"
    ct = encrypt_cbc(key, iv, pt)
    assert ct != pt
    dec = decrypt_cbc(key, iv, ct)
    assert dec == pt


def test_aes_ctr():
    key = b"YELLOW SUBMARINE"
    nonce = b"123456789012"
    msg = b"Hello, CTR mode world!"
    ct = crypt_ctr(key, nonce, msg)
    assert ct != msg
    dec = crypt_ctr(key, nonce, ct)
    assert dec == msg


def test_chacha20_roundtrip():
    key = bytes(range(32))
    nonce = bytes(range(12))
    msg = b"ChaCha20 RFC 8439 standard stream cipher test payload"
    ct = chacha20_crypt(key, nonce, msg)
    assert ct != msg
    dec = chacha20_crypt(key, nonce, ct)
    assert dec == msg


def test_des_ecb_roundtrip():
    key = b"12345678"
    pt = b"TESTDATA"
    ct = des_encrypt_ecb(key, pt)
    assert ct != pt
    dec = des_decrypt_ecb(key, ct)
    assert dec == pt


def test_rc4_roundtrip():
    key = b"SecretKey"
    data = b"Plaintext for RC4 stream encryption"
    ct = rc4_crypt(key, data)
    assert ct != data
    dec = rc4_crypt(key, ct)
    assert dec == data


def test_rc4_fms_weak_key():
    assert is_fms_weak_key(bytes([3, 255, 42])) is True
    assert is_fms_weak_key(bytes([1, 2, 3])) is False
