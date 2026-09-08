"""Symmetric Cryptography Engine: AES, ChaCha20, DES/3DES, RC4 and attack suites."""

from __future__ import annotations

from ichnos.crypto.symmetric.aes import (
    crypt_ctr,
    decrypt_cbc,
    decrypt_ecb,
    encrypt_cbc,
    encrypt_ecb,
)
from ichnos.crypto.symmetric.chacha20 import chacha20_crypt
from ichnos.crypto.symmetric.des import (
    DES_SEMI_WEAK_KEYS,
    DES_WEAK_KEYS,
    des3_decrypt_cbc,
    des_decrypt_ecb,
    des_encrypt_ecb,
    is_des_semi_weak_key,
    is_des_weak_key,
)
from ichnos.crypto.symmetric.openssl import is_openssl_available
from ichnos.crypto.symmetric.rc4 import is_fms_weak_key, rc4_crypt

__all__ = [
    "crypt_ctr",
    "decrypt_cbc",
    "decrypt_ecb",
    "encrypt_cbc",
    "encrypt_ecb",
    "chacha20_crypt",
    "des_encrypt_ecb",
    "des_decrypt_ecb",
    "des3_decrypt_cbc",
    "DES_WEAK_KEYS",
    "DES_SEMI_WEAK_KEYS",
    "is_des_weak_key",
    "is_des_semi_weak_key",
    "rc4_crypt",
    "is_fms_weak_key",
    "is_openssl_available",
]
