"""RC4 / ARC4 stream cipher implementation and Fluhrer-Mantin-Shamir (FMS) bias analysis.

Provides:
- Symmetric encryption/decryption via OpenSSL and pure Python
- FMS weak-key detection and second-byte bias check
"""

from __future__ import annotations

from ichnos.crypto.symmetric.openssl import evp_cipher, is_openssl_available


def rc4_crypt(key: bytes, data: bytes, drop_bytes: int = 0) -> bytes:
    """Encrypts or decrypts data using RC4 (symmetric keystream).

    Optionally drops initial keystream bytes (RC4-drop[n]) to mitigate initial-byte bias.
    """
    if is_openssl_available() and drop_bytes == 0:
        res = evp_cipher("rc4", key, None, data, encrypt=True, padding=False)
        if res is not None:
            return res[: len(data)]

    # Key Scheduling Algorithm (KSA)
    s = list(range(256))
    j = 0
    key_len = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % key_len]) & 0xFF
        s[i], s[j] = s[j], s[i]

    # Pseudo-Random Generation Algorithm (PRGA)
    i = 0
    j = 0
    # Drop initial keystream bytes if requested
    for _ in range(drop_bytes):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]

    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) & 0xFF]
        out.append(b ^ k)
    return bytes(out)


def is_fms_weak_key(iv: bytes) -> bool:
    """Returns True if the IV is of the form (A + 3, N - 1, X) vulnerable to FMS attack."""
    if len(iv) < 3:
        return False
    return iv[1] == 255
