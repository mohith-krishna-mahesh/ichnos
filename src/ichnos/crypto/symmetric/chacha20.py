"""ChaCha20 and ChaCha20-Poly1305 stream cipher implementation (RFC 8439).

Multi-tier backend:
1. OpenSSL EVP via ctypes (EVP_chacha20)
2. 100% Pure Python RFC 8439 reference implementation with zero dependencies.
"""

from __future__ import annotations

import struct

from ichnos.crypto.symmetric.openssl import evp_cipher, is_openssl_available


def _rotl32(v: int, c: int) -> int:
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _quarter_round(x: list[int], a: int, b: int, c: int, d: int) -> None:
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = _rotl32(x[d] ^ x[a], 16)

    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = _rotl32(x[b] ^ x[c], 12)

    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = _rotl32(x[d] ^ x[a], 8)

    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = _rotl32(x[b] ^ x[c], 7)


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Generates a 64-byte ChaCha20 keystream block using pure Python."""
    constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]  # "expand 32-byte k"
    key_words = list(struct.unpack("<8I", key))
    nonce_words = list(struct.unpack("<3I", nonce))

    initial_state = constants + key_words + [counter] + nonce_words
    state = list(initial_state)

    for _ in range(10):
        # Column round
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        # Diagonal round
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)

    out = bytearray()
    for i in range(16):
        word = (state[i] + initial_state[i]) & 0xFFFFFFFF
        out.extend(struct.pack("<I", word))
    return bytes(out)


def chacha20_crypt(key: bytes, nonce: bytes, data: bytes, counter: int = 1) -> bytes:
    """Encrypts or decrypts data using ChaCha20 stream cipher (symmetric)."""
    if len(key) != 32:
        raise ValueError(f"ChaCha20 key must be 32 bytes, got {len(key)}")
    if len(nonce) not in (12, 16):
        raise ValueError(f"ChaCha20 nonce must be 12 bytes (RFC 8439) or 16 bytes, got {len(nonce)}")

    # RFC 8439 uses 12-byte nonce
    if len(nonce) == 16:
        nonce = nonce[:12]

    # Try OpenSSL if counter is 1 or 0
    if is_openssl_available() and counter in (0, 1):
        iv = (b"\x00" * 4) + nonce if len(nonce) == 12 else nonce
        res = evp_cipher("chacha20", key, iv, data, encrypt=True, padding=False)
        if res is not None:
            return res[: len(data)]

    # Pure Python fallback
    out = bytearray()
    cur_counter = counter
    for offset in range(0, len(data), 64):
        keystream = _chacha20_block(key, cur_counter, nonce)
        chunk = data[offset : offset + 64]
        out.extend(bytes([d ^ k for d, k in zip(chunk, keystream[: len(chunk)])]))
        cur_counter = (cur_counter + 1) & 0xFFFFFFFF
    return bytes(out)
