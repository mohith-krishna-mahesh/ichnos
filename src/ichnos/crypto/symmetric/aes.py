"""Multi-backend AES implementation (ECB, CBC, CTR, GCM).

Selects the fastest available execution engine:
1. OpenSSL EVP via ctypes (libcrypto)
2. Apple CommonCrypto (CCCrypt on macOS)
3. 100% Pure Python implementation with zero dependencies.
"""

from __future__ import annotations

import ctypes
import struct
import sys
from typing import Callable

from ichnos.crypto.symmetric.openssl import evp_cipher, is_openssl_available

# =========================================================================
# 1. Apple CommonCrypto Backend (macOS native accelerator)
# =========================================================================
_COMMON_CRYPTO_FN: Callable | None = None
_COMMON_CRYPTO_LOADED: bool = False


def _get_common_crypto() -> Callable | None:
    global _COMMON_CRYPTO_FN, _COMMON_CRYPTO_LOADED
    if _COMMON_CRYPTO_LOADED:
        return _COMMON_CRYPTO_FN

    _COMMON_CRYPTO_LOADED = True
    if sys.platform != "darwin":
        return None

    try:
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        fn = lib.CCCrypt
        fn.argtypes = [
            ctypes.c_uint32,  # op: 0=encrypt, 1=decrypt
            ctypes.c_uint32,  # alg: 0=AES
            ctypes.c_uint32,  # options: 2=ECB, 1=PKCS7, 0=CBC
            ctypes.c_void_p,  # key
            ctypes.c_size_t,  # keyLength
            ctypes.c_void_p,  # iv
            ctypes.c_void_p,  # dataIn
            ctypes.c_size_t,  # dataInLength
            ctypes.c_void_p,  # dataOut
            ctypes.c_size_t,  # dataOutAvailable
            ctypes.POINTER(ctypes.c_size_t),  # dataOutMoved
        ]
        fn.restype = ctypes.c_int32
        _COMMON_CRYPTO_FN = fn
        return fn
    except Exception:
        return None


# =========================================================================
# 2. Pure Python AES (Zero dependencies, guaranteed portable)
# =========================================================================
_S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5E, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

_INV_S_BOX = [0] * 256
for _i, _x in enumerate(_S_BOX):
    _INV_S_BOX[_x] = _i

_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)


def _mul(a: int, b: int) -> int:
    res = 0
    while b > 0:
        if b & 1:
            res ^= a
        a = _xtime(a)
        b >>= 1
    return res


def _key_expansion(key: bytes) -> list[list[int]]:
    key_len = len(key)
    if key_len == 16:
        nk, nr = 4, 10
    elif key_len == 24:
        nk, nr = 6, 12
    elif key_len == 32:
        nk, nr = 8, 14
    else:
        raise ValueError(f"Invalid AES key length: {key_len}")

    w = [list(key[4 * i : 4 * (i + 1)]) for i in range(nk)]

    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = [_S_BOX[temp[(j + 1) % 4]] for j in range(4)]
            temp[0] ^= _RCON[i // nk]
        elif nk > 6 and i % nk == 4:
            temp = [_S_BOX[temp[j]] for j in range(4)]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])

    round_keys: list[list[int]] = []
    for r in range(nr + 1):
        rk = []
        for c in range(4):
            rk.extend(w[4 * r + c])
        round_keys.append(rk)
    return round_keys


def _aes_encrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    nr = len(round_keys) - 1
    state = list(block)

    # Initial round
    for i in range(16):
        state[i] ^= round_keys[0][i]

    # Main rounds
    for r in range(1, nr):
        # SubBytes
        state = [_S_BOX[b] for b in state]
        # ShiftRows
        state = [
            state[0], state[5], state[10], state[15],
            state[4], state[9], state[14], state[3],
            state[8], state[13], state[2], state[7],
            state[12], state[1], state[6], state[11],
        ]
        # MixColumns
        new_state = [0] * 16
        for c in range(4):
            idx = 4 * c
            s0, s1, s2, s3 = state[idx], state[idx + 1], state[idx + 2], state[idx + 3]
            new_state[idx] = _xtime(s0) ^ (_xtime(s1) ^ s1) ^ s2 ^ s3
            new_state[idx + 1] = s0 ^ _xtime(s1) ^ (_xtime(s2) ^ s2) ^ s3
            new_state[idx + 2] = s0 ^ s1 ^ _xtime(s2) ^ (_xtime(s3) ^ s3)
            new_state[idx + 3] = (_xtime(s0) ^ s0) ^ s1 ^ s2 ^ _xtime(s3)
        state = new_state
        # AddRoundKey
        for i in range(16):
            state[i] ^= round_keys[r][i]

    # Final round
    state = [_S_BOX[b] for b in state]
    state = [
        state[0], state[5], state[10], state[15],
        state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7],
        state[12], state[1], state[6], state[11],
    ]
    for i in range(16):
        state[i] ^= round_keys[nr][i]

    return bytes(state)


def _aes_decrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    nr = len(round_keys) - 1
    state = list(block)

    # Initial round
    for i in range(16):
        state[i] ^= round_keys[nr][i]

    # Main rounds
    for r in range(nr - 1, 0, -1):
        # InvShiftRows
        state = [
            state[0], state[13], state[10], state[7],
            state[4], state[1], state[14], state[11],
            state[8], state[5], state[2], state[15],
            state[12], state[9], state[6], state[3],
        ]
        # InvSubBytes
        state = [_INV_S_BOX[b] for b in state]
        # AddRoundKey
        for i in range(16):
            state[i] ^= round_keys[r][i]
        # InvMixColumns
        new_state = [0] * 16
        for c in range(4):
            idx = 4 * c
            s0, s1, s2, s3 = state[idx], state[idx + 1], state[idx + 2], state[idx + 3]
            new_state[idx] = _mul(s0, 0x0E) ^ _mul(s1, 0x0B) ^ _mul(s2, 0x0D) ^ _mul(s3, 0x09)
            new_state[idx + 1] = _mul(s0, 0x09) ^ _mul(s1, 0x0E) ^ _mul(s2, 0x0B) ^ _mul(s3, 0x0D)
            new_state[idx + 2] = _mul(s0, 0x0D) ^ _mul(s1, 0x09) ^ _mul(s2, 0x0E) ^ _mul(s3, 0x0B)
            new_state[idx + 3] = _mul(s0, 0x0B) ^ _mul(s1, 0x0D) ^ _mul(s2, 0x09) ^ _mul(s3, 0x0E)
        state = new_state

    # Final round
    state = [
        state[0], state[13], state[10], state[7],
        state[4], state[1], state[14], state[11],
        state[8], state[5], state[2], state[15],
        state[12], state[9], state[6], state[3],
    ]
    state = [_INV_S_BOX[b] for b in state]
    for i in range(16):
        state[i] ^= round_keys[0][i]

    return bytes(state)


# =========================================================================
# 3. High-Level Public API (Auto-dispatching to fastest backend)
# =========================================================================

def decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypts ciphertext using AES-ECB mode across all available backends."""
    if len(ciphertext) % 16 != 0:
        raise ValueError(f"Ciphertext length must be multiple of 16, got {len(ciphertext)}")

    cipher_name = f"aes-{len(key)*8}-ecb"

    # Try OpenSSL first
    if is_openssl_available():
        res = evp_cipher(cipher_name, key, None, ciphertext, encrypt=False, padding=False)
        if res is not None:
            return res[: len(ciphertext)]

    # Try CommonCrypto (macOS)
    cc = _get_common_crypto()
    if cc:
        out_buf = ctypes.create_string_buffer(len(ciphertext) + 16)
        moved = ctypes.c_size_t(0)
        # op=1 (decrypt), alg=0 (AES), options=2 (ECB)
        status = cc(1, 0, 2, key, len(key), None, ciphertext, len(ciphertext), out_buf, len(out_buf), ctypes.byref(moved))
        if status == 0:
            return out_buf.raw[: moved.value]

    # Pure Python fallback
    rkeys = _key_expansion(key)
    out = bytearray()
    for i in range(0, len(ciphertext), 16):
        out.extend(_aes_decrypt_block(ciphertext[i : i + 16], rkeys))
    return bytes(out)


def encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    """Encrypts plaintext using AES-ECB mode."""
    if len(plaintext) % 16 != 0:
        raise ValueError("Plaintext length must be multiple of 16")

    cipher_name = f"aes-{len(key)*8}-ecb"

    if is_openssl_available():
        res = evp_cipher(cipher_name, key, None, plaintext, encrypt=True, padding=False)
        if res is not None:
            return res[: len(plaintext)]

    cc = _get_common_crypto()
    if cc:
        out_buf = ctypes.create_string_buffer(len(plaintext) + 16)
        moved = ctypes.c_size_t(0)
        status = cc(0, 0, 2, key, len(key), None, plaintext, len(plaintext), out_buf, len(out_buf), ctypes.byref(moved))
        if status == 0:
            return out_buf.raw[: moved.value]

    rkeys = _key_expansion(key)
    out = bytearray()
    for i in range(0, len(plaintext), 16):
        out.extend(_aes_encrypt_block(plaintext[i : i + 16], rkeys))
    return bytes(out)


def decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypts ciphertext using AES-CBC mode."""
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be multiple of 16")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")

    cipher_name = f"aes-{len(key)*8}-cbc"

    if is_openssl_available():
        res = evp_cipher(cipher_name, key, iv, ciphertext, encrypt=False, padding=False)
        if res is not None:
            return res[: len(ciphertext)]

    cc = _get_common_crypto()
    if cc:
        out_buf = ctypes.create_string_buffer(len(ciphertext) + 16)
        moved = ctypes.c_size_t(0)
        status = cc(1, 0, 0, key, len(key), iv, ciphertext, len(ciphertext), out_buf, len(out_buf), ctypes.byref(moved))
        if status == 0:
            return out_buf.raw[: moved.value]

    rkeys = _key_expansion(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i : i + 16]
        dec = _aes_decrypt_block(block, rkeys)
        out.extend(bytes([d ^ p for d, p in zip(dec, prev)]))
        prev = block
    return bytes(out)


def encrypt_cbc(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypts plaintext using AES-CBC mode."""
    if len(plaintext) % 16 != 0:
        raise ValueError("Plaintext length must be multiple of 16")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")

    cipher_name = f"aes-{len(key)*8}-cbc"

    if is_openssl_available():
        res = evp_cipher(cipher_name, key, iv, plaintext, encrypt=True, padding=False)
        if res is not None:
            return res[: len(plaintext)]

    cc = _get_common_crypto()
    if cc:
        out_buf = ctypes.create_string_buffer(len(plaintext) + 16)
        moved = ctypes.c_size_t(0)
        status = cc(0, 0, 0, key, len(key), iv, plaintext, len(plaintext), out_buf, len(out_buf), ctypes.byref(moved))
        if status == 0:
            return out_buf.raw[: moved.value]

    rkeys = _key_expansion(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(plaintext), 16):
        block = plaintext[i : i + 16]
        xored = bytes([b ^ p for b, p in zip(block, prev)])
        enc = _aes_encrypt_block(xored, rkeys)
        out.extend(enc)
        prev = enc
    return bytes(out)


def crypt_ctr(key: bytes, nonce: bytes, data: bytes, initial_counter: int = 0) -> bytes:
    """Encrypts or decrypts data using AES-CTR mode (symmetric keystream operation)."""
    cipher_name = f"aes-{len(key)*8}-ctr"

    # If nonce is 16 bytes and counter=0, we can use OpenSSL directly
    if len(nonce) == 16 and initial_counter == 0 and is_openssl_available():
        res = evp_cipher(cipher_name, key, nonce, data, encrypt=True, padding=False)
        if res is not None:
            return res[: len(data)]

    # Standard 12-byte nonce + 4-byte counter or 8-byte nonce + 8-byte counter
    rkeys = _key_expansion(key)
    out = bytearray()

    counter = initial_counter
    for offset in range(0, len(data), 16):
        if len(nonce) == 12:
            counter_block = nonce + struct.pack(">I", counter)
        elif len(nonce) == 8:
            counter_block = nonce + struct.pack(">Q", counter)
        elif len(nonce) == 16:
            iv_int = int.from_bytes(nonce, "big") + counter
            counter_block = iv_int.to_bytes(16, "big")
        else:
            padded_nonce = nonce[:16].ljust(12, b"\x00")
            counter_block = padded_nonce + struct.pack(">I", counter)

        keystream = _aes_encrypt_block(counter_block, rkeys)
        chunk = data[offset : offset + 16]
        out.extend(bytes([c ^ k for c, k in zip(chunk, keystream[: len(chunk)])]))
        counter += 1

    return bytes(out)
