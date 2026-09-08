"""OpenSSL EVP dynamic binding via ctypes for high-performance symmetric cryptography.

Provides hardware-accelerated AES (ECB, CBC, CTR, GCM), ChaCha20, 3DES, and RC4
via system libcrypto on macOS, Linux, and Windows with silent fallback.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
from typing import Any

# Global reference to loaded libcrypto
_LIBCRYPTO: Any = None
_OPENSSL_AVAILABLE: bool = False


def _find_libcrypto() -> str | None:
    """Locates the system libcrypto shared library across common OS paths."""
    candidates: list[str] = []

    if sys.platform == "darwin":
        candidates.extend([
            "/opt/homebrew/opt/openssl/lib/libcrypto.dylib",
            "/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib",
            "/opt/homebrew/opt/openssl@1.1/lib/libcrypto.dylib",
            "/usr/local/opt/openssl/lib/libcrypto.dylib",
            "/usr/local/lib/libcrypto.dylib",
            "/usr/lib/libcrypto.dylib",
        ])
    elif sys.platform.startswith("linux"):
        candidates.extend([
            "libcrypto.so.3",
            "libcrypto.so.1.1",
            "libcrypto.so",
            "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
            "/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1",
            "/usr/lib64/libcrypto.so.3",
            "/usr/lib64/libcrypto.so",
        ])
    elif sys.platform == "win32":
        candidates.extend([
            "libcrypto-3-x64.dll",
            "libcrypto-1_1-x64.dll",
            "libcrypto-3.dll",
            "libcrypto.dll",
        ])

    found = ctypes.util.find_library("crypto")
    if found:
        candidates.append(found)

    for path in candidates:
        if path and (os.path.exists(path) or ("/" not in path and "\\" not in path)):
            try:
                lib = ctypes.CDLL(path)
                if hasattr(lib, "EVP_CIPHER_CTX_new"):
                    return path
            except Exception:
                continue

    return None


def _init_openssl() -> bool:
    global _LIBCRYPTO, _OPENSSL_AVAILABLE
    if _OPENSSL_AVAILABLE and _LIBCRYPTO is not None:
        return True

    path = _find_libcrypto()
    if not path:
        _OPENSSL_AVAILABLE = False
        return False

    try:
        lib = ctypes.CDLL(path)

        # Declare argument and return types
        lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
        lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]

        lib.EVP_CipherInit_ex.argtypes = [
            ctypes.c_void_p,  # ctx
            ctypes.c_void_p,  # type
            ctypes.c_void_p,  # impl (NULL)
            ctypes.c_char_p,  # key
            ctypes.c_char_p,  # iv
            ctypes.c_int,     # enc (1=encrypt, 0=decrypt)
        ]
        lib.EVP_CipherInit_ex.restype = ctypes.c_int

        lib.EVP_CipherUpdate.argtypes = [
            ctypes.c_void_p,  # ctx
            ctypes.c_char_p,  # out
            ctypes.POINTER(ctypes.c_int),  # outl
            ctypes.c_char_p,  # in
            ctypes.c_int,     # inl
        ]
        lib.EVP_CipherUpdate.restype = ctypes.c_int

        lib.EVP_CipherFinal_ex.argtypes = [
            ctypes.c_void_p,  # ctx
            ctypes.c_char_p,  # outm
            ctypes.POINTER(ctypes.c_int),  # outl
        ]
        lib.EVP_CipherFinal_ex.restype = ctypes.c_int

        lib.EVP_CIPHER_CTX_set_padding.argtypes = [ctypes.c_void_p, ctypes.c_int]
        lib.EVP_CIPHER_CTX_set_padding.restype = ctypes.c_int

        _LIBCRYPTO = lib
        _OPENSSL_AVAILABLE = True
        return True
    except Exception:
        _OPENSSL_AVAILABLE = False
        return False


def is_openssl_available() -> bool:
    """Returns True if system libcrypto is loaded and usable."""
    if _OPENSSL_AVAILABLE:
        return True
    return _init_openssl()


def get_cipher_ptr(name: str) -> Any:
    """Resolves an EVP_CIPHER pointer by algorithm name."""
    if not is_openssl_available():
        return None

    func_map = {
        # AES ECB
        "aes-128-ecb": "EVP_aes_128_ecb",
        "aes-192-ecb": "EVP_aes_192_ecb",
        "aes-256-ecb": "EVP_aes_256_ecb",
        # AES CBC
        "aes-128-cbc": "EVP_aes_128_cbc",
        "aes-192-cbc": "EVP_aes_192_cbc",
        "aes-256-cbc": "EVP_aes_256_cbc",
        # AES CTR
        "aes-128-ctr": "EVP_aes_128_ctr",
        "aes-192-ctr": "EVP_aes_192_ctr",
        "aes-256-ctr": "EVP_aes_256_ctr",
        # AES GCM
        "aes-128-gcm": "EVP_aes_128_gcm",
        "aes-256-gcm": "EVP_aes_256_gcm",
        # ChaCha20
        "chacha20": "EVP_chacha20",
        "chacha20-poly1305": "EVP_chacha20_poly1305",
        # DES / 3DES
        "des-ecb": "EVP_des_ecb",
        "des-cbc": "EVP_des_cbc",
        "des-ede3-cbc": "EVP_des_ede3_cbc",
        # RC4
        "rc4": "EVP_rc4",
    }

    norm = name.lower().replace("_", "-")
    func_name = func_map.get(norm)
    if func_name and hasattr(_LIBCRYPTO, func_name):
        fn = getattr(_LIBCRYPTO, func_name)
        fn.restype = ctypes.c_void_p
        return fn()

    if hasattr(_LIBCRYPTO, "EVP_get_cipherbyname"):
        get_by_name = _LIBCRYPTO.EVP_get_cipherbyname
        get_by_name.argtypes = [ctypes.c_char_p]
        get_by_name.restype = ctypes.c_void_p
        return get_by_name(norm.encode())

    return None


def evp_cipher(
    cipher_name: str,
    key: bytes,
    iv: bytes | None,
    data: bytes,
    encrypt: bool = True,
    padding: bool = False,
) -> bytes | None:
    """Performs symmetric encryption/decryption using OpenSSL EVP API.

    Returns ciphertext/plaintext bytes on success, or None on failure/unsupported.
    """
    if not is_openssl_available():
        return None

    cipher_ptr = get_cipher_ptr(cipher_name)
    if not cipher_ptr:
        return None

    ctx = _LIBCRYPTO.EVP_CIPHER_CTX_new()
    if not ctx:
        return None

    try:
        enc_flag = 1 if encrypt else 0
        iv_ptr = iv if iv else None

        if _LIBCRYPTO.EVP_CipherInit_ex(ctx, cipher_ptr, None, key, iv_ptr, enc_flag) != 1:
            return None

        # Set padding mode (0 = disable padding, 1 = PKCS#7 padding)
        pad_flag = 1 if padding else 0
        _LIBCRYPTO.EVP_CIPHER_CTX_set_padding(ctx, pad_flag)

        out_buf = ctypes.create_string_buffer(len(data) + 64)
        out_len = ctypes.c_int(0)

        if _LIBCRYPTO.EVP_CipherUpdate(ctx, out_buf, ctypes.byref(out_len), data, len(data)) != 1:
            return None

        fin_buf = ctypes.create_string_buffer(64)
        fin_len = ctypes.c_int(0)

        if _LIBCRYPTO.EVP_CipherFinal_ex(ctx, fin_buf, ctypes.byref(fin_len)) != 1:
            return None

        return out_buf.raw[: out_len.value] + fin_buf.raw[: fin_len.value]
    finally:
        _LIBCRYPTO.EVP_CIPHER_CTX_free(ctx)
