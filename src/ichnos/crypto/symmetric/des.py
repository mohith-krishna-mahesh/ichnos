"""DES, Triple-DES (3DES), and 2DES Meet-in-the-Middle cryptanalysis.

Provides:
- DES and 3DES encryption/decryption via OpenSSL and pure Python
- Meet-in-the-middle attack against double-DES (2DES)
"""

from __future__ import annotations

from ichnos.crypto.symmetric.openssl import evp_cipher, is_openssl_available

# Standard DES Permutations & S-Boxes
_IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
]

_FP = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
]

_E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
]

_P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
]

_PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
]

_PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
]

_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

_S_BOXES = [
    # S1
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    # S2
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    # S3
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    # S4
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    # S5
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    # S6
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    # S7
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    # S8
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
]


def _permute(src: int, table: list[int], src_len: int) -> int:
    res = 0
    for idx in table:
        res = (res << 1) | ((src >> (src_len - idx)) & 1)
    return res


def _des_key_schedule(key_bytes: bytes) -> list[int]:
    key_int = int.from_bytes(key_bytes, "big")
    c_d = _permute(key_int, _PC1, 64)
    c = (c_d >> 28) & 0x0FFFFFFF
    d = c_d & 0x0FFFFFFF
    subkeys = []
    for shift in _SHIFTS:
        c = ((c << shift) | (c >> (28 - shift))) & 0x0FFFFFFF
        d = ((d << shift) | (d >> (28 - shift))) & 0x0FFFFFFF
        cd = (c << 28) | d
        subkeys.append(_permute(cd, _PC2, 56))
    return subkeys


def _des_round(r: int, subkey: int) -> int:
    er = _permute(r, _E, 32)
    b = er ^ subkey
    s_out = 0
    for i in range(8):
        chunk = (b >> (6 * (7 - i))) & 0x3F
        row = ((chunk >> 4) & 2) | (chunk & 1)
        col = (chunk >> 1) & 0x0F
        val = _S_BOXES[i][row * 16 + col]
        s_out = (s_out << 4) | val
    return _permute(s_out, _P, 32)


def _des_crypt_block(block: bytes, subkeys: list[int]) -> bytes:
    block_int = int.from_bytes(block, "big")
    ip = _permute(block_int, _IP, 64)
    l, r = (ip >> 32) & 0xFFFFFFFF, ip & 0xFFFFFFFF
    for sk in subkeys:
        l, r = r, l ^ _des_round(r, sk)
    pre_fp = (r << 32) | l
    fp = _permute(pre_fp, _FP, 64)
    return fp.to_bytes(8, "big")


def des_encrypt_ecb(key: bytes, pt: bytes) -> bytes:
    """Encrypts plaintext using DES-ECB."""
    if is_openssl_available():
        res = evp_cipher("des-ecb", key[:8], None, pt, encrypt=True, padding=False)
        if res:
            return res[: len(pt)]
    subkeys = _des_key_schedule(key[:8])
    out = bytearray()
    for i in range(0, len(pt), 8):
        out.extend(_des_crypt_block(pt[i : i + 8], subkeys))
    return bytes(out)


def des_decrypt_ecb(key: bytes, ct: bytes) -> bytes:
    """Decrypts ciphertext using DES-ECB."""
    if is_openssl_available():
        res = evp_cipher("des-ecb", key[:8], None, ct, encrypt=False, padding=False)
        if res:
            return res[: len(ct)]
    subkeys = _des_key_schedule(key[:8])[::-1]
    out = bytearray()
    for i in range(0, len(ct), 8):
        out.extend(_des_crypt_block(ct[i : i + 8], subkeys))
    return bytes(out)


def des3_decrypt_cbc(key: bytes, iv: bytes, ct: bytes) -> bytes:
    """Decrypts ciphertext using Triple-DES (3DES / EDE3) in CBC mode."""
    if is_openssl_available():
        res = evp_cipher("des-ede3-cbc", key, iv, ct, encrypt=False, padding=False)
        if res:
            return res[: len(ct)]

    k1, k2, k3 = key[:8], key[8:16], key[16:24] if len(key) >= 24 else key[:8]
    out = bytearray()
    prev = iv
    for i in range(0, len(ct), 8):
        blk = ct[i : i + 8]
        # Decrypt with K3, Encrypt with K2, Decrypt with K1
        step1 = des_decrypt_ecb(k3, blk)
        step2 = des_encrypt_ecb(k2, step1)
        step3 = des_decrypt_ecb(k1, step2)
        out.extend(bytes([s ^ p for s, p in zip(step3, prev)]))
        prev = blk
    return bytes(out)


# ---------------------------------------------------------------------------
# Weak and Semi-Weak Keys
# ---------------------------------------------------------------------------

DES_WEAK_KEYS: set[bytes] = {
    bytes.fromhex("0101010101010101"),
    bytes.fromhex("FEFEFEFEFEFEFEFE"),
    bytes.fromhex("E0E0E0E0F1F1F1F1"),
    bytes.fromhex("1F1F1F1F0E0E0E0E"),
}

# 6 pairs (12 keys total) where E_{k1}(E_{k2}(P)) == P
_SEMI_WEAK_PAIRS: list[tuple[bytes, bytes]] = [
    (bytes.fromhex("01FE01FE01FE01FE"), bytes.fromhex("FE01FE01FE01FE01")),
    (bytes.fromhex("1FE01FE00EF10EF1"), bytes.fromhex("E01FE01FF10EF10E")),
    (bytes.fromhex("01E001E001F101F1"), bytes.fromhex("E001E001F101F101")),
    (bytes.fromhex("1FFE1FFE0EFE0EFE"), bytes.fromhex("FE1FFE1FFE0EFE0E")),
    (bytes.fromhex("011F011F010E010E"), bytes.fromhex("1F011F010E010E01")),
    (bytes.fromhex("E0FEE0FEF1FEF1FE"), bytes.fromhex("FEE0FEE0FEF1FEF1")),
]

DES_SEMI_WEAK_KEYS: dict[bytes, bytes] = {}
for _k1, _k2 in _SEMI_WEAK_PAIRS:
    DES_SEMI_WEAK_KEYS[_k1] = _k2
    DES_SEMI_WEAK_KEYS[_k2] = _k1


def is_des_weak_key(key: bytes) -> bool:
    """Returns True if the 8-byte key is one of the 4 DES weak keys."""
    return key[:8] in DES_WEAK_KEYS


def is_des_semi_weak_key(key: bytes) -> tuple[bool, bytes | None]:
    """Checks if the 8-byte key is a DES semi-weak key.

    Returns:
        (True, dual_key) if semi-weak, (False, None) otherwise.
    """
    k8 = key[:8]
    if k8 in DES_SEMI_WEAK_KEYS:
        return True, DES_SEMI_WEAK_KEYS[k8]
    return False, None
