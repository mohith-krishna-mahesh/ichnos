"""Merkle-Damgård length extension attacks for MD5, SHA-1, and SHA-256.

Exploits the iterative construction of Merkle-Damgård hash functions:
given ``H(secret || original_data)`` and ``len(secret)``, an attacker can
compute ``H(secret || original_data || padding || extra_data)`` **without
knowing the secret**.

This module provides:
- ``md_padding``  – compute MD padding for a given message length
- ``sha256_length_extension`` – SHA-256 length extension attack
- ``md5_length_extension``    – MD5 length extension attack

Internal helpers (SHA-1, SHA-256, MD5 compression functions) are also exposed
for advanced use via ``sha1_extend`` and ``sha256_extend``.
"""

from __future__ import annotations

import struct

# =============================================================================
# Merkle-Damgård Padding
# =============================================================================


def md_pad(data_len: int, endian: str = "<") -> bytes:
    """Computes Merkle-Damgård padding for a given byte length.

    endian: '<' for MD5 (little-endian length), '>' for SHA-1/SHA-256 (big-endian length).
    """
    pad = b"\x80"
    total_len = data_len + 1
    rem = total_len % 64
    if rem <= 56:
        pad += b"\x00" * (56 - rem)
    else:
        pad += b"\x00" * (64 + 56 - rem)
    bit_len = data_len * 8
    pad += struct.pack(f"{endian}Q", bit_len)
    return pad


def md_padding(message_len: int, endian: str = "big") -> bytes:
    """Compute the Merkle-Damgård padding for a message of *message_len* bytes.

    The padding consists of:
    1. A ``0x80`` byte.
    2. Enough ``0x00`` bytes so that the total (message + padding) length is
       congruent to 56 mod 64.
    3. The original message bit-length as a 64-bit integer.

    Parameters
    ----------
    message_len : int
        Length of the original message in bytes.
    endian : str
        ``'big'`` for SHA-family (big-endian 64-bit length) or ``'little'``
        for MD5 (little-endian 64-bit length).

    Returns
    -------
    bytes
        The padding bytes that would follow the message.
    """
    fmt = ">" if endian == "big" else "<"
    return md_pad(message_len, endian=fmt)


# =============================================================================
# SHA-1 Length Extension
# =============================================================================


def _sha1_process_block(block: bytes, state: list[int]) -> list[int]:
    """Applies SHA-1 compression function to a single 64-byte block."""
    h = list(state)
    w = list(struct.unpack(">16I", block)) + [0] * 64

    for i in range(16, 80):
        w[i] = (
            (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]) << 1
            | (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]) >> 31
        ) & 0xFFFFFFFF

    a, b, c, d, e = h

    for i in range(80):
        if i < 20:
            f = (b & c) | ((~b) & d)
            k = 0x5A827999
        elif i < 40:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif i < 60:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d
            k = 0xCA62C1D6

        temp = ((((a << 5) | (a >> 27)) & 0xFFFFFFFF) + f + e + k + w[i]) & 0xFFFFFFFF
        e = d
        d = c
        c = ((b << 30) | (b >> 2)) & 0xFFFFFFFF
        b = a
        a = temp

    return [
        (h[0] + a) & 0xFFFFFFFF,
        (h[1] + b) & 0xFFFFFFFF,
        (h[2] + c) & 0xFFFFFFFF,
        (h[3] + d) & 0xFFFFFFFF,
        (h[4] + e) & 0xFFFFFFFF,
    ]


def sha1_extend(
    original_hash: str,
    original_data_len: int,
    data_to_append: bytes,
) -> tuple[str, bytes]:
    """Performs SHA-1 length extension attack.

    Returns (forged_hash_hex, payload_to_append).
    """
    # 1. Unpack original hash into internal state (5 x 32-bit big-endian)
    state = list(struct.unpack(">5I", bytes.fromhex(original_hash)))

    # 2. Compute glue padding
    glue_padding = md_pad(original_data_len, endian=">")

    # 3. New message block starts after original_data + glue_padding
    new_total_len = original_data_len + len(glue_padding) + len(data_to_append)
    append_stream = data_to_append + md_pad(new_total_len, endian=">")

    # 4. Process appended stream block-by-block starting from injected state
    for i in range(0, len(append_stream), 64):
        block = append_stream[i : i + 64]
        state = _sha1_process_block(block, state)

    forged_hash = "".join(f"{x:08x}" for x in state)
    payload_to_append = glue_padding + data_to_append
    return forged_hash, payload_to_append


# =============================================================================
# SHA-256 Length Extension
# =============================================================================

_K256 = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]


def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _sha256_process_block(block: bytes, state: list[int]) -> list[int]:
    """Applies SHA-256 compression function to a 64-byte block."""
    w = list(struct.unpack(">16I", block)) + [0] * 48
    for i in range(16, 64):
        s0 = _rotr32(w[i - 15], 7) ^ _rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr32(w[i - 2], 17) ^ _rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

    a, b, c, d, e, f, g, h = state
    for i in range(64):
        s1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
        ch = (e & f) ^ ((~e) & g)
        temp1 = (h + s1 + ch + _K256[i] + w[i]) & 0xFFFFFFFF
        s0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (s0 + maj) & 0xFFFFFFFF

        h = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF

    return [(state[i] + val) & 0xFFFFFFFF for i, val in enumerate([a, b, c, d, e, f, g, h])]


def sha256_extend(
    original_hash: str,
    original_data_len: int,
    data_to_append: bytes,
) -> tuple[str, bytes]:
    """Performs SHA-256 length extension attack.

    Returns (forged_hash_hex, payload_to_append).
    """
    state = list(struct.unpack(">8I", bytes.fromhex(original_hash)))
    glue_padding = md_pad(original_data_len, endian=">")

    new_total_len = original_data_len + len(glue_padding) + len(data_to_append)
    append_stream = data_to_append + md_pad(new_total_len, endian=">")

    for i in range(0, len(append_stream), 64):
        block = append_stream[i : i + 64]
        state = _sha256_process_block(block, state)

    forged_hash = "".join(f"{x:08x}" for x in state)
    payload_to_append = glue_padding + data_to_append
    return forged_hash, payload_to_append


def sha256_length_extension(
    known_hash_hex: str,
    known_data: bytes,
    secret_len: int,
    extra_data: bytes,
) -> tuple[str, bytes]:
    """SHA-256 length extension attack — high-level interface.

    Given ``H(secret || known_data)`` and the length of the secret, computes
    ``H(secret || known_data || glue_padding || extra_data)`` **without
    knowing the secret**.

    Parameters
    ----------
    known_hash_hex : str
        Hex-encoded SHA-256 digest of ``secret || known_data``.
    known_data : bytes
        The known portion of the original message (everything after the secret).
    secret_len : int
        Length of the unknown secret prefix in bytes.
    extra_data : bytes
        Additional data to append after the glue padding.

    Returns
    -------
    tuple[str, bytes]
        ``(forged_hash_hex, forged_message_without_secret)`` where
        *forged_message_without_secret* is
        ``known_data || glue_padding || extra_data``.
    """
    original_msg_len = secret_len + len(known_data)

    # Compute glue padding that the original hash would have used
    glue_padding = md_pad(original_msg_len, endian=">")

    # Total length the hash engine has processed so far
    padded_len = original_msg_len + len(glue_padding)

    # Inject the known hash as the SHA-256 internal state and process
    # extra_data with the correct running byte count
    state = list(struct.unpack(">8I", bytes.fromhex(known_hash_hex)))

    # Build the data stream for the new blocks: extra_data + its own padding
    new_total_len = padded_len + len(extra_data)
    append_stream = extra_data + md_pad(new_total_len, endian=">")

    for i in range(0, len(append_stream), 64):
        block = append_stream[i : i + 64]
        state = _sha256_process_block(block, state)

    forged_hash = "".join(f"{x:08x}" for x in state)
    forged_message = known_data + glue_padding + extra_data
    return forged_hash, forged_message


# =============================================================================
# MD5 Length Extension
# =============================================================================

# MD5 round constants: T[i] = floor(2^32 * abs(sin(i + 1)))
_T_MD5 = [
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
]

# Per-round shift amounts
_S_MD5 = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
]


def _rotl32(x: int, n: int) -> int:
    """32-bit left rotate."""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _md5_process_block(block: bytes, state: list[int]) -> list[int]:
    """Applies MD5 compression function to a single 64-byte block.

    Parameters
    ----------
    block : bytes
        Exactly 64 bytes of data.
    state : list[int]
        Current MD5 state ``[a, b, c, d]`` — four 32-bit words.

    Returns
    -------
    list[int]
        Updated state after processing the block.
    """
    # Decode block into 16 little-endian 32-bit words
    m = list(struct.unpack("<16I", block))

    a, b, c, d = state

    for i in range(64):
        if i < 16:
            f = (b & c) | ((~b) & d)
            g = i
        elif i < 32:
            f = (d & b) | ((~d) & c)
            g = (5 * i + 1) % 16
        elif i < 48:
            f = b ^ c ^ d
            g = (3 * i + 5) % 16
        else:
            f = c ^ (b | (~d))
            g = (7 * i) % 16

        f = (f + a + _T_MD5[i] + m[g]) & 0xFFFFFFFF
        a = d
        d = c
        c = b
        b = (b + _rotl32(f, _S_MD5[i])) & 0xFFFFFFFF

    return [
        (state[0] + a) & 0xFFFFFFFF,
        (state[1] + b) & 0xFFFFFFFF,
        (state[2] + c) & 0xFFFFFFFF,
        (state[3] + d) & 0xFFFFFFFF,
    ]


def md5_length_extension(
    known_hash_hex: str,
    known_data: bytes,
    secret_len: int,
    extra_data: bytes,
) -> tuple[str, bytes]:
    """MD5 length extension attack.

    Given ``MD5(secret || known_data)`` and the length of the secret, computes
    ``MD5(secret || known_data || glue_padding || extra_data)`` **without
    knowing the secret**.

    Parameters
    ----------
    known_hash_hex : str
        Hex-encoded MD5 digest of ``secret || known_data``.
    known_data : bytes
        The known portion of the original message (after the secret).
    secret_len : int
        Length of the unknown secret prefix in bytes.
    extra_data : bytes
        Additional data to append after the glue padding.

    Returns
    -------
    tuple[str, bytes]
        ``(forged_hash_hex, forged_message_without_secret)`` where
        *forged_message_without_secret* is
        ``known_data || glue_padding || extra_data``.
    """
    original_msg_len = secret_len + len(known_data)

    # Glue padding uses little-endian length for MD5
    glue_padding = md_pad(original_msg_len, endian="<")

    # Total length the MD5 engine has processed so far
    padded_len = original_msg_len + len(glue_padding)

    # Inject the known hash as MD5 internal state (4 x 32-bit LE words)
    state = list(struct.unpack("<4I", bytes.fromhex(known_hash_hex)))

    # Build new data stream: extra_data + its own MD5 padding
    new_total_len = padded_len + len(extra_data)
    append_stream = extra_data + md_pad(new_total_len, endian="<")

    for i in range(0, len(append_stream), 64):
        block = append_stream[i : i + 64]
        state = _md5_process_block(block, state)

    # MD5 digest is the state words in little-endian
    forged_hash = struct.pack("<4I", *state).hex()
    forged_message = known_data + glue_padding + extra_data
    return forged_hash, forged_message
