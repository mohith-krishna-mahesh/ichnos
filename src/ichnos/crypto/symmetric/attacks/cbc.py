"""Cipher Block Chaining (CBC) cryptanalysis tools.

Provides:
- Bit-flipping attack across block boundaries
- Vaudenay PKCS#7 padding oracle block decryptor
- IV=Key recovery via C1 || 0 || C1
"""

from __future__ import annotations

from typing import Callable


def cbc_bit_flip(
    ciphertext: bytes,
    block_index: int,
    byte_offset: int,
    original_val: int,
    target_val: int,
    block_size: int = 16,
) -> bytes:
    """Flips bits in the preceding block (block_index - 1) to alter plaintext in block_index.

    In CBC decryption: P[i] = D(C[i]) ^ C[i-1].
    To change P[i][k] from original_val to target_val, set C[i-1][k] ^= original_val ^ target_val.
    """
    if block_index <= 0:
        raise ValueError("block_index must be >= 1 (cannot flip bits before IV/block 0)")

    prev_block_offset = (block_index - 1) * block_size + byte_offset
    if prev_block_offset >= len(ciphertext):
        raise IndexError("Target byte offset out of range")

    ct_bytes = bytearray(ciphertext)
    ct_bytes[prev_block_offset] ^= original_val ^ target_val
    return bytes(ct_bytes)


def cbc_padding_oracle(
    oracle_fn: Callable[[bytes, bytes], bool],
    iv: bytes,
    ciphertext: bytes,
    block_size: int = 16,
) -> bytes:
    """Decodes ciphertext using a CBC padding oracle (oracle returns True if padding is valid).

    oracle_fn signature: oracle_fn(iv, ciphertext) -> bool
    """
    blocks = [iv] + [ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)]
    plaintext = bytearray()

    for b_idx in range(1, len(blocks)):
        prev_block = bytearray(blocks[b_idx - 1])
        target_block = blocks[b_idx]
        recovered_intermediate = [0] * block_size

        block_pt = [0] * block_size
        for byte_idx in range(block_size - 1, -1, -1):
            pad_val = block_size - byte_idx

            crafted_prev = bytearray(prev_block)
            for k in range(byte_idx + 1, block_size):
                crafted_prev[k] = recovered_intermediate[k] ^ pad_val

            found_val = None
            for cand in range(256):
                crafted_prev[byte_idx] = cand
                try:
                    if oracle_fn(bytes(crafted_prev), bytes(target_block)):
                        # If pad_val == 1, ensure it's not accidental 0x02 0x02
                        if pad_val == 1 and byte_idx > 0:
                            crafted_prev[byte_idx - 1] ^= 1
                            valid = oracle_fn(bytes(crafted_prev), bytes(target_block))
                            crafted_prev[byte_idx - 1] ^= 1
                            if not valid:
                                continue
                        found_val = cand
                        break
                except Exception:
                    continue

            if found_val is not None:
                intermediate_byte = found_val ^ pad_val
                recovered_intermediate[byte_idx] = intermediate_byte
                pt_byte = intermediate_byte ^ prev_block[byte_idx]
                block_pt[byte_idx] = pt_byte
            else:
                block_pt[byte_idx] = ord("?")

        plaintext.extend(block_pt)

    # Unpad PKCS#7 if valid
    if plaintext:
        pad_len = plaintext[-1]
        if 1 <= pad_len <= block_size and all(b == pad_len for b in plaintext[-pad_len:]):
            return bytes(plaintext[:-pad_len])

    return bytes(plaintext)


def cbc_recover_key_iv_reuse(
    oracle_decrypt: Callable[[bytes, bytes], bytes],
    ct_block1: bytes,
    block_size: int = 16,
) -> bytes:
    """Recovers the key when IV = Key in CBC mode.

    Sends (C1 || 0 || C1) to decryption oracle.
    P1 = D(C1) ^ Key
    P3 = D(C1) ^ 0 = D(C1)
    Key = P1 ^ P3
    """
    zero_block = b"\x00" * block_size
    crafted_ct = ct_block1 + zero_block + ct_block1
    pt = oracle_decrypt(ct_block1, crafted_ct)
    p1 = pt[:block_size]
    p3 = pt[2 * block_size : 3 * block_size]
    return bytes([a ^ b for a, b in zip(p1, p3)])
