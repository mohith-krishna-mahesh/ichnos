"""Modern symmetric cryptanalysis tools: ECB recovery, CBC bit flipping, and padding oracles."""

from __future__ import annotations

from typing import Any, Callable


def detect_ecb(ciphertext: bytes, block_size: int = 16) -> bool:
    """Detects Electronic Codebook (ECB) mode encryption by checking for repeated blocks."""
    if len(ciphertext) < block_size * 2:
        return False
    blocks = [ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)]
    return len(blocks) != len(set(blocks))


def count_duplicate_blocks(ciphertext: bytes, block_size: int = 16) -> int:
    """Counts the number of duplicate blocks in ciphertext."""
    if len(ciphertext) < block_size:
        return 0
    blocks = [ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)]
    return len(blocks) - len(set(blocks))


def cbc_bit_flip(
    ciphertext: bytes,
    block_index: int,
    byte_offset: int,
    original_val: int,
    target_val: int,
) -> bytes:
    """Flips bits in the preceding block (block_index - 1) to alter plaintext in block_index.

    In CBC decryption: P[i] = D(C[i]) ^ C[i-1].
    To change P[i][k] from original_val to target_val, set C[i-1][k] ^= original_val ^ target_val.
    """
    if block_index <= 0:
        raise ValueError("block_index must be >= 1 (cannot flip bits before IV/block 0)")

    block_size = 16
    prev_block_offset = (block_index - 1) * block_size + byte_offset
    if prev_block_offset >= len(ciphertext):
        raise IndexError("Target byte offset out of range")

    ct_bytes = bytearray(ciphertext)
    ct_bytes[prev_block_offset] ^= original_val ^ target_val
    return bytes(ct_bytes)


def ecb_byte_at_a_time(
    oracle_fn: Callable[[bytes], bytes],
    block_size: int = 16,
    max_len: int = 64,
) -> bytes:
    """Recovers hidden suffix in an ECB encryption oracle using byte-at-a-time chosen plaintext attack."""
    recovered = bytearray()

    for target_idx in range(max_len):
        pad_len = block_size - 1 - (target_idx % block_size)
        pad = b"A" * pad_len
        target_block_idx = (len(recovered) + pad_len) // block_size

        try:
            target_ct = oracle_fn(pad)
        except Exception:
            break

        target_block = target_ct[
            target_block_idx * block_size : (target_block_idx + 1) * block_size
        ]

        found_byte = None
        for cand in range(256):
            probe = pad + bytes(recovered) + bytes([cand])
            try:
                probe_ct = oracle_fn(probe)
            except Exception:
                continue
            probe_block = probe_ct[
                target_block_idx * block_size : (target_block_idx + 1) * block_size
            ]
            if probe_block == target_block:
                found_byte = cand
                break

        if found_byte is None:
            break
        recovered.append(found_byte)

    return bytes(recovered)


def padding_oracle_decrypt(
    oracle_fn: Callable[[bytes, bytes], bool],
    iv: bytes,
    ciphertext: bytes,
    block_size: int = 16,
) -> bytes:
    """Decodes ciphertext using a CBC padding oracle (oracle returns True if padding is valid)."""
    blocks = [iv] + [ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)]
    plaintext = bytearray()

    for b_idx in range(1, len(blocks)):
        prev_block = blocks[b_idx - 1]
        cur_block = blocks[b_idx]
        d_block = [0] * block_size

        for byte_idx in range(block_size - 1, -1, -1):
            pad_val = block_size - byte_idx
            fake_prev = bytearray(prev_block)

            # Set already recovered trailing bytes to produce pad_val
            for k in range(byte_idx + 1, block_size):
                fake_prev[k] = d_block[k] ^ pad_val

            found = False
            for cand in range(256):
                fake_prev[byte_idx] = cand
                if oracle_fn(bytes(fake_prev), cur_block):
                    # Check against false positive (e.g. 0x02 0x02)
                    if byte_idx == block_size - 1:
                        fake_prev[byte_idx - 1] ^= 1
                        if not oracle_fn(bytes(fake_prev), cur_block):
                            continue
                    d_block[byte_idx] = cand ^ pad_val
                    plaintext.append(d_block[byte_idx] ^ prev_block[byte_idx])
                    found = True
                    break

            if not found:
                plaintext.append(ord("?"))

    # Strip PKCS#7 padding if valid
    if plaintext and 1 <= plaintext[-1] <= block_size:
        pad_len = plaintext[-1]
        if all(x == pad_len for x in plaintext[-pad_len:]):
            return bytes(plaintext[:-pad_len])

    return bytes(plaintext)


def detect_block_cipher_weakness(ciphertext: bytes, block_size: int = 16) -> dict[str, Any]:
    """Analyzes ciphertext for common block cipher vulnerabilities."""
    dup_count = count_duplicate_blocks(ciphertext, block_size)
    is_ecb = dup_count > 0
    length_aligned = len(ciphertext) % block_size == 0

    return {
        "length": len(ciphertext),
        "block_size": block_size,
        "is_aligned": length_aligned,
        "duplicate_blocks": dup_count,
        "likely_ecb": is_ecb,
        "recommendation": (
            "Vulnerable to ECB replay/block reordering attacks"
            if is_ecb
            else "No immediate ECB repetition detected"
        ),
    }
