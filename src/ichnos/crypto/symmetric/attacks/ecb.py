"""Electronic Codebook (ECB) cryptanalysis tools.

Provides:
- Repeated block detection
- Chosen-plaintext byte-at-a-time suffix recovery
- Block cut-and-paste payload construction
"""

from __future__ import annotations

from typing import Callable


def detect_ecb(ciphertext: bytes, block_size: int = 16) -> bool:
    """Detects ECB mode by identifying duplicate blocks in ciphertext."""
    if len(ciphertext) < block_size * 2:
        return False
    blocks = [ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)]
    return len(blocks) != len(set(blocks))


def count_duplicate_blocks(ciphertext: bytes, block_size: int = 16) -> int:
    """Returns the number of duplicate blocks observed in ciphertext."""
    if len(ciphertext) < block_size:
        return 0
    blocks = [ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)]
    return len(blocks) - len(set(blocks))


def crack_ecb_byte_at_a_time(
    oracle_fn: Callable[[bytes], bytes],
    block_size: int = 16,
    max_len: int = 128,
) -> bytes:
    """Recovers hidden suffix from an ECB oracle function using chosen prefix dictionary."""
    recovered = bytearray()

    for target_idx in range(max_len):
        pad_len = block_size - 1 - (target_idx % block_size)
        pad = b"A" * pad_len
        target_block_idx = (len(recovered) + pad_len) // block_size

        try:
            target_ct = oracle_fn(pad)
        except Exception:
            break

        start_off = target_block_idx * block_size
        target_block = target_ct[start_off : start_off + block_size]

        found_byte = None
        for cand in range(256):
            probe = pad + bytes(recovered) + bytes([cand])
            try:
                probe_ct = oracle_fn(probe)
            except Exception:
                continue
            probe_block = probe_ct[start_off : start_off + block_size]
            if probe_block == target_block:
                found_byte = cand
                break

        if found_byte is None:
            break
        recovered.append(found_byte)

    return bytes(recovered)


def ecb_cut_and_paste(
    blocks: list[bytes],
    block_indices: list[int],
) -> bytes:
    """Assembles a new forged ciphertext by rearranging existing ciphertext blocks."""
    out = bytearray()
    for idx in block_indices:
        if 0 <= idx < len(blocks):
            out.extend(blocks[idx])
        else:
            raise IndexError(f"Block index {idx} out of range (total blocks: {len(blocks)})")
    return bytes(out)
