"""Stream cipher and CTR mode cryptanalysis: Reused nonce & Multi-Time Pad attacks.

When two or more messages are encrypted under the same keystream:
C1 ^ C2 = P1 ^ P2
Provides automated crib dragging and statistical space frequency recovery.
"""

from __future__ import annotations

from ichnos.core.detection import printable_ratio


def crib_drag_stream(ct1: bytes, ct2: bytes, crib: bytes) -> list[tuple[int, bytes]]:
    """Slides a crib over ct1 ^ ct2, returning offsets where the resulting XOR is mostly printable ASCII."""
    xored = bytes([a ^ b for a, b in zip(ct1, ct2)])
    results = []
    crib_len = len(crib)

    for offset in range(len(xored) - crib_len + 1):
        segment = xored[offset : offset + crib_len]
        pt_guess = bytes([s ^ c for s, c in zip(segment, crib)])
        if printable_ratio(pt_guess) >= 0.85:
            results.append((offset, pt_guess))

    return results


def multi_time_pad_space_crack(ciphertexts: list[bytes]) -> bytes:
    """Recovers keystream from multiple ciphertexts sharing a keystream via space character frequency analysis.

    In ASCII, space (0x20) XOR lowercase letter (0x61-0x7A) produces uppercase letter (0x41-0x5A) or vice-versa.
    """
    if not ciphertexts:
        return b""

    max_len = max(len(c) for c in ciphertexts)
    recovered_keystream = bytearray()

    for col in range(max_len):
        col_bytes = [c[col] for c in ciphertexts if col < len(c)]
        if len(col_bytes) < 3:
            recovered_keystream.append(0)
            continue

        best_k = None
        best_score = -1

        for candidate_k in range(256):
            # Check how many decryptions are valid ASCII letters or punctuation
            score = 0
            for b in col_bytes:
                dec = b ^ candidate_k
                if 0x20 <= dec <= 0x7E:
                    score += 1
                    if dec == 0x20 or (0x61 <= dec <= 0x7A) or (0x41 <= dec <= 0x5A):
                        score += 1

            if score > best_score:
                best_score = score
                best_k = candidate_k

        recovered_keystream.append(best_k if best_k is not None else 0)

    return bytes(recovered_keystream)


def break_reused_nonce(ciphertexts: list[bytes], crib: str = "FLAG") -> list[str]:
    """Breaks multiple ciphertexts encrypted with a reused nonce/keystream."""
    keystream = multi_time_pad_space_crack(ciphertexts)
    results = []

    for ct in ciphertexts:
        dec = bytes([c ^ k for c, k in zip(ct, keystream)])
        try:
            results.append(dec.decode("latin-1"))
        except Exception:
            results.append(dec.hex())

    return results
