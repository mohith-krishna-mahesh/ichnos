from __future__ import annotations


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte sequences, truncated to the length of the shorter one."""
    return bytes(x ^ y for x, y in zip(a, b))


def crib_drag(ct1: bytes, ct2: bytes, crib: str) -> list[tuple[int, str]]:
    """
    XOR ct1 and ct2, then slide crib across the resulting stream.
    Report positions where the resulting text is mostly printable.
    """
    stream = xor_bytes(ct1, ct2)
    crib_bytes = crib.encode("ascii", errors="ignore")
    results = []

    for i in range(len(stream) - len(crib_bytes) + 1):
        chunk = stream[i : i + len(crib_bytes)]
        dec = xor_bytes(chunk, crib_bytes)

        # Check if mostly printable
        printable_count = sum(1 for b in dec if 32 <= b <= 126 or b in (9, 10, 13))
        if printable_count >= len(dec) * 0.8:  # 80% threshold
            try:
                results.append((i, dec.decode("ascii", errors="replace")))
            except Exception:
                pass

    return results


def batch_crib_drag(
    ciphertexts: list[bytes], crib: str
) -> dict[tuple[int, int], list[tuple[int, str]]]:
    """Perform crib dragging across all pairs of ciphertexts."""
    results = {}
    for i in range(len(ciphertexts)):
        for j in range(i + 1, len(ciphertexts)):
            drag_res = crib_drag(ciphertexts[i], ciphertexts[j], crib)
            if drag_res:
                results[(i, j)] = drag_res
    return results
