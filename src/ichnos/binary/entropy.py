"""Entropy analysis."""

from __future__ import annotations

from ichnos.core.detection import is_likely_encrypted, shannon_entropy


def whole_file_entropy(data: bytes) -> float:
    return shannon_entropy(data)


def sliding_window_entropy(
    data: bytes, window_size: int = 256, step: int | None = None
) -> list[tuple[int, float]]:
    if step is None:
        step = max(1, window_size // 4)
    results = []
    for i in range(0, max(1, len(data) - window_size + 1), step):
        chunk = data[i : i + window_size]
        results.append((i, shannon_entropy(chunk)))
    return results


def entropy_summary(data: bytes) -> dict:
    overall = whole_file_entropy(data)
    windows = sliding_window_entropy(data)
    high_regions = []
    in_high = False
    start = 0
    last_end = 0
    max_ent = 0.0

    for offset, ent in windows:
        if ent > 7.0:
            if not in_high:
                start = offset
                in_high = True
                max_ent = ent
            else:
                max_ent = max(max_ent, ent)
            last_end = offset + 256
        else:
            if in_high:
                high_regions.append((start, last_end, max_ent))
                in_high = False

    if in_high:
        high_regions.append((start, last_end, max_ent))

    return {
        "entropy": overall,
        "overall_entropy": overall,
        "likely_encrypted": is_likely_encrypted(data),
        "likely_packed": overall > 7.2 and overall < 7.99,
        "high_entropy_regions": high_regions,
    }
