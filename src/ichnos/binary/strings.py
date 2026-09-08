"""Extract strings from binary data."""

from __future__ import annotations


def extract_ascii(data: bytes, min_length: int = 4) -> list[tuple[int, str]]:
    results = []
    current_str = []
    start_offset = 0
    for i, b in enumerate(data):
        if 0x20 <= b <= 0x7E:
            if not current_str:
                start_offset = i
            current_str.append(chr(b))
        else:
            if len(current_str) >= min_length:
                results.append((start_offset, "".join(current_str)))
            current_str = []
    if len(current_str) >= min_length:
        results.append((start_offset, "".join(current_str)))
    return results


def extract_utf16le(data: bytes, min_length: int = 4) -> list[tuple[int, str]]:
    results = []
    current_str = []
    start_offset = 0
    i = 0
    while i < len(data) - 1:
        if 0x20 <= data[i] <= 0x7E and data[i + 1] == 0:
            if not current_str:
                start_offset = i
            current_str.append(chr(data[i]))
            i += 2
        else:
            if len(current_str) >= min_length:
                results.append((start_offset, "".join(current_str)))
            current_str = []
            i += 1
    if len(current_str) >= min_length:
        results.append((start_offset, "".join(current_str)))
    return results


def extract_utf16be(data: bytes, min_length: int = 4) -> list[tuple[int, str]]:
    results = []
    current_str = []
    start_offset = 0
    i = 0
    while i < len(data) - 1:
        if data[i] == 0 and 0x20 <= data[i + 1] <= 0x7E:
            if not current_str:
                start_offset = i
            current_str.append(chr(data[i + 1]))
            i += 2
        else:
            if len(current_str) >= min_length:
                results.append((start_offset, "".join(current_str)))
            current_str = []
            i += 1
    if len(current_str) >= min_length:
        results.append((start_offset, "".join(current_str)))
    return results


def extract_all(
    data: bytes, min_length: int = 4, encoding: str = "all"
) -> list[tuple[int, str, str]]:
    all_strings = []
    if encoding in ("all", "ascii"):
        all_strings.extend([(o, s, "ascii") for o, s in extract_ascii(data, min_length)])
    if encoding in ("all", "utf16le"):
        all_strings.extend([(o, s, "utf16le") for o, s in extract_utf16le(data, min_length)])
    if encoding in ("all", "utf16be"):
        all_strings.extend([(o, s, "utf16be") for o, s in extract_utf16be(data, min_length)])
    all_strings.sort(key=lambda x: x[0])
    return all_strings
