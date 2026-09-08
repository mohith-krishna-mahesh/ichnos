"""Extractor for QR codes and binary module grids concealed within Substation Alpha (.ass) subtitle files."""

from __future__ import annotations

import re
import struct
import zlib
from pathlib import Path
from typing import Any

DIALOGUE_RE = re.compile(r"^Dialogue:\s*(\d+),[^\n]*?,,(.*)$", re.M)
DRAW_BLOCK_RE = re.compile(r"\\p1\}(.*?)\{\\p0\}", re.S)
MOVE_POINT_RE = re.compile(r"m\s+(\d+)\s+(\d+)")


def extract_layers(content: str) -> dict[int, list[tuple[int, int]]]:
    """Extracts module anchor coordinates grouped by Dialogue layer number.

    Falls back to individual drawing block pseudo-layers if no formal
    Dialogue lines are found.
    """
    layers: dict[int, list[tuple[int, int]]] = {}
    dialogue_lines = DIALOGUE_RE.findall(content)

    if dialogue_lines:
        for layer_str, text in dialogue_lines:
            layer = int(layer_str)
            points: list[tuple[int, int]] = []
            for block in DRAW_BLOCK_RE.findall(text):
                points += [(int(x), int(y)) for x, y in MOVE_POINT_RE.findall(block)]
            if points:
                layers.setdefault(layer, []).extend(points)
    else:
        for idx, block in enumerate(DRAW_BLOCK_RE.findall(content)):
            points = [(int(x), int(y)) for x, y in MOVE_POINT_RE.findall(block)]
            if points:
                layers[idx] = points

    return layers


def detect_unit(points: list[tuple[int, int]], fallback: int = 21) -> int:
    """Estimates the QR module unit size in pixels via smallest coordinate delta."""
    coords = sorted({x for x, _ in points} | {y for _, y in points})
    gaps = [b - a for a, b in zip(coords, coords[1:]) if b - a > 0]
    return min(gaps) if gaps else fallback


def points_to_grid(
    points: list[tuple[int, int]], unit: int, canvas: int
) -> list[list[int]]:
    """Projects pixel coordinates into a discrete 2D binary matrix grid."""
    grid = [[0] * canvas for _ in range(canvas)]
    for x, y in points:
        c, r = x // unit, y // unit
        if 0 <= r < canvas and 0 <= c < canvas:
            grid[r][c] = 1
    return grid


def merge_or(grids: dict[int, list[list[int]]]) -> list[list[int]]:
    """Combines multiple layer grids via bitwise OR."""
    canvas = len(next(iter(grids.values())))
    merged = [[0] * canvas for _ in range(canvas)]
    for g in grids.values():
        for r in range(canvas):
            for c in range(canvas):
                merged[r][c] |= g[r][c]
    return merged


def merge_xor(
    grids: dict[int, list[list[int]]], min_trivial: int = 5
) -> list[list[int]] | None:
    """Combines the two primary non-trivial layer grids via bitwise XOR."""
    non_trivial = [g for g in grids.values() if sum(sum(row) for row in g) > min_trivial]
    if len(non_trivial) < 2:
        return None
    canvas = len(non_trivial[0])
    a, b = non_trivial[0], non_trivial[1]
    return [[a[r][c] ^ b[r][c] for c in range(canvas)] for r in range(canvas)]


def grid_to_png(grid: list[list[int]], scale: int = 10) -> bytes:
    """Renders a 2D binary grid to a valid grayscale PNG byte buffer without external imaging libraries."""
    canvas = len(grid)
    width = canvas * scale
    height = canvas * scale

    raw_scanlines = bytearray()
    for r in range(canvas):
        line = bytearray([0])  # filter byte: 0 (None)
        for c in range(canvas):
            # Inverted: 1 (active QR module) is black (0), 0 (background) is white (255)
            val = 0 if grid[r][c] else 255
            line.extend([val] * scale)
        for _ in range(scale):
            raw_scanlines.extend(line)

    png = bytearray(b"\x89PNG\r\n\x1a\n")
    # IHDR: width, height, 8-bit depth, grayscale (color type 0)
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data)
    png.extend(struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc))

    # IDAT
    compressed = zlib.compress(bytes(raw_scanlines))
    idat_crc = zlib.crc32(b"IDAT" + compressed)
    png.extend(struct.pack(">I", len(compressed)) + b"IDAT" + compressed + struct.pack(">I", idat_crc))

    # IEND
    iend_crc = zlib.crc32(b"IEND")
    png.extend(struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc))

    return bytes(png)


def decode_qr_from_grid(grid: list[list[int]], scale: int = 10) -> str | None:
    """Attempts to decode a QR code from a binary grid using zxing-cpp."""
    try:
        import zxingcpp
    except ImportError:
        return None

    canvas = len(grid)
    h = canvas * scale
    w = canvas * scale

    buf = bytearray()
    for r in range(canvas):
        line = bytearray()
        for c in range(canvas):
            val = 0 if grid[r][c] else 255
            line.extend([val] * scale)
        for _ in range(scale):
            buf.extend(line)

    # Cast 1D bytearray into a 2D grayscale memoryview conforming to buffer protocol
    mv = memoryview(buf).cast("B", shape=(h, w))
    try:
        result = zxingcpp.read_barcode(mv)
        if result and result.text:
            return result.text
    except Exception:
        pass

    return None


def extract_and_decode_ass(
    content: str,
    merge: str = "or",
    unit: int | None = None,
    canvas: int | None = None,
    scale: int = 10,
    min_trivial: int = 5,
    out_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Processes subtitle content, recovers vector layers, renders grids, and decodes QR codes."""
    layers = extract_layers(content)
    if not layers:
        return {"error": "No drawing blocks found (expected \\p1{...}{\\p0})", "layers_found": 0}

    all_points = [p for pts in layers.values() for p in pts]
    est_unit = unit or detect_unit(all_points)
    est_canvas = canvas or (max(max(x, y) for x, y in all_points) // est_unit + 1)

    grids: dict[int, list[list[int]]] = {}
    saved_files: list[str] = []
    decoded_qr: str | None = None

    dest_dir = Path(out_dir) if out_dir else None
    if dest_dir:
        dest_dir.mkdir(parents=True, exist_ok=True)

    for layer, pts in layers.items():
        g = points_to_grid(pts, est_unit, est_canvas)
        grids[layer] = g
        if dest_dir:
            png_bytes = grid_to_png(g, scale=scale)
            out_file = dest_dir / f"layer_{layer}.png"
            out_file.write_bytes(png_bytes)
            saved_files.append(str(out_file))

        # Check individual layer for QR
        if not decoded_qr:
            decoded_qr = decode_qr_from_grid(g, scale=scale)

    significant = {l: g for l, g in grids.items() if sum(sum(row) for row in g) > min_trivial}

    merged = None
    if merge == "or" and significant:
        merged = merge_or(significant)
    elif merge == "xor":
        merged = merge_xor(grids, min_trivial=min_trivial)

    if merged:
        if dest_dir:
            png_bytes = grid_to_png(merged, scale=scale)
            merged_file = dest_dir / f"qr_merged_{merge}.png"
            merged_file.write_bytes(png_bytes)
            saved_files.append(str(merged_file))

        qr_text = decode_qr_from_grid(merged, scale=scale)
        if qr_text:
            decoded_qr = qr_text

    return {
        "layers_count": len(layers),
        "unit": est_unit,
        "canvas": est_canvas,
        "decoded_qr": decoded_qr,
        "merged_strategy": merge if merged else None,
        "saved_files": saved_files,
    }


def decode_ass_qr(content: str) -> str | None:
    """Convenience helper to extract and decode QR code from ASS subtitle content."""
    res_or = extract_and_decode_ass(content, merge="or")
    if res_or.get("decoded_qr"):
        return res_or["decoded_qr"]
    res_xor = extract_and_decode_ass(content, merge="xor")
    if res_xor.get("decoded_qr"):
        return res_xor["decoded_qr"]
    return None
