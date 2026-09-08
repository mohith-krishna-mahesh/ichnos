"""Unit tests for ASS subtitle QR and drawing vector extractor."""

from pathlib import Path

from ichnos.stego.ass_subtitle import (
    detect_unit,
    extract_and_decode_ass,
    extract_layers,
    grid_to_png,
    merge_or,
    merge_xor,
    points_to_grid,
)


def test_extract_layers_dialogue():
    ass_content = """
[Script Info]
Title: Test

[Events]
Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
Dialogue: 0,0:00:00.00,0:00:05.00,Default,,0,0,0,,{\\p1}m 10 20 m 30 40{\\p0}
Dialogue: 1,0:00:00.00,0:00:05.00,Default,,0,0,0,,{\\p1}m 50 60{\\p0}
"""
    layers = extract_layers(ass_content)
    assert 0 in layers
    assert 1 in layers
    assert layers[0] == [(10, 20), (30, 40)]
    assert layers[1] == [(50, 60)]


def test_extract_layers_raw_blocks():
    raw_content = "Some text {\\p1}m 100 200{\\p0} other text {\\p1}m 300 400{\\p0}"
    layers = extract_layers(raw_content)
    assert len(layers) == 2
    assert layers[0] == [(100, 200)]
    assert layers[1] == [(300, 400)]


def test_detect_unit():
    points = [(10, 10), (20, 10), (30, 10), (10, 20)]
    unit = detect_unit(points)
    assert unit == 10


def test_points_to_grid():
    points = [(0, 0), (20, 40)]
    unit = 20
    canvas = 3
    grid = points_to_grid(points, unit, canvas)
    assert grid[0][0] == 1
    # (x=20 -> col 1, y=40 -> row 2)
    assert grid[2][1] == 1
    assert grid[1][1] == 0


def test_merge_or_and_xor():
    g1 = [
        [1, 0],
        [0, 1],
    ]
    g2 = [
        [1, 1],
        [0, 0],
    ]
    merged_or = merge_or({0: g1, 1: g2})
    assert merged_or == [
        [1, 1],
        [0, 1],
    ]

    # For merge_xor, min_trivial must be satisfied
    merged_xor = merge_xor({0: g1, 1: g2}, min_trivial=1)
    assert merged_xor == [
        [0, 1],
        [0, 1],
    ]


def test_grid_to_png():
    grid = [
        [1, 0],
        [0, 1],
    ]
    png_bytes = grid_to_png(grid, scale=4)
    assert png_bytes.startswith(b"\x89PNG\r\n\x1a\n")
    assert b"IHDR" in png_bytes
    assert b"IDAT" in png_bytes
    assert b"IEND" in png_bytes


def test_extract_and_decode_ass_e2e(tmp_path: Path):
    ass_data = """
Dialogue: 0,0:00:00.00,0:00:05.00,Default,,0,0,0,,{\\p1}m 0 0 m 10 0 m 0 10 m 10 10{\\p0}
"""
    res = extract_and_decode_ass(
        content=ass_data,
        merge="or",
        unit=10,
        canvas=2,
        out_dir=tmp_path,
    )
    assert res["layers_count"] == 1
    assert res["unit"] == 10
    assert res["canvas"] == 2
    assert len(res["saved_files"]) >= 1
    assert (tmp_path / "layer_0.png").exists()


def test_decode_ass_qr():
    from ichnos.stego.ass_subtitle import decode_ass_qr

    # Non-qr content should return None safely
    assert decode_ass_qr("non qr data") is None
