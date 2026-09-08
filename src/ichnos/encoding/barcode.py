"""Barcode and QR code encoding/decoding utilities.

Integrates with zxing-cpp (official Python wrapper) when available,
and provides pure-Python Code 39 1D barcode generation without system dependencies.
"""

from __future__ import annotations

from typing import Any

# =============================================================================
# zxing-cpp Dynamic Wrapper
# =============================================================================


def is_zxing_available() -> bool:
    """Returns True if zxingcpp is installed and importable."""
    try:
        import zxingcpp  # noqa: F401

        return True
    except ImportError:
        return False


def decode_barcode(source: str | bytes) -> list[dict[str, Any]]:
    """Decodes barcodes/QR codes from an image path or raw image bytes.

    Requires zxing-cpp package (`pip install zxing-cpp`).
    Returns list of dicts with keys: 'text', 'format', 'is_valid', 'orientation'.
    """
    try:
        import zxingcpp
    except ImportError as e:
        raise RuntimeError(
            "zxing-cpp is required for barcode decoding. "
            "Install it via: uv add zxing-cpp (or pip install zxing-cpp)"
        ) from e

    # If source is a file path, load and read
    if isinstance(source, str):
        # zxing-cpp read_barcodes can accept PIL Image or image file path directly in newer versions
        try:
            results = zxingcpp.read_barcodes(source)
        except Exception:
            # Fallback if path string isn't directly accepted by C++ wrapper: try image open if available
            try:
                from PIL import Image

                img = Image.open(source)
                results = zxingcpp.read_barcodes(img)
            except ImportError:
                raise RuntimeError(
                    "Could not read image file. Ensure Pillow is installed or pass valid image buffer."
                )

        return [
            {
                "text": r.text,
                "format": str(r.format),
                "is_valid": r.is_valid,
                "orientation": r.orientation,
            }
            for r in results
        ]

    # If source is raw bytes
    raise NotImplementedError(
        "Direct raw byte barcode decoding requires an image container format or path."
    )


# =============================================================================
# Pure-Python Code 39 Barcode Generator (Zero Dependencies)
# =============================================================================

# Standard Code 39 character table: 9 bits per character (5 bars, 4 spaces).
# 1 = Wide element, 0 = Narrow element.
# Odd index = Bar, Even index = Space.
CODE39_PATTERNS: dict[str, str] = {
    "0": "000110100",
    "1": "100100001",
    "2": "001100001",
    "3": "101100000",
    "4": "000110001",
    "5": "100110000",
    "6": "001110000",
    "7": "000100101",
    "8": "100100100",
    "9": "001100100",
    "A": "100001001",
    "B": "001001001",
    "C": "101001000",
    "D": "000011001",
    "E": "100011000",
    "F": "001011000",
    "G": "000001101",
    "H": "100001100",
    "I": "001001100",
    "J": "000011100",
    "K": "100000011",
    "L": "001000011",
    "M": "101000010",
    "N": "000010011",
    "O": "100010010",
    "P": "001010010",
    "Q": "000000111",
    "R": "100000110",
    "S": "001000110",
    "T": "000010110",
    "U": "110000001",
    "V": "011000001",
    "W": "111000000",
    "X": "010010001",
    "Y": "110010000",
    "Z": "011010000",
    "-": "010000101",
    ".": "110000100",
    " ": "011000100",
    "$": "010101000",
    "/": "010100010",
    "+": "010001010",
    "%": "000101010",
    "*": "010010100",  # Start/stop delimiter
}


def encode_code39_pattern(text: str) -> list[tuple[bool, bool]]:
    """Encodes text into a sequence of Code 39 elements.

    Returns a list of tuples: `(is_bar: bool, is_wide: bool)`.
    Automatically encloses text with start/stop delimiter '*'.
    """
    clean_text = f"*{text.upper()}*"
    elements: list[tuple[bool, bool]] = []

    for i, ch in enumerate(clean_text):
        if ch not in CODE39_PATTERNS:
            raise ValueError(f"Character {ch!r} not supported in Code 39")
        pattern = CODE39_PATTERNS[ch]
        for elem_idx, bit in enumerate(pattern):
            is_bar = (elem_idx % 2) == 0
            is_wide = bit == "1"
            elements.append((is_bar, is_wide))
        # Add inter-character gap (narrow space) except after the last character
        if i < len(clean_text) - 1:
            elements.append((False, False))

    return elements


def generate_code39_svg(
    text: str,
    height: int = 80,
    narrow_width: int = 2,
    wide_width: int = 5,
    margin: int = 10,
) -> str:
    """Generates an SVG string representation of a Code 39 barcode."""
    elements = encode_code39_pattern(text)

    # Calculate total width
    total_elements_width = sum(wide_width if is_wide else narrow_width for _, is_wide in elements)
    svg_width = total_elements_width + 2 * margin
    svg_height = height + 2 * margin + 16  # Extra room for text label

    rects = []
    x = margin
    for is_bar, is_wide in elements:
        w = wide_width if is_wide else narrow_width
        if is_bar:
            rects.append(f'<rect x="{x}" y="{margin}" width="{w}" height="{height}" fill="black"/>')
        x += w

    rects_str = "\n  ".join(rects)
    label_x = svg_width / 2
    label_y = margin + height + 14

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{svg_width}" height="{svg_height}" '
        f'viewBox="0 0 {svg_width} {svg_height}">\n'
        f'  <rect width="100%" height="100%" fill="white"/>\n'
        f"  {rects_str}\n"
        f'  <text x="{label_x}" y="{label_y}" font-family="monospace" font-size="12" '
        f'text-anchor="middle" fill="black">*{text.upper()}*</text>\n'
        f"</svg>"
    )
