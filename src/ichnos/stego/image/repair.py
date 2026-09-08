"""
PNG image dimension repair tools for Ichnos stego toolkit.

Detects IHDR CRC mismatches and brute-forces correct width/height values,
a common CTF technique where PNG dimensions are intentionally corrupted
to hide portions of an image.
"""

from __future__ import annotations

import struct
import zlib

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

# IHDR data layout: width(4) + height(4) + bit_depth(1) + color_type(1)
#                   + compression(1) + filter(1) + interlace(1) = 13 bytes
_IHDR_DATA_LEN = 13


def _parse_ihdr(png_data: bytes) -> tuple[bytes, int, int, int]:
    """Extract IHDR chunk components from raw PNG data.

    Returns:
        Tuple of (ihdr_type_and_data, stored_crc, width, height).

    Raises:
        ValueError: If the data is not a valid PNG or IHDR is missing.
    """
    if not png_data.startswith(PNG_SIGNATURE):
        raise ValueError("Invalid PNG signature")

    offset = 8  # skip signature
    if offset + 8 > len(png_data):
        raise ValueError("PNG too short: missing IHDR length/type")

    length = struct.unpack(">I", png_data[offset : offset + 4])[0]
    chunk_type = png_data[offset + 4 : offset + 8]

    if chunk_type != b"IHDR":
        raise ValueError("First chunk is not IHDR")
    if length != _IHDR_DATA_LEN:
        raise ValueError(f"Unexpected IHDR data length: {length}")

    data_start = offset + 8
    data_end = data_start + length
    crc_end = data_end + 4

    if crc_end > len(png_data):
        raise ValueError("PNG truncated in IHDR chunk")

    ihdr_data = png_data[data_start : data_end]
    stored_crc = struct.unpack(">I", png_data[data_end : crc_end])[0]
    type_and_data = chunk_type + ihdr_data

    width, height = struct.unpack(">II", ihdr_data[:8])
    return type_and_data, stored_crc, width, height


def _bytes_per_pixel(color_type: int, bit_depth: int) -> float:
    """Calculate bytes per pixel from PNG color type and bit depth.

    Color type mapping:
        0 (Grayscale)       -> 1 channel
        2 (RGB)             -> 3 channels
        3 (Indexed)         -> 1 byte per pixel (palette index)
        4 (Grayscale+Alpha) -> 2 channels
        6 (RGBA)            -> 4 channels
    """
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
    ch = channels.get(color_type)
    if ch is None:
        raise ValueError(f"Unknown PNG color type: {color_type}")
    if color_type == 3:
        # Indexed color: always 1 byte per pixel regardless of bit depth
        return 1
    return ch * bit_depth / 8


def detect_ihdr_crc_mismatch(png_data: bytes) -> bool:
    """Check if the IHDR chunk's CRC-32 matches the stored CRC.

    Returns:
        True if a mismatch is detected (i.e. the IHDR has been tampered with).
    """
    type_and_data, stored_crc, _, _ = _parse_ihdr(png_data)
    computed_crc = zlib.crc32(type_and_data) & 0xFFFFFFFF
    return computed_crc != stored_crc


def brute_force_png_height(
    png_data: bytes, max_height: int = 4096
) -> tuple[int, int] | None:
    """Brute-force the correct PNG height by recalculating IHDR CRC.

    Iterates candidate heights from 1 to *max_height*, also trying all
    candidate widths would be prohibitively expensive, so width is assumed
    correct and only height is varied.  If no single-height fix is found,
    a second pass tries varying width as well (1..max_width capped at 4096).

    Returns:
        ``(correct_width, correct_height)`` on success, or ``None``.
    """
    if not png_data.startswith(PNG_SIGNATURE):
        return None

    type_and_data, stored_crc, original_width, original_height = _parse_ihdr(png_data)
    ihdr_suffix = type_and_data[12:]  # everything after width+height (5 bytes)

    # Pass 1: vary height only, keep original width
    for candidate_h in range(1, max_height + 1):
        candidate_data = (
            b"IHDR"
            + struct.pack(">I", original_width)
            + struct.pack(">I", candidate_h)
            + ihdr_suffix
        )
        if zlib.crc32(candidate_data) & 0xFFFFFFFF == stored_crc:
            return (original_width, candidate_h)

    # Pass 2: vary width as well (slower, but covers width-tampered PNGs)
    max_width = 4096
    for candidate_w in range(1, max_width + 1):
        if candidate_w == original_width:
            continue  # already checked in pass 1
        for candidate_h in range(1, max_height + 1):
            candidate_data = (
                b"IHDR"
                + struct.pack(">I", candidate_w)
                + struct.pack(">I", candidate_h)
                + ihdr_suffix
            )
            if zlib.crc32(candidate_data) & 0xFFFFFFFF == stored_crc:
                return (candidate_w, candidate_h)

    return None


def repair_png_dimensions(png_data: bytes) -> tuple[bytes, dict]:
    """Detect CRC mismatch and brute-force correct dimensions.

    Returns:
        A tuple of ``(repaired_png_bytes, info_dict)`` where *info_dict*
        contains the keys ``original_width``, ``original_height``,
        ``correct_width``, ``correct_height``, and ``repaired`` (bool).
    """
    _, stored_crc, original_width, original_height = _parse_ihdr(png_data)

    info: dict = {
        "original_width": original_width,
        "original_height": original_height,
        "correct_width": original_width,
        "correct_height": original_height,
        "repaired": False,
    }

    if not detect_ihdr_crc_mismatch(png_data):
        return png_data, info

    result = brute_force_png_height(png_data)
    if result is None:
        return png_data, info

    correct_width, correct_height = result
    info["correct_width"] = correct_width
    info["correct_height"] = correct_height
    info["repaired"] = True

    # Reconstruct the IHDR chunk with corrected dimensions
    ihdr_type_and_data_orig = png_data[12 : 12 + _IHDR_DATA_LEN]  # original IHDR data
    ihdr_suffix = ihdr_type_and_data_orig[8:]  # bit_depth .. interlace

    new_ihdr_data = struct.pack(">II", correct_width, correct_height) + ihdr_suffix
    new_type_and_data = b"IHDR" + new_ihdr_data
    new_crc = struct.pack(">I", zlib.crc32(new_type_and_data) & 0xFFFFFFFF)

    # Build repaired PNG:
    #   signature (8) + length (4) + type (4) + data (13) + crc (4) = 33 bytes
    repaired = (
        PNG_SIGNATURE
        + struct.pack(">I", _IHDR_DATA_LEN)
        + new_type_and_data
        + new_crc
        + png_data[8 + 4 + 4 + _IHDR_DATA_LEN + 4 :]  # remainder after IHDR chunk
    )

    return repaired, info


def calculate_png_height_from_idat(png_data: bytes) -> int | None:
    """Calculate true image height from decompressed IDAT data.

    Concatenates all IDAT chunk payloads, decompresses them, and computes::

        height = decompressed_size / (1 + width * bytes_per_pixel)

    The ``+1`` accounts for the filter byte at the start of each scanline.

    Returns:
        The calculated height, or ``None`` if the data cannot be parsed.
    """
    if not png_data.startswith(PNG_SIGNATURE):
        return None

    # Read IHDR for width, bit_depth, color_type
    _, _, width, _ = _parse_ihdr(png_data)
    ihdr_data = png_data[16 : 16 + _IHDR_DATA_LEN]  # offset 8+4+4 = 16
    bit_depth = ihdr_data[8]
    color_type = ihdr_data[9]

    try:
        bpp = _bytes_per_pixel(color_type, bit_depth)
    except ValueError:
        return None

    # Collect all IDAT chunks
    idat_payloads: list[bytes] = []
    offset = 8
    while offset + 8 <= len(png_data):
        length = struct.unpack(">I", png_data[offset : offset + 4])[0]
        chunk_type = png_data[offset + 4 : offset + 8]
        data_start = offset + 8
        data_end = data_start + length

        if data_end + 4 > len(png_data):
            break

        if chunk_type == b"IDAT":
            idat_payloads.append(png_data[data_start:data_end])

        offset = data_end + 4  # skip CRC

    if not idat_payloads:
        return None

    try:
        decompressed = zlib.decompress(b"".join(idat_payloads))
    except zlib.error:
        return None

    scanline_bytes = 1 + int(width * bpp)  # filter byte + pixel data
    if scanline_bytes <= 0:
        return None

    height = len(decompressed) // scanline_bytes
    return height if height > 0 else None
