"""
LSB extraction for Ichnos (zsteg style).
"""

from __future__ import annotations

from ichnos.core.detection import printable_ratio
from ichnos.core.models import Candidate
from ichnos.core.security import safe_decompress_zlib
from ichnos.stego.image.png import parse_chunks, parse_ihdr


def paeth_predictor(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    elif pb <= pc:
        return b
    else:
        return c


def extract_raw_pixels(png_data: bytes) -> tuple[bytes, int, int, int]:
    """Decompress IDAT chunks, undo PNG filtering."""
    chunks = parse_chunks(png_data)
    ihdr_chunk = next((c for c in chunks if c.chunk_type == "IHDR"), None)
    if not ihdr_chunk:
        raise ValueError("No IHDR chunk")
    ihdr = parse_ihdr(ihdr_chunk.data)
    width = ihdr["width"]
    height = ihdr["height"]
    color_type = ihdr["color_type"]
    bit_depth = ihdr["bit_depth"]

    if width > 65536 or height > 65536 or width <= 0 or height <= 0:
        raise ValueError(f"PNG dimensions out of supported range (1..65536): {width}x{height}")

    if bit_depth != 8:
        raise ValueError("Only 8-bit depth supported for LSB")

    if color_type == 2:  # RGB
        channels = 3
    elif color_type == 6:  # RGBA
        channels = 4
    elif color_type == 0:  # Grayscale
        channels = 1
    elif color_type == 4:  # Grayscale + Alpha
        channels = 2
    else:
        raise ValueError("Unsupported color type")

    expected_scanline_bytes = height * (1 + width * channels)
    if expected_scanline_bytes > 128 * 1024 * 1024:
        raise ValueError(
            f"Expected uncompressed pixel data ({expected_scanline_bytes // (1024*1024)}MB) exceeds limit"
        )

    idat_data = b"".join(c.data for c in chunks if c.chunk_type == "IDAT")
    max_len = min(max(expected_scanline_bytes + 4096, 64 * 1024 * 1024), 128 * 1024 * 1024)
    decompressed = safe_decompress_zlib(idat_data, max_size=max_len)

    stride = width * channels
    pixels = bytearray()

    prev_scanline = bytearray(stride)

    offset = 0
    for y in range(height):
        if offset + 1 + stride > len(decompressed):
            break
        filter_type = decompressed[offset]
        scanline = decompressed[offset + 1 : offset + 1 + stride]
        offset += 1 + stride

        recon = bytearray(stride)
        for i in range(stride):
            x_val = scanline[i]
            a = recon[i - channels] if i >= channels else 0
            b = prev_scanline[i]
            c = prev_scanline[i - channels] if i >= channels else 0

            if filter_type == 0:
                val = x_val
            elif filter_type == 1:
                val = (x_val + a) & 0xFF
            elif filter_type == 2:
                val = (x_val + b) & 0xFF
            elif filter_type == 3:
                val = (x_val + (a + b) // 2) & 0xFF
            elif filter_type == 4:
                val = (x_val + paeth_predictor(a, b, c)) & 0xFF
            else:
                raise ValueError(f"Unknown filter type {filter_type}")

            recon[i] = val

        pixels.extend(recon)
        prev_scanline = recon

    return bytes(pixels), width, height, channels


def extract_lsb(
    pixel_bytes: bytes,
    width: int | None = None,
    height: int | None = None,
    channels: int | None = None,
    channel_order: str = "RGB",
    bit_order: str = "lsb",
    num_bits: int = 1,
) -> bytes:
    """Extract least significant bits from pixel data or PNG file bytes."""
    if isinstance(width, str):
        # Called as extract_lsb(png_data, channel_order, num_bits)
        if isinstance(height, int):
            num_bits = height
        channel_order = width
        width = None

    if width is None or pixel_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        pixel_bytes, width, height, channels = extract_raw_pixels(pixel_bytes)

    # Build channel indices mapping
    channel_map = {"R": 0, "G": 1, "B": 2, "A": 3, "L": 0}
    if channels == 1:
        indices = [0] * len(channel_order)  # Ignore order if grayscale
    elif channels == 2:
        indices = [channel_map.get(c, 0) for c in channel_order if c in "LA"]
    else:
        indices = [
            channel_map.get(c, 0)
            for c in channel_order
            if c in channel_map and channel_map[c] < channels
        ]

    if not indices:
        return b""

    extracted_bits = []

    for i in range(0, len(pixel_bytes), channels):
        pixel = pixel_bytes[i : i + channels]
        if len(pixel) < channels:
            break
        for ch_idx in indices:
            val = pixel[ch_idx]
            for b in range(num_bits):
                if bit_order == "lsb":
                    bit = (val >> b) & 1
                else:  # msb
                    bit = (val >> (num_bits - 1 - b)) & 1
                extracted_bits.append(bit)

    # Pack bits to bytes
    res = bytearray()
    for i in range(0, len(extracted_bits), 8):
        byte_bits = extracted_bits[i : i + 8]
        if len(byte_bits) < 8:
            break
        val = 0
        for j, b in enumerate(byte_bits):
            if bit_order == "lsb":
                val |= b << j
            else:
                val |= b << (7 - j)
        res.append(val)

    return bytes(res)


def brute_force_lsb(png_data: bytes, max_results: int = 20) -> list[Candidate]:
    """Try all reasonable permutations for LSB extraction."""
    try:
        pixel_bytes, width, height, channels = extract_raw_pixels(png_data)
    except Exception:
        return []

    channel_orders = ["RGB", "RBG", "GBR", "GRB", "BGR", "BRG", "R", "G", "B", "RGBA", "ABGR"]
    bit_orders = ["lsb", "msb"]
    num_bits_opts = [1, 2]

    candidates = []

    for co in channel_orders:
        for bo in bit_orders:
            for nb in num_bits_opts:
                try:
                    data = extract_lsb(pixel_bytes, width, height, channels, co, bo, nb)
                    if not data:
                        continue

                    sample = data[:256]
                    score = printable_ratio(sample)

                    if score > 0.4:
                        candidates.append(
                            Candidate(
                                decoded=data,
                                method=f"lsb_extract_{co}_{bo}_{nb}bit",
                                confidence=score,
                                layers=["stego.image.lsb"],
                            )
                        )
                except Exception:
                    continue

    candidates.sort(key=lambda c: c.confidence, reverse=True)
    return candidates[:max_results]
