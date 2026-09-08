"""Multi-frame GIF analysis, comment extraction, and timing steganography decoder.

Parses GIF87a and GIF89a streams, extracts metadata comments, and detects
data encoded in Graphic Control Extension frame delay times.
"""

from __future__ import annotations

import struct


def is_gif(data: bytes) -> bool:
    """Returns True if header starts with GIF87a or GIF89a."""
    return data.startswith((b"GIF87a", b"GIF89a"))


def extract_gif_comments(data: bytes) -> list[str]:
    """Extracts text from all GIF Comment Extension blocks (0x21 0xFE)."""
    if not is_gif(data):
        return []

    comments: list[str] = []
    idx = 13  # Skip header (6) + Logical Screen Descriptor (7)

    # Skip global color table if present
    flags = data[10]
    has_gct = bool(flags & 0x80)
    if has_gct:
        gct_size = 3 * (2 ** ((flags & 0x07) + 1))
        idx += gct_size

    data_len = len(data)
    while idx < data_len:
        b = data[idx]
        if b == 0x3B:  # Trailer
            break
        elif b == 0x21:  # Extension block
            if idx + 1 >= data_len:
                break
            ext_label = data[idx + 1]
            idx += 2

            if ext_label == 0xFE:  # Comment Extension
                comment_parts: list[bytes] = []
                while idx < data_len:
                    sub_len = data[idx]
                    idx += 1
                    if sub_len == 0:
                        break
                    comment_parts.append(data[idx : idx + sub_len])
                    idx += sub_len
                full_comment = b"".join(comment_parts).decode("latin-1", errors="replace")
                if full_comment:
                    comments.append(full_comment)
            else:
                # Skip sub-blocks
                while idx < data_len:
                    sub_len = data[idx]
                    idx += 1
                    if sub_len == 0:
                        break
                    idx += sub_len
        elif b == 0x2C:  # Image descriptor
            if idx + 9 >= data_len:
                break
            img_flags = data[idx + 9]
            idx += 10
            if bool(img_flags & 0x80):  # Local color table
                lct_size = 3 * (2 ** ((img_flags & 0x07) + 1))
                idx += lct_size
            # LZW min code size
            if idx < data_len:
                idx += 1
            # Skip image data sub-blocks
            while idx < data_len:
                sub_len = data[idx]
                idx += 1
                if sub_len == 0:
                    break
                idx += sub_len
        else:
            idx += 1

    return comments


def extract_gif_frame_delays(data: bytes) -> list[int]:
    """Extracts frame delay times in 1/100ths of a second from Graphic Control Extensions."""
    if not is_gif(data):
        return []

    delays: list[int] = []
    idx = 13
    flags = data[10]
    if bool(flags & 0x80):
        idx += 3 * (2 ** ((flags & 0x07) + 1))

    data_len = len(data)
    while idx < data_len:
        b = data[idx]
        if b == 0x3B:
            break
        elif b == 0x21:
            if idx + 1 >= data_len:
                break
            ext_label = data[idx + 1]
            idx += 2
            if ext_label == 0xF9:  # Graphic Control Extension
                block_len = data[idx]
                idx += 1
                if block_len == 4 and idx + 4 <= data_len:
                    packed, delay = struct.unpack("<BH", data[idx : idx + 3])
                    delays.append(delay)
                    idx += 4  # Skip packed, delay (2), transparent index
                # Skip to block terminator
                while idx < data_len and data[idx] != 0:
                    idx += data[idx] + 1
                if idx < data_len:
                    idx += 1
            else:
                while idx < data_len:
                    sub_len = data[idx]
                    idx += 1
                    if sub_len == 0:
                        break
                    idx += sub_len
        elif b == 0x2C:
            if idx + 9 >= data_len:
                break
            img_flags = data[idx + 9]
            idx += 10
            if bool(img_flags & 0x80):
                idx += 3 * (2 ** ((img_flags & 0x07) + 1))
            if idx < data_len:
                idx += 1
            while idx < data_len:
                sub_len = data[idx]
                idx += 1
                if sub_len == 0:
                    break
                idx += sub_len
        else:
            idx += 1

    return delays


def decode_timing_steganography(delays: list[int]) -> str | None:
    """Decodes binary data encoded in alternating frame delay times."""
    if len(delays) < 8:
        return None

    # Check if delays cluster into two distinct buckets (e.g. 10 and 20)
    unique = sorted(set(delays))
    if len(unique) == 2:
        lo, _hi = unique[0], unique[1]
        bits = [0 if d == lo else 1 for d in delays]
        # Group into bytes
        byte_vals = bytearray()
        for i in range(0, len(bits) - 7, 8):
            val = 0
            for bit in bits[i : i + 8]:
                val = (val << 1) | bit
            byte_vals.append(val)
        try:
            return byte_vals.decode("utf-8")
        except Exception:
            return byte_vals.decode("latin-1", errors="replace")

    return None
