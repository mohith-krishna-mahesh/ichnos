"""Animated PNG (APNG) chunk parser and hidden frame extractor.

Extracts animation control (acTL), frame control (fcTL), and frame data (fdAT)
chunks to reconstruct individual PNG frames and identify hidden steganographic frames.
"""

from __future__ import annotations

import struct
import zlib
from typing import Any

from ichnos.stego.image.png import parse_chunks


def is_apng(data: bytes) -> bool:
    """Returns True if the PNG contains APNG animation chunks."""
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return False
    chunks = parse_chunks(data)
    return any(c.chunk_type == "acTL" for c in chunks)


def parse_apng(data: bytes) -> dict[str, Any]:
    """Parses APNG animation metadata and frame sequence headers.

    Returns:
        Dict with 'is_animated', 'num_frames', 'num_plays', 'frame_headers'.
    """
    if not is_apng(data):
        return {"is_animated": False, "num_frames": 1, "num_plays": 0, "frame_headers": []}

    chunks = parse_chunks(data)
    num_frames = 1
    num_plays = 0
    frame_headers: list[dict[str, Any]] = []

    for c in chunks:
        if c.chunk_type == "acTL" and len(c.data) >= 8:
            num_frames, num_plays = struct.unpack(">II", c.data[:8])
        elif c.chunk_type == "fcTL" and len(c.data) >= 26:
            seq, w, h, x_off, y_off, delay_num, delay_den, disp_op, blend_op = struct.unpack(
                ">IIIIIHHBB", c.data[:26]
            )
            frame_headers.append({
                "sequence": seq,
                "width": w,
                "height": h,
                "x_offset": x_off,
                "y_offset": y_off,
                "delay_num": delay_num,
                "delay_den": delay_den,
                "dispose_op": disp_op,
                "blend_op": blend_op,
            })

    return {
        "is_animated": True,
        "num_frames": num_frames,
        "num_plays": num_plays,
        "frame_headers": frame_headers,
    }


def extract_apng_frames(data: bytes) -> list[bytes]:
    """Extracts each individual APNG animation frame as a standalone PNG image file."""
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return []

    chunks = parse_chunks(data)
    png_sig = b"\x89PNG\r\n\x1a\n"

    # Capture global header chunks (IHDR, PLTE, etc.)
    ihdr_chunk = next((c for c in chunks if c.chunk_type == "IHDR"), None)
    if not ihdr_chunk:
        return []

    palette_chunks = [c for c in chunks if c.chunk_type in ("PLTE", "tRNS")]

    # Build default / first frame from IDAT chunks
    first_frame_idats = [c for c in chunks if c.chunk_type == "IDAT"]
    frames: list[bytes] = []

    if first_frame_idats:
        first_frame = bytearray(png_sig)
        first_frame.extend(struct.pack(">I", len(ihdr_chunk.data)) + b"IHDR" + ihdr_chunk.data + struct.pack(">I", ihdr_chunk.crc))
        for pc in palette_chunks:
            first_frame.extend(struct.pack(">I", len(pc.data)) + pc.chunk_type.encode() + pc.data + struct.pack(">I", pc.crc))
        for idat in first_frame_idats:
            first_frame.extend(struct.pack(">I", len(idat.data)) + b"IDAT" + idat.data + struct.pack(">I", idat.crc))
        iend_crc = zlib.crc32(b"IEND")
        first_frame.extend(struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc))
        frames.append(bytes(first_frame))

    # Reconstruct subsequent frames from fcTL + fdAT chunks
    cur_fctl = None
    cur_fdat_data = bytearray()

    for c in chunks:
        if len(frames) >= 100:
            break
        if c.chunk_type == "fcTL":
            if cur_fctl and cur_fdat_data:
                # Assemble frame
                frame_bytes = _assemble_frame_png(ihdr_chunk.data, cur_fctl, bytes(cur_fdat_data), palette_chunks)
                if frame_bytes:
                    frames.append(frame_bytes)
                cur_fdat_data.clear()
            cur_fctl = c.data
        elif c.chunk_type == "fdAT" and len(c.data) >= 4:
            # First 4 bytes of fdAT are sequence number; rest is IDAT payload
            if len(cur_fdat_data) + len(c.data) - 4 <= 64 * 1024 * 1024:
                cur_fdat_data.extend(c.data[4:])

    if cur_fctl and cur_fdat_data and len(frames) < 100:
        frame_bytes = _assemble_frame_png(ihdr_chunk.data, cur_fctl, bytes(cur_fdat_data), palette_chunks)
        if frame_bytes:
            frames.append(frame_bytes)

    return frames


def _assemble_frame_png(
    base_ihdr_data: bytes,
    fctl_data: bytes,
    raw_idat_data: bytes,
    palette_chunks: list[Any],
) -> bytes:
    """Builds a standalone PNG from an fcTL header and concatenated fdAT data."""
    if len(fctl_data) < 26 or len(base_ihdr_data) < 13:
        return b""

    seq, w, h, x_off, y_off, d_num, d_den, disp, blend = struct.unpack(">IIIIIHHBB", fctl_data[:26])
    if w > 65536 or h > 65536 or w == 0 or h == 0:
        return b""
    # Build IHDR with frame dimensions, keeping bit_depth/color_type from base
    bit_depth = base_ihdr_data[8]
    color_type = base_ihdr_data[9]
    compression = base_ihdr_data[10]
    filter_m = base_ihdr_data[11]
    interlace = base_ihdr_data[12]

    new_ihdr_data = struct.pack(">IIBBBBB", w, h, bit_depth, color_type, compression, filter_m, interlace)
    ihdr_crc = zlib.crc32(b"IHDR" + new_ihdr_data)

    out = bytearray(b"\x89PNG\r\n\x1a\n")
    out.extend(struct.pack(">I", 13) + b"IHDR" + new_ihdr_data + struct.pack(">I", ihdr_crc))

    for pc in palette_chunks:
        out.extend(struct.pack(">I", len(pc.data)) + pc.chunk_type.encode() + pc.data + struct.pack(">I", pc.crc))

    idat_crc = zlib.crc32(b"IDAT" + raw_idat_data)
    out.extend(struct.pack(">I", len(raw_idat_data)) + b"IDAT" + raw_idat_data + struct.pack(">I", idat_crc))

    iend_crc = zlib.crc32(b"IEND")
    out.extend(struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc))
    return bytes(out)
