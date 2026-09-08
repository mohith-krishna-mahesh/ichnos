"""File repair tools for common CTF forensics challenges.

Implements automated detection and repair of:
- ZIP pseudo-encryption (fake encryption bit without actual cipher headers).
- PNG CRC mismatches, including IHDR height brute-forcing.
"""

from __future__ import annotations

import binascii
import struct

# ---------------------------------------------------------------------------
# PNG constants
# ---------------------------------------------------------------------------
_PNG_SIG = b"\x89PNG\r\n\x1a\n"
_PNG_SIG_LEN = 8

# ---------------------------------------------------------------------------
# ZIP constants
# ---------------------------------------------------------------------------
_ZIP_LOCAL_SIG = b"PK\x03\x04"
_ZIP_CENTRAL_SIG = b"PK\x01\x02"


# ===================================================================
# ZIP pseudo-encryption
# ===================================================================

def detect_zip_pseudo_encryption(data: bytes) -> bool:
    """Return ``True`` if the ZIP has the encryption bit set without real encryption.

    Pseudo-encrypted ZIPs set the general-purpose bit flag's bit 0 (encrypted)
    in the local and/or central directory headers, but contain no actual
    encryption header.  Standard tools refuse to extract them, but clearing the
    bit is enough to recover the files.

    Args:
        data: Raw ZIP file bytes.

    Returns:
        ``True`` when at least one local file header has bit 0 set.
    """
    pos = 0
    while True:
        idx = data.find(_ZIP_LOCAL_SIG, pos)
        if idx == -1:
            break
        if idx + 30 > len(data):
            break
        gp_flag = struct.unpack("<H", data[idx + 6 : idx + 8])[0]
        if gp_flag & 0x0001:
            return True
        # Skip to next header
        fname_len = struct.unpack("<H", data[idx + 26 : idx + 28])[0]
        extra_len = struct.unpack("<H", data[idx + 28 : idx + 30])[0]
        comp_size = struct.unpack("<I", data[idx + 18 : idx + 22])[0]
        pos = idx + 30 + fname_len + extra_len + comp_size
    return False


def fix_zip_pseudo_encryption(data: bytes) -> bytes:
    """Clear the fake encryption bit in all local and central directory headers.

    For every local file header (``PK\\x03\\x04``) and central directory entry
    (``PK\\x01\\x02``), bit 0 of the general-purpose flag is cleared.

    Args:
        data: Raw ZIP file bytes.

    Returns:
        The repaired ZIP as ``bytes`` with encryption bits cleared.
    """
    buf = bytearray(data)

    # --- Local file headers ---
    pos = 0
    while True:
        idx = buf.find(_ZIP_LOCAL_SIG, pos)
        if idx == -1:
            break
        if idx + 30 > len(buf):
            break
        gp_flag = struct.unpack("<H", buf[idx + 6 : idx + 8])[0]
        if gp_flag & 0x0001:
            gp_flag &= ~0x0001
            struct.pack_into("<H", buf, idx + 6, gp_flag)
        fname_len = struct.unpack("<H", buf[idx + 26 : idx + 28])[0]
        extra_len = struct.unpack("<H", buf[idx + 28 : idx + 30])[0]
        comp_size = struct.unpack("<I", buf[idx + 18 : idx + 22])[0]
        pos = idx + 30 + fname_len + extra_len + comp_size

    # --- Central directory entries ---
    pos = 0
    while True:
        idx = buf.find(_ZIP_CENTRAL_SIG, pos)
        if idx == -1:
            break
        if idx + 46 > len(buf):
            break
        gp_flag = struct.unpack("<H", buf[idx + 8 : idx + 10])[0]
        if gp_flag & 0x0001:
            gp_flag &= ~0x0001
            struct.pack_into("<H", buf, idx + 8, gp_flag)
        fname_len = struct.unpack("<H", buf[idx + 28 : idx + 30])[0]
        extra_len = struct.unpack("<H", buf[idx + 30 : idx + 32])[0]
        comment_len = struct.unpack("<H", buf[idx + 32 : idx + 34])[0]
        pos = idx + 46 + fname_len + extra_len + comment_len

    return bytes(buf)


# ===================================================================
# PNG CRC validation & repair
# ===================================================================

def _iter_png_chunks(data: bytes):
    """Yield ``(offset, chunk_type, chunk_data, stored_crc)`` for each PNG chunk.

    *offset* is the byte position of the 4-byte length field.
    """
    pos = _PNG_SIG_LEN
    while pos + 8 <= len(data):
        chunk_length = struct.unpack(">I", data[pos : pos + 4])[0]
        chunk_type_raw = data[pos + 4 : pos + 8]
        try:
            chunk_type = chunk_type_raw.decode("ascii")
        except UnicodeDecodeError:
            chunk_type = chunk_type_raw.hex()

        payload_start = pos + 8
        payload_end = payload_start + chunk_length

        if payload_end + 4 > len(data):
            break

        chunk_data = data[payload_start:payload_end]
        stored_crc = struct.unpack(">I", data[payload_end : payload_end + 4])[0]

        yield pos, chunk_type, chunk_type_raw, chunk_data, stored_crc

        pos = payload_end + 4


def detect_png_crc_mismatch(data: bytes) -> list[tuple[str, int, int]]:
    """Check the CRC-32 of every PNG chunk.

    Args:
        data: Raw PNG file bytes.

    Returns:
        A list of ``(chunk_type, expected_crc, actual_crc)`` tuples for each
        chunk whose stored CRC does not match the computed CRC.
    """
    if data[:_PNG_SIG_LEN] != _PNG_SIG:
        return []

    mismatches: list[tuple[str, int, int]] = []
    for _offset, chunk_type, chunk_type_raw, chunk_data, stored_crc in _iter_png_chunks(data):
        computed = binascii.crc32(chunk_type_raw + chunk_data) & 0xFFFFFFFF
        if computed != stored_crc:
            mismatches.append((chunk_type, computed, stored_crc))

    return mismatches


def fix_png_ihdr_crc(data: bytes) -> tuple[bytes, dict]:
    """Recalculate and fix the IHDR chunk's CRC, brute-forcing height if needed.

    A very common CTF challenge is a PNG with an intentionally wrong IHDR height
    (or width) so that part of the image is hidden.  The CRC stored in the IHDR
    chunk corresponds to the *original* correct dimensions, so we can brute-force
    the height to find the value that matches the stored CRC.

    Workflow:
        1. Check whether the current IHDR data matches its stored CRC.
        2. If not, try height values 1 … 4096 with the stored width until the
           CRC matches.
        3. Return the repaired PNG and a dict describing the changes.

    Args:
        data: Raw PNG file bytes.

    Returns:
        A 2-tuple ``(repaired_png, info)`` where *info* contains:

        - **original_height** (*int*): The height found in the original IHDR.
        - **correct_height** (*int | None*): The brute-forced height, or
          ``None`` if no match was found.
        - **crc_fixed** (*bool*): Whether the CRC was corrected.
    """
    if data[:_PNG_SIG_LEN] != _PNG_SIG:
        return data, {"original_height": 0, "correct_height": None, "crc_fixed": False}

    # IHDR is always the first chunk
    ihdr_offset = _PNG_SIG_LEN  # length field starts here
    if ihdr_offset + 8 > len(data):
        return data, {"original_height": 0, "correct_height": None, "crc_fixed": False}

    ihdr_length = struct.unpack(">I", data[ihdr_offset : ihdr_offset + 4])[0]
    ihdr_type = data[ihdr_offset + 4 : ihdr_offset + 8]
    if ihdr_type != b"IHDR":
        return data, {"original_height": 0, "correct_height": None, "crc_fixed": False}

    payload_start = ihdr_offset + 8
    payload_end = payload_start + ihdr_length
    crc_offset = payload_end

    if crc_offset + 4 > len(data):
        return data, {"original_height": 0, "correct_height": None, "crc_fixed": False}

    ihdr_data = bytearray(data[payload_start:payload_end])
    stored_crc = struct.unpack(">I", data[crc_offset : crc_offset + 4])[0]

    # IHDR payload: width(4) height(4) bitdepth(1) colortype(1) compression(1) filter(1) interlace(1)
    original_width = struct.unpack(">I", ihdr_data[0:4])[0]
    original_height = struct.unpack(">I", ihdr_data[4:8])[0]

    computed_crc = binascii.crc32(ihdr_type + bytes(ihdr_data)) & 0xFFFFFFFF

    info: dict = {
        "original_width": original_width,
        "original_height": original_height,
        "correct_height": None,
        "crc_fixed": False,
    }

    if computed_crc == stored_crc:
        # CRC already correct
        info["correct_height"] = original_height
        info["crc_fixed"] = False
        return data, info

    # Brute-force height 1..4096
    for h in range(1, 4097):
        struct.pack_into(">I", ihdr_data, 4, h)
        candidate_crc = binascii.crc32(ihdr_type + bytes(ihdr_data)) & 0xFFFFFFFF
        if candidate_crc == stored_crc:
            info["correct_height"] = h
            info["crc_fixed"] = True
            buf = bytearray(data)
            buf[payload_start + 4 : payload_start + 8] = struct.pack(">I", h)
            # CRC is already correct (matches stored_crc), no need to rewrite
            return bytes(buf), info

    # Height brute-force failed – just fix the CRC to match current data
    struct.pack_into(">I", ihdr_data, 4, original_height)
    new_crc = binascii.crc32(ihdr_type + bytes(ihdr_data)) & 0xFFFFFFFF
    buf = bytearray(data)
    struct.pack_into(">I", buf, crc_offset, new_crc)
    info["crc_fixed"] = True
    return bytes(buf), info
