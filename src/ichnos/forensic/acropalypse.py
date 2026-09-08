"""Acropalypse vulnerability detector and data recovery.

Detects and recovers data leaked by CVE-2023-21036 (Android Pixel Markup) and
CVE-2023-28310 (Windows Snipping Tool).  When a screenshot is cropped, the app
writes the smaller file at offset 0 but does NOT truncate the original.  The
uncropped pixel data remains as trailing bytes after the new file's end marker.
"""

from __future__ import annotations

import struct
import zlib

# ---------------------------------------------------------------------------
# PNG constants
# ---------------------------------------------------------------------------
_PNG_SIG = b"\x89PNG\r\n\x1a\n"
_IEND_MARKER = b"IEND\xaeB`\x82"

# ---------------------------------------------------------------------------
# JPEG constants
# ---------------------------------------------------------------------------
_JPEG_SOI = b"\xff\xd8"
_JPEG_EOI = b"\xff\xd9"
_JPEG_APP1 = b"\xff\xe1"
_EXIF_HEADER = b"Exif\x00\x00"


# ---------------------------------------------------------------------------
# PNG helpers
# ---------------------------------------------------------------------------

def detect_png_trailing_data(data: bytes) -> tuple[bool, int, bytes]:
    """Detect data appended after the PNG IEND chunk.

    The IEND chunk (including its 4-byte CRC) is the last legitimate byte of a
    PNG file.  Anything beyond it is trailing data that may contain the original
    uncropped pixel information.

    Args:
        data: Raw file bytes.

    Returns:
        A 3-tuple of ``(has_trailing, iend_end_offset, trailing_data)`` where
        *iend_end_offset* is the byte position immediately after IEND and its
        CRC.  If no IEND is found, ``(False, -1, b"")`` is returned.
    """
    pos = data.find(_IEND_MARKER)
    if pos == -1:
        return False, -1, b""

    # IEND marker is 4-byte type + 4-byte CRC = the _IEND_MARKER itself (8 B).
    # But the chunk also has a preceding 4-byte *length* field (always 0 for
    # IEND).  The marker search gives us the start of the type field, so the
    # full chunk ends 8 bytes after that: type(4) + CRC(4).
    iend_end = pos + len(_IEND_MARKER)

    trailing = data[iend_end:]
    return (len(trailing) > 0, iend_end, trailing)


# ---------------------------------------------------------------------------
# JPEG helpers
# ---------------------------------------------------------------------------

def detect_jpeg_trailing_data(data: bytes) -> tuple[bool, int, bytes]:
    """Detect data appended after the JPEG EOI marker.

    Scans *backwards* from the end so that embedded thumbnails (which have
    their own SOI/EOI pair) are not confused with the outer image's EOI.

    Args:
        data: Raw file bytes.

    Returns:
        A 3-tuple ``(has_trailing, eoi_end_offset, trailing_data)``.  If no
        EOI is found, ``(False, -1, b"")`` is returned.
    """
    # Walk forward through JPEG markers to find the *outer* EOI.
    # This avoids being tricked by the thumbnail's EOI inside APP1.
    eoi_pos = _find_outer_jpeg_eoi(data)
    if eoi_pos == -1:
        return False, -1, b""

    eoi_end = eoi_pos + 2  # EOI is 2 bytes
    trailing = data[eoi_end:]
    return (len(trailing) > 0, eoi_end, trailing)


def _find_outer_jpeg_eoi(data: bytes) -> int:
    """Walk JPEG marker segments to locate the outer-image EOI.

    Returns the byte offset of the ``\\xff\\xd9`` marker, or -1.
    """
    if len(data) < 2 or data[:2] != _JPEG_SOI:
        return -1

    pos = 2
    while pos < len(data) - 1:
        if data[pos] != 0xFF:
            pos += 1
            continue

        marker = data[pos + 1]

        # Padding bytes (0xFF fill)
        if marker == 0xFF:
            pos += 1
            continue

        # EOI
        if marker == 0xD9:
            return pos

        # Stand-alone markers (TEM, RST0-RST7)
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue

        # SOI – should not appear at this level, but skip it
        if marker == 0xD8:
            pos += 2
            continue

        # SOS – scan data follows; search byte-by-byte for next marker
        if marker == 0xDA:
            pos += 2
            if pos + 2 > len(data):
                break
            length = struct.unpack(">H", data[pos : pos + 2])[0]
            pos += length
            # Entropy-coded data – skip until next non-stuffed 0xFF
            while pos < len(data) - 1:
                if data[pos] == 0xFF and data[pos + 1] != 0x00:
                    break
                pos += 1
            continue

        # Generic marker with length
        pos += 2
        if pos + 2 > len(data):
            break
        length = struct.unpack(">H", data[pos : pos + 2])[0]
        pos += length

    return -1


# ---------------------------------------------------------------------------
# EXIF thumbnail extraction
# ---------------------------------------------------------------------------

def extract_exif_thumbnail(data: bytes) -> bytes | None:
    """Extract the EXIF APP1 embedded JPEG thumbnail.

    Many camera/phone images embed a small JPEG thumbnail inside the EXIF
    metadata.  When the image is cropped and the file is not truncated, the
    EXIF thumbnail often still references the *original* uncropped image.

    Args:
        data: Raw JPEG file bytes.

    Returns:
        The JPEG thumbnail bytes, or ``None`` if no thumbnail is found.
    """
    app1_pos = data.find(_JPEG_APP1)
    if app1_pos == -1:
        return None

    # APP1 segment: marker(2) + length(2) + payload
    seg_start = app1_pos + 2
    if seg_start + 2 > len(data):
        return None
    seg_len = struct.unpack(">H", data[seg_start : seg_start + 2])[0]
    seg_data = data[seg_start + 2 : seg_start + seg_len]

    # Verify EXIF header
    if not seg_data.startswith(_EXIF_HEADER):
        return None

    # Search for an embedded JPEG (SOI..EOI) inside the EXIF payload
    thumb_start = seg_data.find(_JPEG_SOI)
    if thumb_start == -1:
        return None

    thumb_end = seg_data.find(_JPEG_EOI, thumb_start + 2)
    if thumb_end == -1:
        return None

    return seg_data[thumb_start : thumb_end + 2]


# ---------------------------------------------------------------------------
# Trailing IDAT recovery
# ---------------------------------------------------------------------------

def carve_trailing_png_idat(trailing: bytes) -> bytes | None:
    """Attempt to decompress leftover IDAT data from trailing PNG bytes.

    When Acropalypse occurs on a PNG, the trailing data may contain partial or
    complete IDAT chunks from the original uncropped image.  This function
    tries to locate valid zlib/Deflate streams by probing at various offsets.

    The function attempts two strategies:

    1. **Chunk-aware scan** – look for ``IDAT`` chunk headers in the trailing
       data and try to reassemble/decompress the payload.
    2. **Brute-force Deflate scan** – try ``zlib.decompress(wbits=-15)`` at
       every byte offset (up to a configurable limit) to recover raw Deflate
       blocks.

    Args:
        trailing: The raw bytes after the PNG IEND marker.

    Returns:
        Decompressed pixel data (raw filter bytes) on success, or ``None``.
    """
    if not trailing:
        return None

    # --- Strategy 1: chunk-aware IDAT reassembly ---
    result = _reassemble_idat_chunks(trailing)
    if result is not None:
        return result

    # --- Strategy 2: brute-force Deflate scan ---
    max_scan = min(len(trailing), 1024)
    for offset in range(max_scan):
        candidate = trailing[offset:]
        # Try raw Deflate (wbits=-15)
        try:
            return zlib.decompress(candidate, -15)
        except zlib.error:
            pass
        # Try zlib-wrapped (wbits=15)
        try:
            return zlib.decompress(candidate, 15)
        except zlib.error:
            pass

    return None


def _reassemble_idat_chunks(data: bytes) -> bytes | None:
    """Scan *data* for IDAT chunk headers and concatenate their payloads.

    Each PNG chunk: length(4) + type(4) + payload(length) + CRC(4).
    """
    idat_payloads: list[bytes] = []
    pos = 0
    while pos + 12 <= len(data):
        # Look for next "IDAT" occurrence
        idx = data.find(b"IDAT", pos)
        if idx == -1:
            break
        # The length field is 4 bytes before the type
        length_offset = idx - 4
        if length_offset < 0:
            pos = idx + 4
            continue
        chunk_length = struct.unpack(">I", data[length_offset : length_offset + 4])[0]
        payload_start = idx + 4
        payload_end = payload_start + chunk_length
        if payload_end > len(data):
            # Truncated chunk – grab what we can
            idat_payloads.append(data[payload_start:])
            break
        idat_payloads.append(data[payload_start:payload_end])
        # Skip past CRC (4 bytes)
        pos = payload_end + 4

    if not idat_payloads:
        return None

    compressed = b"".join(idat_payloads)
    for wbits in (15, -15):
        try:
            return zlib.decompress(compressed, wbits)
        except zlib.error:
            continue

    return None


# ---------------------------------------------------------------------------
# Master analysis
# ---------------------------------------------------------------------------

def analyze_acropalypse(file_data: bytes) -> dict:
    """Run full Acropalypse analysis on a file.

    Determines whether the file is PNG or JPEG, checks for trailing data,
    attempts EXIF thumbnail extraction (JPEG) and trailing IDAT recovery (PNG).

    Args:
        file_data: Raw bytes of the image file.

    Returns:
        A dict with the following keys:

        - **vulnerable** (*bool*): ``True`` if trailing data was detected.
        - **file_type** (*str | None*): ``"png"`` or ``"jpeg"``, or ``None``.
        - **trailing_size** (*int*): Number of trailing bytes found.
        - **thumbnail** (*bytes | None*): Extracted EXIF thumbnail, if any.
        - **recovered_data** (*bytes | None*): Decompressed IDAT data, if any.
        - **findings** (*list[str]*): Human-readable summary strings.
    """
    result: dict = {
        "vulnerable": False,
        "file_type": None,
        "trailing_size": 0,
        "thumbnail": None,
        "recovered_data": None,
        "findings": [],
    }

    is_png = file_data[:8] == _PNG_SIG
    is_jpeg = file_data[:2] == _JPEG_SOI

    if not is_png and not is_jpeg:
        result["findings"].append("File is neither PNG nor JPEG; skipping.")
        return result

    if is_png:
        result["file_type"] = "png"
        has_trail, offset, trailing = detect_png_trailing_data(file_data)
        if has_trail:
            result["vulnerable"] = True
            result["trailing_size"] = len(trailing)
            result["findings"].append(
                f"PNG trailing data detected: {len(trailing)} bytes after IEND at offset {offset}."
            )
            recovered = carve_trailing_png_idat(trailing)
            if recovered:
                result["recovered_data"] = recovered
                result["findings"].append(
                    f"Successfully decompressed {len(recovered)} bytes of IDAT pixel data."
                )
            else:
                result["findings"].append(
                    "Could not decompress trailing IDAT data."
                )
        else:
            result["findings"].append("No trailing data after IEND; file appears clean.")

    else:  # JPEG
        result["file_type"] = "jpeg"
        has_trail, offset, trailing = detect_jpeg_trailing_data(file_data)
        if has_trail:
            result["vulnerable"] = True
            result["trailing_size"] = len(trailing)
            result["findings"].append(
                f"JPEG trailing data detected: {len(trailing)} bytes after EOI at offset {offset}."
            )
        else:
            result["findings"].append("No trailing data after EOI; file appears clean.")

        # Thumbnail extraction (regardless of trailing data)
        thumb = extract_exif_thumbnail(file_data)
        if thumb:
            result["thumbnail"] = thumb
            result["findings"].append(
                f"EXIF thumbnail extracted: {len(thumb)} bytes."
            )

    return result
