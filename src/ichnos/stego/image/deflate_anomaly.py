"""PNG IDAT and Deflate Compression Anomaly Detector.

Scans zlib streams inside PNG IDAT chunks for uncompressed stored blocks (BTYPE=00),
anomalous compression levels, multiple discrete concatenated streams, or embedded headers.
"""

from __future__ import annotations

import zlib
from typing import Any

from ichnos.stego.image.png import parse_chunks


def analyze_idat_deflate(png_data: bytes) -> dict[str, Any]:
    """Inspects PNG IDAT streams for compression-layer steganographic anomalies.

    Returns:
        Dict with: 'has_anomalies', 'stored_blocks_count', 'concatenated_streams',
        'raw_stored_payloads'.
    """
    if not png_data.startswith(b"\x89PNG\r\n\x1a\n"):
        return {"has_anomalies": False, "error": "Not a valid PNG"}

    chunks = parse_chunks(png_data)
    idat_chunks = [c for c in chunks if c.chunk_type == "IDAT"]
    if not idat_chunks:
        return {"has_anomalies": False, "error": "No IDAT chunks found"}

    concatenated_data = b"".join(c.data for c in idat_chunks)
    stored_payloads: list[bytes] = []

    # Check for raw Deflate uncompressed blocks (BTYPE=00)
    # Each stored block has header: BFINAL (1 bit), BTYPE (2 bits = 00), 5 bits padding,
    # followed by LEN (16 bits) and NLEN (16 bits, one's complement of LEN)
    pos = 2  # Skip 2-byte zlib header (e.g. 0x78 0x9C)
    while pos + 4 < len(concatenated_data):
        b = concatenated_data[pos]
        # BTYPE == 0b00 (uncompressed)
        if (b & 0x06) == 0:
            pos += 1
            if pos + 4 <= len(concatenated_data):
                length = concatenated_data[pos] | (concatenated_data[pos + 1] << 8)
                nlen = concatenated_data[pos + 2] | (concatenated_data[pos + 3] << 8)
                if length == (~nlen & 0xFFFF) and length > 0:
                    pos += 4
                    if pos + length <= len(concatenated_data):
                        payload = concatenated_data[pos : pos + length]
                        stored_payloads.append(payload)
                        pos += length
                        continue
        pos += 1

    # Check for multiple concatenated zlib streams (0x7801, 0x789C, 0x78DA)
    zlib_headers = [b"\x78\x01", b"\x78\x9c", b"\x78\xda", b"\x78\x5e"]
    header_indices = []
    for h in zlib_headers:
        start = 0
        while True:
            idx = concatenated_data.find(h, start)
            if idx == -1:
                break
            header_indices.append(idx)
            start = idx + 1

    header_indices.sort()
    multiple_streams = len(header_indices) > 1

    # Attempt decompression of any secondary zlib streams
    secondary_decompressed: list[bytes] = []
    for offset in header_indices[1:]:
        try:
            decomp = zlib.decompress(concatenated_data[offset:])
            if decomp:
                secondary_decompressed.append(decomp)
        except Exception:
            pass

    has_anomalies = bool(stored_payloads or secondary_decompressed)

    return {
        "has_anomalies": has_anomalies,
        "idat_chunks_count": len(idat_chunks),
        "total_compressed_bytes": len(concatenated_data),
        "stored_uncompressed_blocks": len(stored_payloads),
        "raw_stored_payloads": stored_payloads,
        "multiple_zlib_streams": multiple_streams,
        "secondary_payloads": secondary_decompressed,
    }
