"""Pure-Python image channel analysis and EXIF metadata extractor.

Extracts EXIF tags (Make, Model, Software, DateTime, GPS, UserComment) from
raw JPEG/PNG/TIFF bytes without external libraries, and analyzes RGB/RGBA channel
plane statistics and entropy distributions.
"""

from __future__ import annotations

import math
import struct
from typing import Any

# Standard EXIF Tag Dictionary
EXIF_TAGS: dict[int, str] = {
    0x010E: "ImageDescription",
    0x010F: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x011A: "XResolution",
    0x011B: "YResolution",
    0x0128: "ResolutionUnit",
    0x0131: "Software",
    0x0132: "DateTime",
    0x013B: "Artist",
    0x8298: "Copyright",
    0x8769: "ExifOffset",
    0x8825: "GPSInfo",
    0x9000: "ExifVersion",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0x920A: "FocalLength",
    0x9286: "UserComment",
    0xA002: "PixelXDimension",
    0xA003: "PixelYDimension",
}

GPS_TAGS: dict[int, str] = {
    0x0000: "GPSVersionID",
    0x0001: "GPSLatitudeRef",
    0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef",
    0x0004: "GPSLongitude",
    0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude",
    0x0007: "GPSTimeStamp",
    0x001D: "GPSDateStamp",
}


def _parse_tiff_ifd(
    data: bytes, ifd_offset: int, endian: str, tag_map: dict[int, str]
) -> tuple[dict[str, Any], int]:
    """Parses a TIFF Image File Directory (IFD)."""
    tags: dict[str, Any] = {}
    if ifd_offset + 2 > len(data):
        return tags, 0

    num_entries = struct.unpack(f"{endian}H", data[ifd_offset : ifd_offset + 2])[0]
    curr = ifd_offset + 2

    for _ in range(num_entries):
        if curr + 12 > len(data):
            break
        tag_id, tag_type, count, val_or_offset = struct.unpack(
            f"{endian}HHI4s", data[curr : curr + 12]
        )
        curr += 12
        tag_name = tag_map.get(tag_id, f"Tag_0x{tag_id:04X}")

        # Parse basic types
        val: Any = None
        if tag_type == 2:  # ASCII string
            offset = struct.unpack(f"{endian}I", val_or_offset)[0] if count > 4 else None
            raw_str = (
                data[offset : offset + count]
                if offset is not None and offset + count <= len(data)
                else val_or_offset[:count]
            )
            val = raw_str.rstrip(b"\x00").decode("utf-8", errors="replace")
        elif tag_type in (3, 4):  # SHORT or LONG
            val = struct.unpack(f"{endian}I", val_or_offset)[0]
        elif tag_type == 5:  # RATIONAL (num/den)
            offset = struct.unpack(f"{endian}I", val_or_offset)[0]
            if offset + 8 <= len(data):
                num, den = struct.unpack(f"{endian}II", data[offset : offset + 8])
                val = (num / den) if den != 0 else 0.0
            else:
                val = val_or_offset
        else:
            val = val_or_offset

        tags[tag_name] = val

    next_ifd = struct.unpack(f"{endian}I", data[curr : curr + 4])[0] if curr + 4 <= len(data) else 0
    return tags, next_ifd


def parse_exif(data: bytes) -> dict[str, Any]:
    """Parses EXIF TIFF structure from raw EXIF bytes."""
    if len(data) < 8:
        return {}

    # Read TIFF endianness
    endian_marker = data[:2]
    if endian_marker == b"II":
        endian = "<"
    elif endian_marker == b"MM":
        endian = ">"
    else:
        return {}

    magic = struct.unpack(f"{endian}H", data[2:4])[0]
    if magic != 42:
        return {}

    first_ifd_offset = struct.unpack(f"{endian}I", data[4:8])[0]
    tags, _ = _parse_tiff_ifd(data, first_ifd_offset, endian, EXIF_TAGS)

    # If ExifOffset exists, parse sub-IFD
    if "ExifOffset" in tags and isinstance(tags["ExifOffset"], int):
        sub_tags, _ = _parse_tiff_ifd(data, tags["ExifOffset"], endian, EXIF_TAGS)
        tags["ExifSubIFD"] = sub_tags

    # If GPSInfo exists, parse GPS IFD
    if "GPSInfo" in tags and isinstance(tags["GPSInfo"], int):
        gps_tags, _ = _parse_tiff_ifd(data, tags["GPSInfo"], endian, GPS_TAGS)
        tags["GPS"] = gps_tags

    return tags


def extract_exif_from_image(data: bytes) -> dict[str, Any]:
    """Extracts EXIF metadata from raw JPEG, PNG, or TIFF image bytes."""
    # Check JPEG APP1
    if data.startswith(b"\xff\xd8"):
        exif_marker = b"\xff\xe1"
        idx = 2
        while idx < len(data) - 4:
            if data[idx : idx + 2] == exif_marker:
                length = struct.unpack(">H", data[idx + 2 : idx + 4])[0]
                payload = data[idx + 4 : idx + 2 + length]
                if payload.startswith(b"Exif\x00\x00"):
                    return parse_exif(payload[6:])
            idx += 1

    # Check PNG eXIf chunk
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        idx = 8
        while idx < len(data) - 8:
            length, chunk_type = struct.unpack(">I4s", data[idx : idx + 8])
            if chunk_type == b"eXIf":
                return parse_exif(data[idx + 8 : idx + 8 + length])
            idx += 12 + length

    # Check direct TIFF
    if data.startswith(b"II\x2a\x00") or data.startswith(b"MM\x00\x2a"):
        return parse_exif(data)

    return {}


# =============================================================================
# Channel Plane & Entropy Analysis
# =============================================================================


def _calc_entropy(counts: list[int], total: int) -> float:
    """Calculates Shannon entropy given byte frequency counts."""
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def analyze_channels(raw_pixels: bytes, channels: int = 3) -> dict[str, Any]:
    """Analyzes pixel bytes across channels (R, G, B, [A]).

    Calculates per-channel byte counts, Shannon entropy, and flags anomalous planes.
    """
    if not raw_pixels or channels <= 0:
        return {"error": "Invalid pixel data or channel count"}

    channel_names = ["Red", "Green", "Blue", "Alpha"][:channels]
    plane_data: list[list[int]] = [[] for _ in range(channels)]

    for i in range(0, len(raw_pixels) - (len(raw_pixels) % channels), channels):
        for c in range(channels):
            plane_data[c].append(raw_pixels[i + c])

    results: dict[str, Any] = {}
    entropies: dict[str, float] = {}

    for c, name in enumerate(channel_names):
        vals = plane_data[c]
        counts = [0] * 256
        for v in vals:
            counts[v] += 1
        ent = _calc_entropy(counts, len(vals))
        entropies[name] = round(ent, 4)
        results[name] = {
            "samples": len(vals),
            "entropy": round(ent, 4),
            "min": min(vals) if vals else 0,
            "max": max(vals) if vals else 0,
            "unique_values": sum(1 for cnt in counts if cnt > 0),
        }

    # Detect stego anomaly (e.g. one plane has significantly higher entropy)
    max_ent_ch = max(entropies, key=entropies.get)
    min_ent_ch = min(entropies, key=entropies.get)
    diff = entropies[max_ent_ch] - entropies[min_ent_ch]

    results["summary"] = {
        "channel_entropies": entropies,
        "max_entropy_channel": max_ent_ch,
        "entropy_spread": round(diff, 4),
        "suspect_plane_stego": diff > 1.5,
    }

    return results
