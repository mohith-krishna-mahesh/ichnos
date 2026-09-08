"""Archive inspection and forensics (TAR, GZ, BZ2, XZ, 7z, RAR).

Inspects archive contents, member file permissions, timestamps, hidden files,
and compression metadata using standard library tools and pure-Python header parsers.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import struct
import tarfile
from typing import Any

from ichnos.forensic.zip import inspect_zip


def inspect_tar(data: bytes) -> dict[str, Any]:
    """Inspects a TAR archive and returns entries, permissions, owners, and timestamps."""
    f = io.BytesIO(data)
    try:
        with tarfile.open(fileobj=f, mode="r:*") as tar:
            members = []
            total_size = 0
            for m in tar.getmembers():
                members.append(
                    {
                        "name": m.name,
                        "size": m.size,
                        "mode": oct(m.mode),
                        "mtime": m.mtime,
                        "uid": m.uid,
                        "gid": m.gid,
                        "uname": m.uname,
                        "gname": m.gname,
                        "is_file": m.isfile(),
                        "is_dir": m.isdir(),
                        "is_symlink": m.issym(),
                        "link_target": m.linkname if m.issym() else None,
                    }
                )
                total_size += m.size

            return {
                "format": "tar",
                "total_entries": len(members),
                "total_size": total_size,
                "entries": members,
            }
    except Exception as e:
        raise ValueError(f"Failed to inspect TAR archive: {e}") from e


def inspect_7z_header(data: bytes) -> dict[str, Any]:
    """Parses 7z signature and archive header (magic: 7z\\xBC\\xAF\\x27\\x1C)."""
    if len(data) < 32 or data[:6] != b"7z\xbc\xaf'\x1c":
        raise ValueError("Invalid 7z archive: missing 7z signature")

    ver_major, ver_minor = data[6], data[7]
    start_hdr_crc = struct.unpack("<I", data[8:12])[0]
    next_hdr_offset = struct.unpack("<Q", data[12:20])[0]
    next_hdr_size = struct.unpack("<Q", data[20:28])[0]
    next_hdr_crc = struct.unpack("<I", data[28:32])[0]

    return {
        "format": "7z",
        "version": f"{ver_major}.{ver_minor}",
        "start_header_crc": hex(start_hdr_crc),
        "next_header_offset": hex(next_hdr_offset),
        "next_header_size": next_hdr_size,
        "next_header_crc": hex(next_hdr_crc),
    }


def inspect_rar_header(data: bytes) -> dict[str, Any]:
    """Parses RAR signature (RAR4: Rar!\\x1A\\x07\\x00, RAR5: Rar!\\x1A\\x07\\x01\\x00)."""
    if data.startswith(b"Rar!\x1a\x07\x01\x00"):
        ver = "RAR5"
    elif data.startswith(b"Rar!\x1a\x07\x00"):
        ver = "RAR4"
    else:
        raise ValueError("Invalid RAR archive: missing RAR signature")

    return {
        "format": "rar",
        "version": ver,
        "size": len(data),
    }


def decompress_stream(data: bytes) -> tuple[str, bytes]:
    """Decompresses single-stream compressed data (gzip, bz2, xz).

    Returns tuple: `(algorithm: str, decompressed_bytes: bytes)`.
    """
    # GZIP (0x1F 0x8B)
    if data.startswith(b"\x1f\x8b"):
        return "gzip", gzip.decompress(data)
    # BZIP2 ('BZh')
    if data.startswith(b"BZh"):
        return "bz2", bz2.decompress(data)
    # XZ (0xFD '7zXZ\x00')
    if data.startswith(b"\xfd7zXZ\x00"):
        return "xz", lzma.decompress(data)

    raise ValueError("Unrecognized compressed stream format")


def inspect_archive(data: bytes) -> dict[str, Any]:
    """Auto-detects and inspects any supported archive format."""
    # ZIP
    if data.startswith(b"PK\x03\x04"):
        return {"format": "zip", **inspect_zip(data)}
    # 7z
    if data.startswith(b"7z\xbc\xaf'\x1c"):
        return inspect_7z_header(data)
    # RAR
    if data.startswith(b"Rar!\x1a\x07"):
        return inspect_rar_header(data)
    # GZIP
    if data.startswith(b"\x1f\x8b"):
        algo, dec = decompress_stream(data)
        return {"format": algo, "decompressed_size": len(dec)}
    # BZ2
    if data.startswith(b"BZh"):
        algo, dec = decompress_stream(data)
        return {"format": algo, "decompressed_size": len(dec)}
    # XZ
    if data.startswith(b"\xfd7zXZ\x00"):
        algo, dec = decompress_stream(data)
        return {"format": algo, "decompressed_size": len(dec)}
    # TAR
    try:
        return inspect_tar(data)
    except Exception:
        pass

    raise ValueError("Unsupported or corrupted archive format")
