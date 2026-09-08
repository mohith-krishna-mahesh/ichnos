"""Centralized security primitives and input sanitization.

Guards against:
- Decompression bombs (zlib, gzip, bz2, xz) via bounded streaming decompression.
- Path traversal (Zip Slip, Tar Slip) via strict archive path sanitization.
- Terminal / ANSI escape injection via control character stripping.
"""

from __future__ import annotations

import bz2
import lzma
import re
import zlib
from pathlib import Path

# Limits
DEFAULT_MAX_DECOMPRESSED_SIZE = 64 * 1024 * 1024  # 64 MB
DEFAULT_MAX_EXPANSION_RATIO = 100.0  # 100:1 ratio for files > 1MB
DEFAULT_MAX_FILE_READ_SIZE = 100 * 1024 * 1024  # 100 MB

# ANSI Escape Sequences regex (OSC, CSI, and standard 2-byte escapes)
_ANSI_ESCAPE_PATTERN = re.compile(
    r"(?:\x1B\][^\x07\x1B]*(?:\x07|\x1B\\)"        # OSC sequences (e.g. OSC 52 clipboard)
    r"|\x1B\[[0-?]*[ -/]*[@-~]"                   # CSI sequences
    r"|\x1B[P^_][^\x1B]*(?:\x1B\\)?"              # DCS, PM, APC sequences
    r"|\x1B[@-Z\\_]"                              # 2-byte escape sequences
    r"|[\x80-\x9F][0-?]*[ -/]*[@-~]"              # 8-bit C1 controls
    r")"
)


def safe_decompress_zlib(
    data: bytes,
    max_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE,
    max_ratio: float = DEFAULT_MAX_EXPANSION_RATIO,
    wbits: int = zlib.MAX_WBITS,
) -> bytes:
    """Decompresses zlib/deflate data with running size and expansion ratio bounds.

    Raises:
        ValueError: If uncompressed data exceeds max_size or max_ratio.
    """
    dobj = zlib.decompressobj(wbits)
    out = bytearray()
    chunk_size = 64 * 1024

    for i in range(0, len(data), chunk_size):
        chunk = dobj.decompress(data[i : i + chunk_size], max_size - len(out) + 1)
        out.extend(chunk)
        if len(out) > max_size:
            raise ValueError(
                f"Decompression bomb detected: uncompressed size exceeded limit of {max_size} bytes"
            )

    out.extend(dobj.flush(max_size - len(out) + 1))
    if len(out) > max_size:
        raise ValueError(
            f"Decompression bomb detected: uncompressed size exceeded limit of {max_size} bytes"
        )

    # Check ratio for inputs > 100KB that yielded > 10MB
    if len(data) > 100 * 1024 and len(out) > 10 * 1024 * 1024:
        ratio = len(out) / max(1, len(data))
        if ratio > max_ratio:
            raise ValueError(
                f"Decompression bomb detected: expansion ratio {ratio:.1f}:1 exceeds limit {max_ratio}:1"
            )

    return bytes(out)


def safe_decompress_gzip(
    data: bytes,
    max_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE,
    max_ratio: float = DEFAULT_MAX_EXPANSION_RATIO,
) -> bytes:
    """Decompresses GZIP data (header 0x1F 0x8B) with running size checks."""
    # GZIP is raw deflate wrapped with 10-byte header and 8-byte trailer; wbits = 16 + MAX_WBITS
    return safe_decompress_zlib(data, max_size=max_size, max_ratio=max_ratio, wbits=16 + zlib.MAX_WBITS)


def safe_decompress_bz2(
    data: bytes,
    max_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE,
    max_ratio: float = DEFAULT_MAX_EXPANSION_RATIO,
) -> bytes:
    """Decompresses BZ2 data with running size checks."""
    dobj = bz2.BZ2Decompressor()
    out = bytearray()
    chunk_size = 64 * 1024

    for i in range(0, len(data), chunk_size):
        chunk = dobj.decompress(data[i : i + chunk_size], max_size - len(out) + 1)
        out.extend(chunk)
        if len(out) > max_size:
            raise ValueError(
                f"Decompression bomb detected: uncompressed size exceeded limit of {max_size} bytes"
            )

    if len(data) > 100 * 1024 and len(out) > 10 * 1024 * 1024:
        ratio = len(out) / max(1, len(data))
        if ratio > max_ratio:
            raise ValueError(
                f"Decompression bomb detected: expansion ratio {ratio:.1f}:1 exceeds limit {max_ratio}:1"
            )

    return bytes(out)


def safe_decompress_xz(
    data: bytes,
    max_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE,
    max_ratio: float = DEFAULT_MAX_EXPANSION_RATIO,
) -> bytes:
    """Decompresses XZ/LZMA data with running size checks."""
    dobj = lzma.LZMADecompressor()
    out = bytearray()
    chunk_size = 64 * 1024

    for i in range(0, len(data), chunk_size):
        chunk = dobj.decompress(data[i : i + chunk_size], max_size - len(out) + 1)
        out.extend(chunk)
        if len(out) > max_size:
            raise ValueError(
                f"Decompression bomb detected: uncompressed size exceeded limit of {max_size} bytes"
            )

    if len(data) > 100 * 1024 and len(out) > 10 * 1024 * 1024:
        ratio = len(out) / max(1, len(data))
        if ratio > max_ratio:
            raise ValueError(
                f"Decompression bomb detected: expansion ratio {ratio:.1f}:1 exceeds limit {max_ratio}:1"
            )

    return bytes(out)


def sanitize_archive_path(filename: str, target_dir: Path | None = None) -> str:
    """Sanitizes an archive member path to prevent Zip Slip / Tar Slip vulnerabilities.

    Rejects:
    - Path traversal sequences ('..')
    - Absolute paths (leading '/' or Windows drive spec like 'C:')
    - Null bytes

    Returns:
        Clean relative path string.
    Raises:
        ValueError: If path traversal or invalid characters are detected.
    """
    if "\x00" in filename:
        raise ValueError(f"Null byte detected in archive filename: {filename!r}")

    # Normalize slashes
    clean = filename.replace("\\", "/").strip()

    # Reject absolute paths
    if clean.startswith("/") or bool(re.match(r"^[a-zA-Z]:", clean)):
        raise ValueError(f"Path traversal detected: absolute path not allowed in archive ({filename!r})")

    parts = [p for p in clean.split("/") if p and p != "."]
    if ".." in parts:
        raise ValueError(f"Path traversal detected: '..' sequence not allowed in archive ({filename!r})")

    resolved_rel = "/".join(parts)

    if target_dir is not None:
        dest = (target_dir / resolved_rel).resolve()
        target_resolved = target_dir.resolve()
        try:
            dest.relative_to(target_resolved)
        except ValueError:
            raise ValueError(
                f"Path traversal detected: entry {filename!r} extracts outside target directory"
            )

    return resolved_rel


def sanitize_terminal_output(text: str) -> str:
    """Strips raw ANSI escape codes and dangerous terminal control characters.

    Protects against:
    - OSC 52 clipboard injection
    - Screen clears and cursor manipulation
    - Terminal title tampering
    """
    if not text:
        return text

    # 1. Strip ANSI escape sequences
    cleaned = _ANSI_ESCAPE_PATTERN.sub("", text)

    # 2. Filter dangerous ASCII control codes while preserving \n, \r, \t
    sanitized_chars = []
    for ch in cleaned:
        code = ord(ch)
        if code in (9, 10, 13) or code >= 32:
            sanitized_chars.append(ch)
        else:
            # Replace control characters (e.g. \x00, \x07 bell, \x08 backspace)
            sanitized_chars.append(" ")

    return "".join(sanitized_chars)
