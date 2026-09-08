"""Shared heuristics — entropy, magic bytes, printable-ratio, chi-square scoring."""

from __future__ import annotations

import math
from collections import Counter

# ---------------------------------------------------------------------------
# Magic-byte file-type signature table
# ---------------------------------------------------------------------------

MAGIC_TABLE: list[tuple[bytes, str, int]] = [
    # (signature_bytes, type_name, offset)
    (b"\x89PNG\r\n\x1a\n", "png", 0),
    (b"\xff\xd8\xff", "jpeg", 0),
    (b"GIF87a", "gif", 0),
    (b"GIF89a", "gif", 0),
    (b"BM", "bmp", 0),
    (b"RIFF", "riff", 0),  # WAV/AVI — need secondary check
    (b"\x7fELF", "elf", 0),
    (b"MZ", "pe", 0),
    (b"\xfe\xed\xfa\xce", "macho32_be", 0),
    (b"\xce\xfa\xed\xfe", "macho32_le", 0),
    (b"\xfe\xed\xfa\xcf", "macho64_be", 0),
    (b"\xcf\xfa\xed\xfe", "macho64_le", 0),
    (b"\xca\xfe\xba\xbe", "macho_universal", 0),
    (b"%PDF", "pdf", 0),
    (b"PK\x03\x04", "zip", 0),
    (b"PK\x05\x06", "zip_empty", 0),
    (b"\x1f\x8b", "gzip", 0),
    (b"BZh", "bzip2", 0),
    (b"\xfd7zXZ\x00", "xz", 0),
    (b"7z\xbc\xaf\x27\x1c", "7z", 0),
    (b"ustar", "tar", 257),  # tar magic at offset 257
    (b"\x00asm", "wasm", 0),
    (b"OggS", "ogg", 0),
    (b"fLaC", "flac", 0),
    (b"ID3", "mp3_id3", 0),
    (b"\xff\xfb", "mp3", 0),
    (b"\xff\xf3", "mp3", 0),
    (b"\xff\xf2", "mp3", 0),
]


def detect_file_type(data: bytes) -> str:
    """Identify file type from magic bytes.

    Returns a short type identifier string, or 'unknown'.
    """
    if len(data) < 4:
        return "unknown"

    for sig, type_name, offset in MAGIC_TABLE:
        end = offset + len(sig)
        if len(data) >= end and data[offset:end] == sig:
            # Secondary check for RIFF containers
            if type_name == "riff" and len(data) >= 12:
                fourcc = data[8:12]
                if fourcc == b"WAVE":
                    return "wav"
                if fourcc == b"AVI ":
                    return "avi"
                return "riff"
            return type_name

    # Heuristic fallback: text vs binary
    ratio = printable_ratio(data[:4096])
    if ratio > 0.85:
        return "text"
    return "binary"


# ---------------------------------------------------------------------------
# Shannon entropy
# ---------------------------------------------------------------------------


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data (0.0 – 8.0 for bytes)."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------
# Chi-square statistic
# ---------------------------------------------------------------------------


def chi_square(data: bytes) -> float:
    """Chi-square statistic testing uniform byte distribution.

    Lower values suggest the data is closer to uniformly random (encrypted/compressed).
    A perfectly uniform distribution of 256 byte values gives χ² ≈ 0.
    English text typically gives χ² >> 256.
    """
    if not data:
        return 0.0
    length = len(data)
    expected = length / 256.0
    counts = Counter(data)
    chi_sq = 0.0
    for byte_val in range(256):
        observed = counts.get(byte_val, 0)
        diff = observed - expected
        chi_sq += (diff * diff) / expected
    return chi_sq


def chi_square_letters(text: str) -> float:
    """Chi-square statistic against English letter frequency distribution.

    Used for scoring whether text looks like English.
    Lower = more English-like.
    """
    english_freq = {
        "A": 0.08167,
        "B": 0.01492,
        "C": 0.02782,
        "D": 0.04253,
        "E": 0.12702,
        "F": 0.02228,
        "G": 0.02015,
        "H": 0.06094,
        "I": 0.06966,
        "J": 0.00153,
        "K": 0.00772,
        "L": 0.04025,
        "M": 0.02406,
        "N": 0.06749,
        "O": 0.07507,
        "P": 0.01929,
        "Q": 0.00095,
        "R": 0.05987,
        "S": 0.06327,
        "T": 0.09056,
        "U": 0.02758,
        "V": 0.00978,
        "W": 0.02360,
        "X": 0.00150,
        "Y": 0.01974,
        "Z": 0.00074,
    }
    upper = text.upper()
    letters_only = [c for c in upper if c.isalpha()]
    if not letters_only:
        return float("inf")

    length = len(letters_only)
    counts = Counter(letters_only)
    chi_sq = 0.0
    for letter, freq in english_freq.items():
        expected = freq * length
        observed = counts.get(letter, 0)
        if expected > 0:
            chi_sq += ((observed - expected) ** 2) / expected
    return chi_sq


# ---------------------------------------------------------------------------
# Printable-ASCII ratio
# ---------------------------------------------------------------------------


def printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII (0x20–0x7E, plus \\t\\n\\r)."""
    if not data:
        return 0.0
    printable_set = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
    count = sum(1 for b in data if b in printable_set)
    return count / len(data)


# ---------------------------------------------------------------------------
# Composite heuristics
# ---------------------------------------------------------------------------


def is_likely_encrypted(data: bytes) -> bool:
    """Heuristic: high entropy + low printable ratio suggests encryption/compression."""
    if len(data) < 16:
        return False
    ent = shannon_entropy(data)
    pr = printable_ratio(data)
    return ent > 7.5 and pr < 0.3


def is_likely_english(text: str) -> bool:
    """Quick heuristic check if text looks like English."""
    chi = chi_square_letters(text)
    return chi < 100.0


def english_score(text: str) -> float:
    """Score how English-like text is. Higher = more English-like.

    Returns a 0–1 score based on inverse chi-square.
    """
    chi = chi_square_letters(text)
    if chi == float("inf"):
        return 0.0
    # Normalize: chi=0 → score=1.0, chi=500 → score≈0
    return max(0.0, 1.0 - chi / 500.0)


# ---------------------------------------------------------------------------
# English letter frequencies (exported for use by cipher modules)
# ---------------------------------------------------------------------------

ENGLISH_FREQ: dict[str, float] = {
    "A": 0.08167,
    "B": 0.01492,
    "C": 0.02782,
    "D": 0.04253,
    "E": 0.12702,
    "F": 0.02228,
    "G": 0.02015,
    "H": 0.06094,
    "I": 0.06966,
    "J": 0.00153,
    "K": 0.00772,
    "L": 0.04025,
    "M": 0.02406,
    "N": 0.06749,
    "O": 0.07507,
    "P": 0.01929,
    "Q": 0.00095,
    "R": 0.05987,
    "S": 0.06327,
    "T": 0.09056,
    "U": 0.02758,
    "V": 0.00978,
    "W": 0.02360,
    "X": 0.00150,
    "Y": 0.01974,
    "Z": 0.00074,
}
