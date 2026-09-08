"""Packer and protector detection heuristics (UPX, ASPack, VMProtect, Themida).

Analyzes section names, import table footprints, high-entropy anomalies,
and signature markers to identify compressed or protected binaries.
"""

from __future__ import annotations

from typing import Any

from ichnos.binary.entropy import sliding_window_entropy, whole_file_entropy
from ichnos.binary.identify import identify

KNOWN_PACKER_SECTIONS: dict[str, str] = {
    "UPX0": "UPX",
    "UPX1": "UPX",
    "UPX2": "UPX",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    "PEC2": "PECompact",
    "PEC2TO": "PECompact",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".themida": "Themida",
    "Themida": "Themida",
    ".MPRESS1": "MPRESS",
    ".MPRESS2": "MPRESS",
    ".nsp0": "NsPack",
    ".petite": "Petite",
}


def detect_upx(data: bytes) -> dict[str, Any]:
    """Detects UPX packer signatures and headers."""
    has_upx_magic = b"UPX!" in data
    has_upx0 = b"UPX0" in data
    has_upx1 = b"UPX1" in data

    is_upx = has_upx_magic or (has_upx0 and has_upx1)
    version = None
    offset = None

    if has_upx_magic:
        pos = data.find(b"UPX!")
        offset = pos
        # UPX header: 'UPX!' followed by 1-byte version, 1-byte format, 1-byte method, 1-byte level
        if pos + 8 <= len(data):
            ver_byte = data[pos + 4]
            version = f"{ver_byte // 10}.{ver_byte % 10}"

    return {
        "is_upx": is_upx,
        "upx_magic_found": has_upx_magic,
        "upx_sections_found": has_upx0 or has_upx1,
        "version": version,
        "offset": hex(offset) if offset is not None else None,
    }


def detect_packer(data: bytes) -> dict[str, Any]:
    """Runs heuristic checks to detect whether a binary is packed or obfuscated."""
    file_info = identify(data)
    entropy = whole_file_entropy(data)
    upx_info = detect_upx(data)

    detected_packers: list[str] = []
    reasons: list[str] = []

    if upx_info["is_upx"]:
        detected_packers.append("UPX")
        reasons.append(f"UPX signature/section detected (ver: {upx_info['version']})")

    # Check known section strings
    for sec_name, packer_name in KNOWN_PACKER_SECTIONS.items():
        if sec_name.encode("latin-1") in data:
            if packer_name not in detected_packers:
                detected_packers.append(packer_name)
                reasons.append(f"Known packed section name found: {sec_name}")

    # Entropy heuristic: executable binary with overall entropy > 7.2 is likely packed
    is_executable = file_info.get("type") in ("elf", "pe", "macho")
    if is_executable and entropy > 7.2:
        reasons.append(
            f"High whole-file entropy ({entropy:.2f} / 8.0) typical of compression/encryption"
        )

    # Sliding window high-entropy density
    windows = sliding_window_entropy(data, window_size=256, step=128)
    high_entropy_count = sum(1 for _, ent in windows if ent > 7.5)
    high_entropy_ratio = high_entropy_count / max(len(windows), 1)

    if high_entropy_ratio > 0.6 and "High whole-file entropy" not in reasons:
        reasons.append(
            f"{high_entropy_ratio * 100:.1f}% of binary blocks have extreme entropy > 7.5"
        )

    is_packed = len(detected_packers) > 0 or (is_executable and entropy > 7.3)

    return {
        "is_packed": is_packed,
        "identified_packers": detected_packers,
        "confidence": 0.95
        if detected_packers
        else (0.75 if (is_executable and entropy > 7.3) else 0.1),
        "entropy": round(entropy, 4),
        "high_entropy_block_ratio": round(high_entropy_ratio, 4),
        "indicators": reasons,
    }
