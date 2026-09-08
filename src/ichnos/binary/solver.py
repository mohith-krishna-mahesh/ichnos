"""Automated Binary and Reverse Engineering Analysis Module.

Extracts sections, symbols, plaintext strings, and single-byte XOR obscured strings
from ELF, PE, and raw executable binaries to locate embedded CTF flags.
"""

from __future__ import annotations

from typing import Any

from ichnos.binary.elf import parse_elf
from ichnos.binary.identify import identify
from ichnos.binary.strings import extract_all
from ichnos.core.harvester import FLAG_PATTERN
from ichnos.crypto.xor.single_byte import brute_force as xor_brute_force


def solve_binary(data: bytes, filename: str = "binary") -> dict[str, Any]:
    """Runs automated static analysis and flag carving on binary executables."""
    file_info = identify(data)
    findings: list[str] = [f"Identified as {file_info['description']}"]
    found_flags: list[str] = []

    # 1. Direct string scan for plaintext flags
    strings = extract_all(data, min_length=4)
    for _, s, _ in strings:
        for match in FLAG_PATTERN.finditer(s):
            found_flags.append(match.group(0))

    if found_flags:
        return {
            "solved": True,
            "flag": found_flags[0],
            "method": "Plaintext string in binary",
            "file_type": file_info["type"],
            "findings": findings,
        }

    # 2. Section parsing if ELF
    if file_info["type"] == "elf":
        try:
            elf_info = parse_elf(data)
            findings.append(f"ELF Architecture: {elf_info.get('header', {}).get('machine')}")
            for sym in elf_info.get("symbols", []):
                sym_name = sym.get("name", "")
                for match in FLAG_PATTERN.finditer(sym_name):
                    found_flags.append(match.group(0))
        except Exception:
            pass

    if found_flags:
        return {
            "solved": True,
            "flag": found_flags[0],
            "method": "Symbol table flag extraction",
            "file_type": file_info["type"],
            "findings": findings,
        }

    # 3. Single-byte XOR scan on high-entropy or selected string chunks
    # Sample up to first 64KB for performance
    sample = data[:65536]
    xor_cands = xor_brute_force(sample)
    for cand in xor_cands:
        if cand.decoded_str:
            for match in FLAG_PATTERN.finditer(cand.decoded_str):
                return {
                    "solved": True,
                    "flag": match.group(0),
                    "method": f"Single-byte XOR decoded binary (key={cand.key})",
                    "file_type": file_info["type"],
                    "findings": findings,
                }

    return {
        "solved": False,
        "flag": None,
        "file_type": file_info["type"],
        "findings": findings,
    }
