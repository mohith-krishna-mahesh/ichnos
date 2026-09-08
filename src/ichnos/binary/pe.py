"""Pure-Python PE (Portable Executable / Windows) parser.

Parses DOS headers, PE headers, COFF file headers, Optional Headers (PE32 and PE32+),
section tables, imported DLLs/functions, exported symbols, and overlay trailing data.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

MACHINE_TYPES: dict[int, str] = {
    0x014C: "x86 (i386)",
    0x8664: "x86-64 (AMD64)",
    0x01C0: "ARM",
    0xAA64: "ARM64 (AArch64)",
    0x0200: "Intel Itanium",
}

SUBSYSTEMS: dict[int, str] = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI (Console)",
    7: "POSIX CUI",
    9: "Windows CE",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
}

DATA_DIRECTORY_NAMES = [
    "Export Table",
    "Import Table",
    "Resource Table",
    "Exception Table",
    "Certificate Table",
    "Base Relocation Table",
    "Debug",
    "Architecture",
    "Global Ptr",
    "TLS Table",
    "Load Config Table",
    "Bound Import",
    "IAT",
    "Delay Import Descriptor",
    "CLR Runtime Header",
    "Reserved",
]


@dataclass
class PESection:
    """Represents a PE section header."""

    name: str
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    characteristics: int


def is_pe(data: bytes) -> bool:
    """Checks whether data is a valid PE binary."""
    if len(data) < 64 or data[:2] != b"MZ":
        return False
    e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
    return e_lfanew + 4 <= len(data) and data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"


def rva_to_offset(rva: int, sections: list[PESection]) -> int | None:
    """Translates a Relative Virtual Address (RVA) to a raw file offset."""
    for sec in sections:
        va = sec.virtual_address
        vsz = max(sec.virtual_size, sec.size_of_raw_data)
        if va <= rva < va + vsz:
            return rva - va + sec.pointer_to_raw_data
    return None


def parse_pe(data: bytes) -> dict[str, Any]:
    """Parses a Portable Executable (PE) binary and extracts full metadata."""
    if not is_pe(data):
        raise ValueError("Invalid PE executable: missing MZ or PE signature")

    e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
    coff_off = e_lfanew + 4

    if coff_off + 20 > len(data):
        raise ValueError("Truncated PE COFF header")

    machine, num_sections, timestamp, _, _, opt_hdr_sz, chars = struct.unpack(
        "<HHIIIHH", data[coff_off : coff_off + 20]
    )
    num_sections = min(max(0, num_sections), 256)

    opt_off = coff_off + 20
    is_64 = False
    entry_point = 0
    image_base = 0
    subsystem = 0
    data_dirs: list[dict[str, Any]] = []

    if opt_hdr_sz > 0 and opt_off + min(opt_hdr_sz, len(data) - opt_off) >= opt_off + 2:
        try:
            magic = struct.unpack("<H", data[opt_off : opt_off + 2])[0]
            is_64 = magic == 0x020B
            if opt_off + 20 <= len(data):
                entry_point = struct.unpack("<I", data[opt_off + 16 : opt_off + 20])[0]

            if is_64 and opt_off + 70 <= len(data):
                image_base = struct.unpack("<Q", data[opt_off + 24 : opt_off + 32])[0]
                subsystem = struct.unpack("<H", data[opt_off + 68 : opt_off + 70])[0]
                dirs_off = opt_off + 112
            elif not is_64 and opt_off + 70 <= len(data):
                image_base = struct.unpack("<I", data[opt_off + 28 : opt_off + 32])[0]
                subsystem = struct.unpack("<H", data[opt_off + 68 : opt_off + 70])[0]
                dirs_off = opt_off + 96
            else:
                dirs_off = opt_off + 112 if is_64 else opt_off + 96

            for i in range(16):
                if dirs_off + (i + 1) * 8 <= min(opt_off + opt_hdr_sz, len(data)):
                    rva, sz = struct.unpack("<II", data[dirs_off + i * 8 : dirs_off + (i + 1) * 8])
                    name = DATA_DIRECTORY_NAMES[i] if i < len(DATA_DIRECTORY_NAMES) else f"Dir_{i}"
                    data_dirs.append({"name": name, "rva": rva, "size": sz})
        except struct.error:
            pass

    # Parse Sections
    sec_off = opt_off + opt_hdr_sz
    sections: list[PESection] = []
    for i in range(num_sections):
        if sec_off + (i + 1) * 40 > len(data):
            break
        s_data = data[sec_off + i * 40 : sec_off + (i + 1) * 40]
        try:
            name = s_data[:8].rstrip(b"\x00").decode("latin-1", errors="replace")
            vsz, va, rsz, rptr, _, _, _, _, s_chars = struct.unpack("<IIIIIIHHI", s_data[8:40])
            sections.append(
                PESection(
                    name=name,
                    virtual_size=vsz,
                    virtual_address=va,
                    size_of_raw_data=rsz,
                    pointer_to_raw_data=rptr,
                    characteristics=s_chars,
                )
            )
        except struct.error:
            break

    # Detect Overlay
    max_raw_end = max((s.pointer_to_raw_data + s.size_of_raw_data for s in sections), default=0)
    overlay = data[max_raw_end:] if len(data) > max_raw_end else None

    # Parse Imports
    imports = _parse_imports(data, data_dirs, sections, is_64)

    return {
        "machine": MACHINE_TYPES.get(machine, f"0x{machine:04X}"),
        "is_64bit": is_64,
        "is_dll": bool(chars & 0x2000),
        "timestamp": timestamp,
        "entry_point": hex(entry_point),
        "image_base": hex(image_base),
        "subsystem": SUBSYSTEMS.get(subsystem, f"0x{subsystem:04X}"),
        "num_sections": len(sections),
        "sections": [
            {
                "name": s.name,
                "virtual_size": s.virtual_size,
                "virtual_address": hex(s.virtual_address),
                "raw_size": s.size_of_raw_data,
                "raw_offset": hex(s.pointer_to_raw_data),
            }
            for s in sections
        ],
        "data_directories": [d for d in data_dirs if d["rva"] > 0],
        "imports": imports,
        "overlay_len": len(overlay) if overlay else 0,
        "has_overlay": overlay is not None,
    }


def _parse_imports(
    data: bytes, data_dirs: list[dict[str, Any]], sections: list[PESection], is_64: bool
) -> dict[str, list[str]]:
    """Extracts imported DLLs and function names from the Import Directory Table."""
    imports: dict[str, list[str]] = {}
    import_dir = next((d for d in data_dirs if d["name"] == "Import Table"), None)
    if not import_dir or import_dir["rva"] == 0:
        return imports

    idt_offset = rva_to_offset(import_dir["rva"], sections)
    if idt_offset is None or idt_offset >= len(data):
        return imports

    curr = idt_offset
    descriptor_count = 0
    while curr + 20 <= len(data) and descriptor_count < 2048:
        descriptor_count += 1
        try:
            orig_first_thunk, _, _, name_rva, first_thunk = struct.unpack(
                "<IIIII", data[curr : curr + 20]
            )
        except struct.error:
            break
        if orig_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
            break
        curr += 20

        # Read DLL name
        dll_offset = rva_to_offset(name_rva, sections)
        if dll_offset is None or dll_offset >= len(data):
            continue

        dll_name_bytes = bytearray()
        pos = dll_offset
        while pos < len(data) and data[pos] != 0 and len(dll_name_bytes) < 256:
            dll_name_bytes.append(data[pos])
            pos += 1
        dll_name = dll_name_bytes.decode("latin-1", errors="replace")

        # Read functions from lookup table (thunk table)
        thunk_rva = orig_first_thunk if orig_first_thunk != 0 else first_thunk
        thunk_offset = rva_to_offset(thunk_rva, sections)
        functions: list[str] = []

        if thunk_offset is not None:
            entry_size = 8 if is_64 else 4
            t_pos = thunk_offset
            while t_pos + entry_size <= len(data) and len(functions) < 4096:
                try:
                    entry_val = (
                        struct.unpack("<Q", data[t_pos : t_pos + 8])[0]
                        if is_64
                        else struct.unpack("<I", data[t_pos : t_pos + 4])[0]
                    )
                except struct.error:
                    break
                if entry_val == 0:
                    break
                t_pos += entry_size

                # Check ordinal flag (MSB set)
                is_ordinal = bool(entry_val & (0x8000000000000000 if is_64 else 0x80000000))
                if is_ordinal:
                    ordinal = entry_val & 0xFFFF
                    functions.append(f"Ordinal_{ordinal}")
                else:
                    # Pointer to IMAGE_IMPORT_BY_NAME: 2-byte Hint + ASCII Name
                    mask = 0x7FFFFFFFFFFFFFFF if is_64 else 0x7FFFFFFF
                    name_ptr = rva_to_offset(entry_val & mask, sections)
                    if name_ptr and name_ptr + 2 < len(data):
                        fn_bytes = bytearray()
                        fn_pos = name_ptr + 2
                        while fn_pos < len(data) and data[fn_pos] != 0 and len(fn_bytes) < 256:
                            fn_bytes.append(data[fn_pos])
                            fn_pos += 1
                        functions.append(fn_bytes.decode("latin-1", errors="replace"))

        imports[dll_name] = functions

    return imports


def detect_overlay(data: bytes) -> bytes | None:
    """Extracts trailing overlay data appended after the last PE section."""
    if not is_pe(data):
        return None
    try:
        info = parse_pe(data)
    except Exception:
        return None
    if not info["has_overlay"]:
        return None
    e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
    coff_off = e_lfanew + 4
    num_sections, opt_hdr_sz = (
        struct.unpack("<HH", data[coff_off + 2 : coff_off + 6])[0],
        struct.unpack("<H", data[coff_off + 16 : coff_off + 18])[0],
    )
    num_sections = min(max(0, num_sections), 256)
    sec_off = coff_off + 20 + opt_hdr_sz

    max_end = 0
    for i in range(num_sections):
        if sec_off + (i + 1) * 40 > len(data):
            break
        s_data = data[sec_off + i * 40 : sec_off + (i + 1) * 40]
        try:
            rsz, rptr = struct.unpack("<II", s_data[16:24])
            max_end = max(max_end, rptr + rsz)
        except struct.error:
            break

    return data[max_end:] if len(data) > max_end else None
