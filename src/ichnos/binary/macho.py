"""Pure-Python Mach-O (macOS / iOS) binary parser.

Supports 32-bit and 64-bit architectures, Little-Endian and Big-Endian,
FAT/Universal binaries, load commands, segment and section mapping,
dynamic library dependencies, and symbol tables.
"""

from __future__ import annotations

import struct
from typing import Any

# Mach-O Magic Numbers
MH_MAGIC = 0xFEEDFACE  # 32-bit BE
MH_CIGAM = 0xCEFAEDFE  # 32-bit LE
MH_MAGIC_64 = 0xFEEDFACF  # 64-bit BE
MH_CIGAM_64 = 0xCFFAEDFE  # 64-bit LE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

CPU_TYPES: dict[int, str] = {
    7: "x86",
    0x01000007: "x86_64",
    12: "ARM",
    0x0100000C: "ARM64",
    18: "PowerPC",
    0x01000012: "PowerPC64",
}

FILE_TYPES: dict[int, str] = {
    1: "OBJECT",
    2: "EXECUTE",
    3: "FVMLIB",
    4: "CORE",
    5: "PRELOAD",
    6: "DYLIB",
    7: "DYLINKER",
    8: "BUNDLE",
    9: "DYLIB_STUB",
    10: "DSYM",
    11: "KEXT_BUNDLE",
}

# Load Commands
LC_SEGMENT = 0x01
LC_SYMTAB = 0x02
LC_DYSYMTAB = 0x0B
LC_LOAD_DYLIB = 0x0C
LC_ID_DYLIB = 0x0D
LC_LOAD_DYLINKER = 0x0E
LC_SEGMENT_64 = 0x19
LC_MAIN = 0x80000028


def is_macho(data: bytes) -> bool:
    """Checks whether data is a valid Mach-O or FAT binary."""
    if len(data) < 4:
        return False
    magic = struct.unpack(">I", data[:4])[0]
    return magic in (
        MH_MAGIC,
        MH_CIGAM,
        MH_MAGIC_64,
        MH_CIGAM_64,
        FAT_MAGIC,
        FAT_CIGAM,
    )


def parse_macho(data: bytes) -> dict[str, Any]:
    """Parses a Mach-O binary and extracts metadata, segments, sections, and dylibs."""
    if not is_macho(data):
        raise ValueError("Invalid Mach-O binary: unrecognized magic number")

    raw_magic = struct.unpack(">I", data[:4])[0]

    # Handle FAT / Universal binary
    if raw_magic in (FAT_MAGIC, FAT_CIGAM):
        endian = ">" if raw_magic == FAT_MAGIC else "<"
        nfat_arch = struct.unpack(f"{endian}I", data[4:8])[0]
        arches = []
        for i in range(nfat_arch):
            off = 8 + i * 20
            if off + 20 <= len(data):
                cputype, cpusub, fileoff, sz, _ = struct.unpack(
                    f"{endian}IIIII", data[off : off + 20]
                )
                arches.append(
                    {
                        "cpu": CPU_TYPES.get(cputype, f"0x{cputype:08X}"),
                        "offset": fileoff,
                        "size": sz,
                    }
                )
        return {
            "format": "Mach-O Universal / FAT Binary",
            "is_fat": True,
            "architectures_count": nfat_arch,
            "architectures": arches,
        }

    # Single Architecture Mach-O
    if raw_magic in (MH_MAGIC, MH_CIGAM):
        is_64 = False
        endian = ">" if raw_magic == MH_MAGIC else "<"
        hdr_size = 28
    else:
        is_64 = True
        endian = ">" if raw_magic == MH_MAGIC_64 else "<"
        hdr_size = 32

    if len(data) < hdr_size:
        raise ValueError("Truncated Mach-O header")

    cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack(
        f"{endian}IIIIII", data[4:28]
    )

    segments: list[dict[str, Any]] = []
    dylibs: list[str] = []
    entry_point: str | None = None
    symbols_count = 0

    curr = hdr_size
    for _ in range(ncmds):
        if curr + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack(f"{endian}II", data[curr : curr + 8])
        cmd_data = data[curr : curr + cmdsize]

        if cmd in (LC_SEGMENT, LC_SEGMENT_64):
            if is_64 and len(cmd_data) >= 72:
                segname = cmd_data[8:24].rstrip(b"\x00").decode("latin-1", errors="replace")
                vmaddr, vmsize, fileoff, filesize, _, _, nsects, sflags = struct.unpack(
                    f"{endian}QQQQIIII", cmd_data[24:72]
                )
                sections = []
                sec_ptr = 72
                for _ in range(nsects):
                    if sec_ptr + 80 <= len(cmd_data):
                        sname = (
                            cmd_data[sec_ptr : sec_ptr + 16]
                            .rstrip(b"\x00")
                            .decode("latin-1", errors="replace")
                        )
                        saddr, ssize, soff = struct.unpack(
                            f"{endian}QQI", cmd_data[sec_ptr + 32 : sec_ptr + 52]
                        )
                        sections.append(
                            {"name": sname, "addr": hex(saddr), "size": ssize, "offset": soff}
                        )
                        sec_ptr += 80
                segments.append(
                    {
                        "name": segname,
                        "vmaddr": hex(vmaddr),
                        "vmsize": vmsize,
                        "fileoff": fileoff,
                        "filesize": filesize,
                        "sections": sections,
                    }
                )
            elif not is_64 and len(cmd_data) >= 56:
                segname = cmd_data[8:24].rstrip(b"\x00").decode("latin-1", errors="replace")
                vmaddr, vmsize, fileoff, filesize, _, _, nsects, sflags = struct.unpack(
                    f"{endian}IIIIIIII", cmd_data[24:56]
                )
                segments.append(
                    {
                        "name": segname,
                        "vmaddr": hex(vmaddr),
                        "vmsize": vmsize,
                        "fileoff": fileoff,
                        "filesize": filesize,
                        "sections_count": nsects,
                    }
                )

        elif cmd == LC_LOAD_DYLIB and len(cmd_data) >= 24:
            str_off = struct.unpack(f"{endian}I", cmd_data[8:12])[0]
            if str_off < len(cmd_data):
                dylib_str = (
                    cmd_data[str_off:].split(b"\x00", 1)[0].decode("latin-1", errors="replace")
                )
                dylibs.append(dylib_str)

        elif cmd == LC_MAIN and len(cmd_data) >= 24:
            entryoff = struct.unpack(f"{endian}Q", cmd_data[8:16])[0]
            entry_point = hex(entryoff)

        elif cmd == LC_SYMTAB and len(cmd_data) >= 24:
            nsyms = struct.unpack(f"{endian}I", cmd_data[12:16])[0]
            symbols_count = nsyms

        curr += cmdsize

    return {
        "format": "Mach-O 64-bit" if is_64 else "Mach-O 32-bit",
        "is_64bit": is_64,
        "is_fat": False,
        "endianness": "little" if endian == "<" else "big",
        "cpu": CPU_TYPES.get(cputype, f"0x{cputype:08X}"),
        "filetype": FILE_TYPES.get(filetype, f"0x{filetype:04X}"),
        "num_commands": ncmds,
        "entry_point": entry_point,
        "symbols_count": symbols_count,
        "segments": segments,
        "linked_dylibs": dylibs,
    }
