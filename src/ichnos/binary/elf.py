"""ELF parsing."""

from __future__ import annotations

import struct

EI_CLASS_32 = 1
EI_CLASS_64 = 2
EI_DATA_LE = 1
EI_DATA_BE = 2

PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_SHLIB = 10
SHT_DYNSYM = 11

CLASS_MAP = {1: 32, 2: 64}
DATA_MAP = {1: "little", 2: "big"}
TYPE_MAP = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
MACHINE_MAP = {3: "386", 62: "X86_64", 40: "ARM", 183: "AARCH64", 8: "MIPS"}
PT_MAP = {
    0: "NULL",
    1: "LOAD",
    2: "DYNAMIC",
    3: "INTERP",
    4: "NOTE",
    5: "SHLIB",
    6: "PHDR",
    7: "TLS",
}


def parse_header(data: bytes) -> dict:
    if not data.startswith(b"\x7fELF") or len(data) < 52:
        raise ValueError("Not a valid ELF file")

    ei_class = data[4]
    ei_data = data[5]
    fmt = "<" if ei_data == EI_DATA_LE else ">"

    if ei_class == EI_CLASS_32:
        hdr_fmt = fmt + "HHIIIIIHHHHHH"
        hdr_size = 36
    elif ei_class == EI_CLASS_64:
        hdr_fmt = fmt + "HHIQQQIHHHHHH"
        hdr_size = 48
    else:
        raise ValueError("Unknown ELF class")

    unpacked = struct.unpack(hdr_fmt, data[16 : 16 + hdr_size])
    return {
        "class": CLASS_MAP.get(ei_class, ei_class),
        "endianness": DATA_MAP.get(ei_data, "little"),
        "osabi": data[7],
        "type": TYPE_MAP.get(unpacked[0], str(unpacked[0])),
        "machine": MACHINE_MAP.get(unpacked[1], str(unpacked[1])),
        "version": unpacked[2],
        "entry_point": unpacked[3],
        "phoff": unpacked[4],
        "shoff": unpacked[5],
        "flags": unpacked[6],
        "ehsize": unpacked[7],
        "phentsize": unpacked[8],
        "phnum": unpacked[9],
        "shentsize": unpacked[10],
        "shnum": unpacked[11],
        "shstrndx": unpacked[12],
    }


def parse_program_headers(data: bytes) -> list[dict]:
    hdr = parse_header(data)
    fmt = "<" if hdr["endianness"] in ("little", EI_DATA_LE) else ">"
    phoff, phentsize, phnum = hdr["phoff"], hdr["phentsize"], hdr["phnum"]

    headers = []
    for i in range(phnum):
        offset = phoff + i * phentsize
        chunk = data[offset : offset + phentsize]
        if hdr["class"] in (32, EI_CLASS_32):
            up = struct.unpack(fmt + "IIIIIIII", chunk[:32])
            flags_val = up[6]
            flag_str = f"{'R ' if flags_val & 4 else ''}{'W ' if flags_val & 2 else ''}{'X' if flags_val & 1 else ''}".strip()
            headers.append(
                {
                    "type": PT_MAP.get(up[0], str(up[0])),
                    "offset": up[1],
                    "vaddr": up[2],
                    "paddr": up[3],
                    "filesz": up[4],
                    "memsz": up[5],
                    "flags": flag_str,
                    "align": up[7],
                }
            )
        else:
            up = struct.unpack(fmt + "IIQQQQQQ", chunk[:56])
            flags_val = up[1]
            flag_str = f"{'R ' if flags_val & 4 else ''}{'W ' if flags_val & 2 else ''}{'X' if flags_val & 1 else ''}".strip()
            headers.append(
                {
                    "type": PT_MAP.get(up[0], str(up[0])),
                    "flags": flag_str,
                    "offset": up[2],
                    "vaddr": up[3],
                    "paddr": up[4],
                    "filesz": up[5],
                    "memsz": up[6],
                    "align": up[7],
                }
            )
    return headers


def parse_section_headers(data: bytes) -> list[dict]:
    hdr = parse_header(data)
    fmt = "<" if hdr["endianness"] in ("little", EI_DATA_LE) else ">"
    shoff, shentsize, shnum = hdr["shoff"], hdr["shentsize"], hdr["shnum"]

    sections = []
    for i in range(shnum):
        offset = shoff + i * shentsize
        chunk = data[offset : offset + shentsize]
        if hdr["class"] in (32, EI_CLASS_32):
            up = struct.unpack(fmt + "IIIIIIIIII", chunk[:40])
            sections.append(
                {
                    "name_idx": up[0],
                    "type": up[1],
                    "flags": up[2],
                    "addr": up[3],
                    "offset": up[4],
                    "size": up[5],
                    "link": up[6],
                    "info": up[7],
                    "addralign": up[8],
                    "entsize": up[9],
                }
            )
        else:
            up = struct.unpack(fmt + "IIQQQQIIQQ", chunk[:64])
            sections.append(
                {
                    "name_idx": up[0],
                    "type": up[1],
                    "flags": up[2],
                    "addr": up[3],
                    "offset": up[4],
                    "size": up[5],
                    "link": up[6],
                    "info": up[7],
                    "addralign": up[8],
                    "entsize": up[9],
                }
            )

    if hdr["shstrndx"] < len(sections):
        strtab_sec = sections[hdr["shstrndx"]]
        strtab = data[strtab_sec["offset"] : strtab_sec["offset"] + strtab_sec["size"]]
        for sec in sections:
            name_idx = sec["name_idx"]
            if name_idx < len(strtab):
                end = strtab.find(b"\x00", name_idx)
                sec["name"] = (
                    strtab[name_idx:end].decode("utf-8", errors="replace") if end != -1 else ""
                )
            else:
                sec["name"] = ""
    return sections


def parse_symbols(data: bytes) -> list[dict]:
    hdr = parse_header(data)
    fmt = "<" if hdr["endianness"] in ("little", EI_DATA_LE) else ">"
    sections = parse_section_headers(data)

    symbols = []
    for sec in sections:
        if sec["type"] in (SHT_SYMTAB, SHT_DYNSYM):
            strtab_sec = sections[sec["link"]]
            strtab = data[strtab_sec["offset"] : strtab_sec["offset"] + strtab_sec["size"]]
            ent_size = sec["entsize"] or (16 if hdr["class"] in (32, EI_CLASS_32) else 24)
            num_syms = sec["size"] // ent_size
            for i in range(num_syms):
                offset = sec["offset"] + i * ent_size
                chunk = data[offset : offset + ent_size]
                if hdr["class"] in (32, EI_CLASS_32):
                    up = struct.unpack(fmt + "IIIBBH", chunk[:16])
                    name_idx = up[0]
                    sym = {
                        "name": "",
                        "value": up[1],
                        "size": up[2],
                        "info": up[3],
                        "other": up[4],
                        "shndx": up[5],
                    }
                else:
                    up = struct.unpack(fmt + "IBBHQQ", chunk[:24])
                    name_idx = up[0]
                    sym = {
                        "name": "",
                        "info": up[1],
                        "other": up[2],
                        "shndx": up[3],
                        "value": up[4],
                        "size": up[5],
                    }
                sym["bind"] = sym["info"] >> 4
                sym["type"] = sym["info"] & 0xF
                sym["visibility"] = sym["other"] & 0x3
                if name_idx < len(strtab):
                    end = strtab.find(b"\x00", name_idx)
                    if end != -1:
                        sym["name"] = strtab[name_idx:end].decode("utf-8", errors="replace")
                symbols.append(sym)
    return symbols


def parse_elf(data: bytes) -> dict:
    return {
        "header": parse_header(data),
        "program_headers": parse_program_headers(data),
        "section_headers": parse_section_headers(data),
        "symbols": parse_symbols(data),
    }
