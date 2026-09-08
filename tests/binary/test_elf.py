import struct

import pytest

from ichnos.binary.elf import parse_header, parse_program_headers


@pytest.fixture
def elf64_le():
    # Minimal ELF64 LE executable header + one program header
    e_ident = (
        b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 8
    )  # class=64, data=LE, version=1, OSABI=0
    header = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # e_type: ET_EXEC
        62,  # e_machine: EM_X86_64
        1,  # e_version
        0x400000,  # e_entry
        64,  # e_phoff
        0,  # e_shoff
        0,  # e_flags
        64,  # e_ehsize
        56,  # e_phentsize
        1,  # e_phnum
        64,  # e_shentsize
        0,  # e_shnum
        0,  # e_shstrndx
    )
    # Program header (56 bytes)
    phdr = struct.pack(
        "<IIQQQQQQ",
        1,  # p_type: PT_LOAD
        5,  # p_flags: PF_R | PF_X
        0,  # p_offset
        0x400000,  # p_vaddr
        0x400000,  # p_paddr
        120,  # p_filesz
        120,  # p_memsz
        0x200000,  # p_align
    )
    return header + phdr


def test_parse_header(elf64_le):
    h = parse_header(elf64_le)
    assert h["class"] == 64
    assert h["endianness"] == "little"
    assert h["type"] == "EXEC"
    assert h["machine"] == "X86_64"
    assert h["entry_point"] == 0x400000


def test_parse_program_headers(elf64_le):
    phdrs = parse_program_headers(elf64_le)
    assert len(phdrs) == 1
    p = phdrs[0]
    assert p["type"] == "LOAD"
    assert p["vaddr"] == 0x400000
    assert p["flags"] == "R X"
