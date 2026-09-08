"""Unit tests for Phase F Binary Expansion: PE parser, Mach-O parser, and Packer detection."""

from __future__ import annotations

import struct

from typer.testing import CliRunner

from ichnos.binary import macho, packer, pe
from ichnos.cli.main import app

runner = CliRunner()


def make_synthetic_pe(with_overlay: bool = True) -> bytes:
    """Helper to construct a valid minimal synthetic PE64 executable."""
    dos = bytearray(b"MZ" + b"\x00" * 58)
    dos += struct.pack("<I", 0x80)
    dos += b"\x00" * (0x80 - len(dos))

    # PE Signature
    pe_sig = b"PE\x00\x00"
    # COFF File Header: machine 0x8664 (x64), 1 section, 0 timestamp, 0 sym, 0 nsym, 240 opt size, chars 0x0022
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x0022)

    # Optional Header (PE32+ 64-bit): magic 0x020B
    opt = bytearray(struct.pack("<H", 0x020B))
    opt += b"\x00" * 14  # linker / code size
    opt += struct.pack("<I", 0x1000)  # entry point
    opt += struct.pack("<I", 0x1000)  # code base
    opt += struct.pack("<Q", 0x140000000)  # image base
    opt += struct.pack("<II", 0x1000, 0x200)  # section align, file align
    opt += b"\x00" * 16
    opt += struct.pack("<I", 0x3000)  # size of image
    opt += struct.pack("<I", 0x200)  # size of headers
    opt += struct.pack("<I", 0)  # checksum
    opt += struct.pack("<H", 3)  # subsystem (CUI)
    opt += struct.pack("<H", 0x8160)  # dll chars
    opt += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16)
    opt += b"\x00" * 128  # Data directories

    # Section Header (40 bytes)
    sec = bytearray(b".text\x00\x00\x00")
    sec += struct.pack("<IIIIIIHHI", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)

    hdr = dos + pe_sig + coff + opt + sec
    hdr += b"\x00" * (0x200 - len(hdr))
    code = b"\x90" * 0x200
    overlay = b"SECRET_PE_OVERLAY_FLAG" if with_overlay else b""

    return bytes(hdr + code + overlay)


def make_synthetic_macho() -> bytes:
    """Helper to construct a valid minimal synthetic 64-bit Mach-O binary."""
    # MH_MAGIC_64 (0xFEEDFACF) in Little Endian is 0xCFFAEDFE
    magic = 0xFEEDFACF
    cputype = 0x0100000C  # ARM64
    cpusubtype = 0
    filetype = 2  # EXECUTE
    ncmds = 1
    sizeofcmds = 72
    flags = 0x00200085
    reserved = 0
    hdr = struct.pack(
        "<IIIIIIII", magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved
    )

    # LC_SEGMENT_64 (0x19), cmdsize 72
    cmd = 0x19
    cmdsize = 72
    segname = b"__PAGEZERO\x00\x00\x00\x00\x00\x00"
    vmaddr = 0
    vmsize = 0x100000000
    fileoff = 0
    filesize = 0
    maxprot = 0
    initprot = 0
    nsects = 0
    sflags = 0
    lc = struct.pack(
        "<II16sQQQQIIII",
        cmd,
        cmdsize,
        segname,
        vmaddr,
        vmsize,
        fileoff,
        filesize,
        maxprot,
        initprot,
        nsects,
        sflags,
    )

    return hdr + lc


# =============================================================================
# 1. PE Parser Tests
# =============================================================================


def test_pe_parser():
    raw_pe = make_synthetic_pe(with_overlay=True)
    assert pe.is_pe(raw_pe) is True

    parsed = pe.parse_pe(raw_pe)
    assert parsed["machine"] == "x86-64 (AMD64)"
    assert parsed["is_64bit"] is True
    assert parsed["is_dll"] is False
    assert parsed["entry_point"] == "0x1000"
    assert parsed["image_base"] == "0x140000000"
    assert parsed["num_sections"] == 1
    assert parsed["sections"][0]["name"] == ".text"
    assert parsed["has_overlay"] is True
    assert parsed["overlay_len"] > 0

    overlay = pe.detect_overlay(raw_pe)
    assert overlay == b"SECRET_PE_OVERLAY_FLAG"


# =============================================================================
# 2. Mach-O Parser Tests
# =============================================================================


def test_macho_parser():
    raw_macho = make_synthetic_macho()
    assert macho.is_macho(raw_macho) is True

    parsed = macho.parse_macho(raw_macho)
    assert parsed["is_64bit"] is True
    assert parsed["cpu"] == "ARM64"
    assert parsed["filetype"] == "EXECUTE"
    assert parsed["num_commands"] == 1
    assert len(parsed["segments"]) == 1
    assert parsed["segments"][0]["name"] == "__PAGEZERO"


# =============================================================================
# 3. Packer Detection Tests
# =============================================================================


def test_packer_detection():
    # Synthetic buffer containing UPX signature
    upx_buf = bytearray(b"MZ\x00\x00")
    upx_buf += b"UPX!" + bytes([39, 1, 2, 3]) + b"A" * 500
    res = packer.detect_upx(bytes(upx_buf))
    assert res["is_upx"] is True
    assert res["version"] == "3.9"

    pack_info = packer.detect_packer(bytes(upx_buf))
    assert pack_info["is_packed"] is True
    assert "UPX" in pack_info["identified_packers"]


# =============================================================================
# 4. CLI Binary Commands Smoke Tests
# =============================================================================


def test_cli_binary_commands(tmp_path):
    pe_path = tmp_path / "sample.exe"
    pe_path.write_bytes(make_synthetic_pe())

    r1 = runner.invoke(app, ["binary", "pe", str(pe_path)])
    assert r1.exit_code == 0
    assert "AMD64" in r1.output or "x86-64" in r1.output

    r2 = runner.invoke(app, ["binary", "packer", str(pe_path)])
    assert r2.exit_code == 0

    macho_path = tmp_path / "sample.bin"
    macho_path.write_bytes(make_synthetic_macho())

    r3 = runner.invoke(app, ["binary", "macho", str(macho_path)])
    assert r3.exit_code == 0
    assert "ARM64" in r3.output
