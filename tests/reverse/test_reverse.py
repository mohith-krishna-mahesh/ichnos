"""Unit tests for Phase F Reverse Engineering module: disassembler, CFG, and binary patching."""

from __future__ import annotations

from typer.testing import CliRunner

from ichnos.cli.main import app
from ichnos.reverse import cfg, disasm, patch

runner = CliRunner()


# =============================================================================
# 1. Disassembler Tests
# =============================================================================


def test_disassembly():
    # Sequence:
    # 0x90 : nop
    # 0x31 0xc0 : xor eax, eax
    # 0x50 : push rax
    # 0x58 : pop rax
    # 0xeb 0x02 : jmp +2
    # 0x90 : nop
    # 0xc3 : ret
    code = b"\x90\x31\xc0\x50\x58\xeb\x02\x90\xc3"
    insns = disasm.disassemble(code, arch="x86_64", base_addr=0x1000)

    assert len(insns) >= 6
    assert insns[0].mnemonic == "nop"
    assert insns[0].address == 0x1000

    # Branch and return detection
    has_jmp = any(i.mnemonic == "jmp" and i.is_branch for i in insns)
    has_ret = any(i.mnemonic == "ret" and i.is_ret for i in insns)
    assert has_jmp is True
    assert has_ret is True


# =============================================================================
# 2. Control Flow Graph Tests
# =============================================================================


def test_cfg_construction():
    # Function with a branch:
    # 0x1000: xor eax, eax (31 c0)
    # 0x1002: jz 0x1006 (74 02)
    # 0x1004: nop (90)
    # 0x1005: nop (90)
    # 0x1006: ret (c3)
    code = b"\x31\xc0\x74\x02\x90\x90\xc3"
    insns = disasm.disassemble(code, arch="x86_64", base_addr=0x1000)
    blocks = cfg.build_cfg(insns)

    assert len(blocks) >= 2
    # First block should end with jz
    assert blocks[0].instructions[-1].mnemonic == "jz"

    # Cyclomatic complexity should be at least 2 due to conditional branch
    complexity = cfg.cyclomatic_complexity(blocks)
    assert complexity >= 2

    # ASCII rendering
    ascii_cfg = cfg.render_ascii_cfg(blocks)
    assert "Control Flow Graph" in ascii_cfg
    assert "Block_0" in ascii_cfg


# =============================================================================
# 3. Binary Patching Tests
# =============================================================================


def test_binary_patching(tmp_path):
    orig = b"\x41\x42\x43\x44\x31\xc0\x90\x90\x90\x55"

    # Pattern finding with wildcard: \x31 \xc0 \x90 -> offset 4
    matches = patch.find_pattern(orig, b"\x31\xc0\x90")
    assert matches == [4]

    # Masked pattern match: 43 ?? 44 (offset 2)
    matches_mask = patch.find_pattern(orig, b"\x43\x00\x31", mask="x?x")
    assert matches_mask == [2]

    # Patch bytes
    patched = patch.patch_bytes(orig, offset=4, replacement=b"\x90\x90")
    assert patched[4:6] == b"\x90\x90"

    # NOP region
    nopped = patch.nop_region(orig, offset=0, length=4, arch="x86")
    assert nopped[:4] == b"\x90\x90\x90\x90"

    # File patching
    f = tmp_path / "target.bin"
    f.write_bytes(orig)
    out_f = tmp_path / "patched.bin"
    patch.patch_file(str(f), str(out_f), offset=0, replacement=b"TEST")
    assert out_f.read_bytes().startswith(b"TEST")


def test_assembly_and_patch_at_offset(tmp_path):
    # Test mnemonic assembly (NOPs, jumps, returns, registers)
    nop_code = patch.assemble("nop", arch="x86")
    assert nop_code == b"\x90"

    multi_insns = patch.assemble("nop; nop; ret", arch="x86")
    assert multi_insns == b"\x90\x90\xc3"

    jmp_patch = patch.assemble("jmp 0x05", arch="x86")
    assert jmp_patch == b"\xeb\x05"

    xor_code = patch.assemble("xor eax, eax", arch="x86")
    assert xor_code == b"\x31\xc0"

    # Test patch_at_offset
    bin_file = tmp_path / "binary_to_patch.bin"
    bin_file.write_bytes(b"\xaa\xbb\xcc\xdd\xee\xff")
    patch.patch_at_offset(str(bin_file), offset=2, assembled_bytes=multi_insns)
    assert bin_file.read_bytes() == b"\xaa\xbb\x90\x90\xc3\xff"


# =============================================================================
# 4. CLI Reverse Commands Smoke Tests
# =============================================================================


def test_cli_reverse_commands(tmp_path):
    code = b"\x90\x90\xc3"
    target = tmp_path / "code.bin"
    target.write_bytes(code)

    r1 = runner.invoke(app, ["reverse", "disasm", str(target)])
    assert r1.exit_code == 0
    assert "nop" in r1.output

    r2 = runner.invoke(app, ["reverse", "cfg", str(target)])
    assert r2.exit_code == 0
    assert "Block_0" in r2.output

    r3 = runner.invoke(app, ["reverse", "nop", str(target), "--offset", "0", "--len", "2"])
    assert r3.exit_code == 0
