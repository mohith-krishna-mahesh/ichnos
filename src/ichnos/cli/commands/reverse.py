"""Reverse engineering sub-app."""

from __future__ import annotations

import typer

import ichnos.reverse.cfg as cfg_mod
import ichnos.reverse.disasm as disasm_mod
import ichnos.reverse.patch as patch_mod
from ichnos.cli.state import state
from ichnos.core.input import read_input
from ichnos.core.models import Result
from ichnos.core.output import print_error, render

app = typer.Typer(no_args_is_help=True)


@app.command("disasm")
def cmd_disasm(
    input_data: str | None = typer.Argument(None),
    arch: str = typer.Option(
        "x86_64", "--arch", "-a", help="Architecture (x86, x86_64, arm, arm64, mips)"
    ),
    base: str = typer.Option("0x1000", "--base", "-b", help="Base loading address in hex"),
):
    """Disassembles binary code into assembly instructions."""
    try:
        inp = read_input(input_data)
        base_addr = int(base, 16) if base.startswith("0x") else int(base)
        insns = disasm_mod.disassemble(inp.data, arch=arch, base_addr=base_addr)
        raw = "\n".join(str(i) for i in insns)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("cfg")
def cmd_cfg(
    input_data: str | None = typer.Argument(None),
    arch: str = typer.Option("x86_64", "--arch", "-a", help="Architecture"),
    base: str = typer.Option("0x1000", "--base", "-b", help="Base address"),
):
    """Constructs basic blocks and renders ASCII Control Flow Graph."""
    try:
        inp = read_input(input_data)
        base_addr = int(base, 16) if base.startswith("0x") else int(base)
        insns = disasm_mod.disassemble(inp.data, arch=arch, base_addr=base_addr)
        blocks = cfg_mod.build_cfg(insns)
        raw = cfg_mod.render_ascii_cfg(blocks)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("patch")
def cmd_patch(
    file: str = typer.Argument(..., help="Target file path to patch"),
    offset: str = typer.Option(
        ..., "--offset", "-o", help="Byte offset in hex (e.g. 0x100) or decimal"
    ),
    replacement: str | None = typer.Option(
        None, "--bytes", "-b", help="Hex string of replacement bytes (e.g. '909090')"
    ),
    nop: bool = typer.Option(False, "--nop", help="Fill region with NOP instructions"),
    length: int = typer.Option(1, "--length", "--len", "-l", help="Number of bytes to NOP"),
    arch: str = typer.Option("x86", "--arch", "-a", help="Architecture for NOP (x86, arm, arm64)"),
    out: str | None = typer.Option(
        None, "--out", help="Output file path (overwrites target if omitted)"
    ),
):
    """Patches byte sequences or applies NOP instructions at a specific offset in a binary file."""
    try:
        off_val = int(offset, 16) if offset.startswith("0x") else int(offset)
        out_path = out or file
        if nop:
            src = read_input(file).data
            patched = patch_mod.nop_region(src, off_val, length, arch=arch)
            import pathlib

            pathlib.Path(out_path).write_bytes(patched)
            res = Result(
                raw_output=f"NOP-filled {length} bytes at offset {hex(off_val)} in {out_path}"
            )
        else:
            if not replacement:
                raise ValueError("Must provide either --bytes HEX or --nop")
            patch_data = bytes.fromhex(replacement.replace(" ", ""))
            patch_mod.patch_file(file, out_path, off_val, patch_data)
            res = Result(
                raw_output=f"Successfully applied {len(patch_data)} patch bytes at offset {hex(off_val)} -> {out_path}"
            )
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("nop", hidden=True)
def cmd_nop(
    file: str = typer.Argument(..., help="Target file path to NOP"),
    offset: str = typer.Option(..., "--offset", "-o", help="Byte offset"),
    length: int = typer.Option(1, "--length", "--len", "-l", help="Number of bytes to NOP"),
    arch: str = typer.Option("x86", "--arch", "-a", help="Architecture (x86, arm, arm64)"),
    out: str | None = typer.Option(None, "--out", help="Output file path"),
):
    """Fills a byte range with architecture-specific NOP instructions."""
    try:
        off_val = int(offset, 16) if offset.startswith("0x") else int(offset)
        out_path = out or file
        src = read_input(file).data
        patched = patch_mod.nop_region(src, off_val, length, arch=arch)
        import pathlib

        pathlib.Path(out_path).write_bytes(patched)
        res = Result(raw_output=f"NOP-filled {length} bytes at offset {hex(off_val)} in {out_path}")
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))
