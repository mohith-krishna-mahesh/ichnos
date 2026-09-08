"""Binary sub-app."""

from __future__ import annotations

import typer

import ichnos.binary.elf as elf_mod
import ichnos.binary.entropy as entropy_mod
import ichnos.binary.identify as identify_mod
import ichnos.binary.macho as macho_mod
import ichnos.binary.misc as misc_mod
import ichnos.binary.packer as packer_mod
import ichnos.binary.pe as pe_mod
import ichnos.binary.strings as strings_mod
from ichnos.cli.state import state
from ichnos.core.input import read_input
from ichnos.core.models import Result
from ichnos.core.output import print_error, render

app = typer.Typer(no_args_is_help=True)


@app.command("identify")
def cmd_identify(file: str | None = typer.Argument(None)):
    """Identifies file formats, magic signatures, architectures, and MIME types."""
    try:
        inp = read_input(file)
        raw = identify_mod.identify_summary(inp.data)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("strings")
def cmd_strings(
    file: str | None = typer.Argument(None),
    min_len: int = typer.Option(4, "--min-len", "-n", help="Minimum string length"),
    encoding: str = typer.Option("all", "--encoding", "-e", help="ascii, utf16, or all"),
):
    """Extracts printable ASCII and UTF-16 strings with file offsets."""
    try:
        inp = read_input(file)
        raw = []
        if encoding == "ascii":
            raw = strings_mod.extract_ascii(inp.data, min_len)
        elif encoding == "utf16":
            raw = strings_mod.extract_utf16le(inp.data, min_len) + strings_mod.extract_utf16be(
                inp.data, min_len
            )
        else:
            raw = strings_mod.extract_all(inp.data, min_len)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("entropy")
def cmd_entropy(
    file: str | None = typer.Argument(None),
    window: int = typer.Option(256, "--window", "-w", help="Sliding window block size"),
):
    """Performs whole-file and sliding window Shannon entropy analysis."""
    try:
        inp = read_input(file)
        raw = entropy_mod.entropy_summary(inp.data, window)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("elf")
def cmd_elf(file: str | None = typer.Argument(None)):
    """Parses Linux/Unix ELF headers, program headers, section tables, and symbols."""
    try:
        inp = read_input(file)
        raw = elf_mod.parse_elf(inp.data)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("pe")
def cmd_pe(file: str | None = typer.Argument(None)):
    """Parses Windows PE/COFF headers, sections, imports/exports, and overlay data."""
    try:
        inp = read_input(file)
        raw = pe_mod.parse_pe(inp.data)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("macho")
def cmd_macho(file: str | None = typer.Argument(None)):
    """Parses macOS/iOS Mach-O headers, FAT architectures, segments, and dylibs."""
    try:
        inp = read_input(file)
        raw = macho_mod.parse_macho(inp.data)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("packer")
def cmd_packer(file: str | None = typer.Argument(None)):
    """Detects packers and protectors (UPX, ASPack, Themida) via heuristics and signatures."""
    try:
        inp = read_input(file)
        raw = packer_mod.detect_packer(inp.data)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("endian")
def cmd_endian(
    input_data: str | None = typer.Argument(None),
    word_size: int = typer.Option(4, "--word-size", "-w", help="Word size in bytes (2, 4, 8)"),
):
    """Swaps byte order within fixed-width word chunks."""
    try:
        inp = read_input(input_data)
        raw = misc_mod.swap_endian(inp.data, word_size)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("hamming")
def cmd_hamming(
    input1: str = typer.Argument(...),
    input2: str = typer.Argument(...),
):
    """Calculates bitwise Hamming distance between two inputs."""
    try:
        inp1 = read_input(input1)
        inp2 = read_input(input2)
        raw = misc_mod.hamming_distance(inp1.data, inp2.data)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))
