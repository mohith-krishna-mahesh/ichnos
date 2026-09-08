"""Forensic sub-app."""

from __future__ import annotations

from pathlib import Path

import typer

import ichnos.forensic.archives as archives_mod
import ichnos.forensic.carver as carver_mod
import ichnos.forensic.filesystem as filesystem_mod
import ichnos.forensic.timestamps as timestamps_mod
import ichnos.forensic.zip as zip_mod
from ichnos.cli.state import state
from ichnos.core.input import read_input
from ichnos.core.models import Result
from ichnos.core.output import print_error, print_success, render

app = typer.Typer(no_args_is_help=True)
zip_app = typer.Typer(no_args_is_help=True)
tar_app = typer.Typer(no_args_is_help=True)
archive_app = typer.Typer(no_args_is_help=True)
disk_app = typer.Typer(no_args_is_help=True)

app.add_typer(zip_app, name="zip", help="ZIP archive inspection and cracking.")
app.add_typer(tar_app, name="tar", help="TAR archive inspection.")
app.add_typer(archive_app, name="archive", help="Multi-format archive inspection.")
app.add_typer(disk_app, name="disk", help="Disk image and partition table inspection.")


@zip_app.command("inspect")
def cmd_zip_inspect(file: str | None = typer.Argument(None)):
    """Inspects ZIP central directory, entries, and compression metadata."""
    try:
        inp = read_input(file)
        raw = zip_mod.inspect_zip(inp.data)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@zip_app.command("comments")
def cmd_zip_comments(file: str | None = typer.Argument(None)):
    """Extracts ZIP archive comments and per-file comments."""
    try:
        inp = read_input(file)
        raw = zip_mod.extract_comments(inp.data)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@zip_app.command("crack")
def cmd_zip_crack(
    file: str | None = typer.Argument(None),
    wordlist: str = typer.Option(..., "--wordlist", "-w", help="Path to dictionary wordlist"),
):
    """Cracks encrypted ZIP archive passwords using a wordlist."""
    try:
        inp = read_input(file)

        with open(wordlist, encoding="utf-8", errors="ignore") as w:
            words = [line.strip() for line in w]

        raw = zip_mod.crack_zip(inp.data, words)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


app.command("zip-inspect", hidden=True)(cmd_zip_inspect)
app.command("zip-comments", hidden=True)(cmd_zip_comments)
app.command("zip-crack", hidden=True)(cmd_zip_crack)


@tar_app.command("inspect")
def cmd_tar_inspect(file: str | None = typer.Argument(None)):
    """Inspects TAR archives, listing entries, permissions, owners, and timestamps."""
    try:
        inp = read_input(file)
        raw = archives_mod.inspect_tar(inp.data)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


app.command("tar-inspect", hidden=True)(cmd_tar_inspect)


@archive_app.command("inspect")
def cmd_archive_inspect(file: str | None = typer.Argument(None)):
    """Auto-detects and inspects archives (ZIP, TAR, 7z, RAR, GZIP, BZIP2, XZ)."""
    try:
        inp = read_input(file)
        raw = archives_mod.inspect_archive(inp.data)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


app.command("archive-inspect", hidden=True)(cmd_archive_inspect)


@app.command("carve")
def cmd_carve(
    file: str | None = typer.Argument(None),
    types: str = typer.Option(
        "all", "--types", "-t", help="Comma-separated file types (png,jpeg,pdf,zip,gif) or 'all'"
    ),
    outdir: str | None = typer.Option(
        None, "--outdir", "-o", help="Directory to save carved files"
    ),
):
    """Carves embedded files (PNG, JPEG, PDF, ZIP, GIF) by header/trailer signatures."""
    try:
        inp = read_input(file)
        selected_types = None if types.lower() == "all" else [t.strip() for t in types.split(",")]
        carved = carver_mod.carve_all(inp.data, types=selected_types)

        summary = [
            {
                "file_type": c.file_type,
                "offset": c.offset,
                "size": c.size,
            }
            for c in carved
        ]

        if outdir:
            out_path = Path(outdir)
            out_path.mkdir(parents=True, exist_ok=True)
            for i, c in enumerate(carved):
                fname = f"carved_{i:04d}_0x{c.offset:X}.{c.file_type}"
                (out_path / fname).write_bytes(c.data)
            print_success(f"Carved {len(carved)} file(s) into {outdir}")

        res = Result(raw_output=summary)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@disk_app.command("inspect")
def cmd_disk_inspect(file: str | None = typer.Argument(None)):
    """Inspects MBR, GPT partition tables, or FAT BIOS Parameter Blocks from disk images."""
    try:
        inp = read_input(file)
        raw = filesystem_mod.inspect_disk(inp.data)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


app.command("disk-inspect", hidden=True)(cmd_disk_inspect)


@app.command("timestamp")
def cmd_timestamp(
    value: str = typer.Argument(..., help="Timestamp value (integer, float, or ISO string)"),
    fmt: str = typer.Option(
        "auto", "--format", "-f", help="Format: auto, filetime, cocoa, chrome, unix, unixms"
    ),
):
    """Converts forensic timestamps (FILETIME, Cocoa, WebKit, Unix) to standard UTC."""
    try:
        raw = timestamps_mod.convert_timestamp(value, fmt=fmt)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))
