"""Stego sub-app."""

from __future__ import annotations

from pathlib import Path

import typer

import ichnos.stego.audio.morse as audio_morse
import ichnos.stego.audio.spectrogram as audio_spec
import ichnos.stego.audio.wav as wav
import ichnos.stego.image.channels as channels
import ichnos.stego.image.jpeg as jpeg
import ichnos.stego.image.lsb as lsb
import ichnos.stego.image.png as png
import ichnos.stego.image.steghide as steghide
import ichnos.stego.text as text_stego
from ichnos.cli.state import state
from ichnos.core.input import read_input
from ichnos.core.models import Result
from ichnos.core.output import print_error, render

app = typer.Typer(no_args_is_help=True)
text_app = typer.Typer(no_args_is_help=True)
audio_app = typer.Typer(no_args_is_help=True)

app.add_typer(
    text_app, name="text", help="Text steganography tools (null cipher, acrostic, reverse)."
)
app.add_typer(
    audio_app, name="audio", help="Audio steganography tools (WAV info, Morse, spectrogram)."
)


# =============================================================================
# Image Steganography Commands
# =============================================================================


@app.command("png")
def cmd_png(file: str | None = typer.Argument(None)):
    """Inspects PNG chunks, metadata, and trailing data."""
    try:
        inp = read_input(file)
        raw = png.inspect(inp.data)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


app.command("png-chunks", hidden=True)(cmd_png)


@app.command("jpeg")
def cmd_jpeg(file: str | None = typer.Argument(None)):
    """Inspects JPEG structure, markers, comments, and trailing data."""
    try:
        inp = read_input(file)
        raw = jpeg.inspect_jpeg(inp.data)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


app.command("jpeg-inspect", hidden=True)(cmd_jpeg)


@app.command("exif")
def cmd_exif(file: str | None = typer.Argument(None)):
    """Extracts EXIF / TIFF metadata (Camera, GPS, Software, Comments) from images."""
    try:
        inp = read_input(file)
        raw = channels.extract_exif_from_image(inp.data)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("channels")
def cmd_channels(
    file: str | None = typer.Argument(None),
    channel_count: int = typer.Option(
        3, "--channels", "-c", help="Number of color channels (3 for RGB, 4 for RGBA)"
    ),
):
    """Analyzes image channel plane entropy and checks for hidden plane anomalies."""
    try:
        inp = read_input(file)
        # If PNG, extract raw pixels; otherwise analyze raw bytes
        if inp.data.startswith(b"\x89PNG\r\n\x1a\n"):
            pixels, _, _, detected_channels = lsb.extract_raw_pixels(inp.data)
            raw = channels.analyze_channels(pixels, channels=detected_channels)
        else:
            raw = channels.analyze_channels(inp.data, channels=channel_count)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("lsb")
def cmd_lsb(
    file: str | None = typer.Argument(None),
    order: str = typer.Option("RGB", "--order", help="Channel order (e.g. RGB, BGR, R, G, B)"),
    bits: int = typer.Option(1, "--bits", help="Number of bits per channel (1-4)"),
    bit_order: str = typer.Option("lsb", "--bit-order", help="Bit ordering ('lsb' or 'msb')"),
    brute: bool = typer.Option(False, "--brute", help="Scan permutations automatically"),
):
    """Extracts least significant bits (LSB) from PNG pixel planes."""
    try:
        inp = read_input(file)
        if brute:
            cands = lsb.brute_force_lsb(inp.data)
            res = Result(candidates=cands)
        else:
            pixels, w, h, ch = lsb.extract_raw_pixels(inp.data)
            raw = lsb.extract_lsb(
                pixels,
                width=w,
                height=h,
                channels=ch,
                channel_order=order,
                num_bits=bits,
                bit_order=bit_order,
            )
            res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("steghide")
def cmd_steghide(
    file: str | None = typer.Argument(None),
    passphrase: str | None = typer.Option(
        None, "--passphrase", "-p", help="Passphrase for extraction"
    ),
    wordlist: str | None = typer.Option(
        None, "--wordlist", "-w", help="Dictionary wordlist for Stegseek cracking"
    ),
    extract: bool = typer.Option(False, "--extract", "-x", help="Extract embedded payload"),
):
    """Inspects carrier files, extracts payload with passphrase, or cracks via Stegseek."""
    try:
        inp = read_input(file)
        if wordlist:
            w_path = Path(wordlist)
            words = [
                line.strip()
                for line in w_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                if line.strip()
            ]
            crack_res = steghide.crack_steghide(inp.data, words)
            if crack_res:
                pwd, payload = crack_res
                raw = {
                    "cracked": True,
                    "passphrase": pwd,
                    "payload_preview": payload[:128].decode("latin-1", errors="replace"),
                }
            else:
                raw = {"cracked": False, "passphrase": None}
        elif extract or passphrase is not None:
            pwd = passphrase or ""
            extracted = steghide.extract_steghide(inp.data, passphrase=pwd)
            raw = {
                "extracted": extracted is not None,
                "payload": extracted.decode("latin-1", errors="replace") if extracted else None,
            }
        else:
            raw = steghide.inspect_steghide_artifacts(inp.data)

        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


# =============================================================================
# Audio Steganography Commands
# =============================================================================


@audio_app.command("info")
def cmd_audio_info(file: str | None = typer.Argument(None)):
    """Parses WAV headers and extracts RIFF metadata."""
    try:
        inp = read_input(file)
        raw = wav.get_metadata(inp.data)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


app.command("wav-info", hidden=True)(cmd_audio_info)


@audio_app.command("morse")
def cmd_audio_morse(
    file: str | None = typer.Argument(None),
    threshold: float = typer.Option(0.5, "--threshold", help="Tone detection amplitude threshold"),
):
    """Detects and decodes Morse code audio tones from WAV files."""
    try:
        inp = read_input(file)
        raw = audio_morse.detect_morse(inp.data, threshold)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


app.command("morse-audio", hidden=True)(cmd_audio_morse)


@audio_app.command("spectrogram")
def cmd_audio_spectrogram(
    file: str | None = typer.Argument(None),
    peaks: bool = typer.Option(False, "--peaks", help="Detect prominent spectral peak frequencies"),
    width: int = typer.Option(60, "--width", "-w", help="ASCII heatmap width"),
    height: int = typer.Option(20, "--height", "-h", help="ASCII heatmap height"),
):
    """Computes STFT audio spectrogram and renders terminal ASCII frequency heatmap."""
    try:
        inp = read_input(file)
        spec, sample_rate = audio_spec.spectrogram_from_wav(inp.data)
        if peaks:
            raw = audio_spec.detect_spectral_peaks(spec, sample_rate=sample_rate)
        else:
            raw = audio_spec.render_ascii_spectrogram(spec, width=width, height=height)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


app.command("spectrogram", hidden=True)(cmd_audio_spectrogram)


# =============================================================================
# Text Steganography Commands
# =============================================================================


@text_app.command("null")
def cmd_text_null(
    text_input: str | None = typer.Argument(None),
    mode: str = typer.Option(
        "first-letter", "--mode", help="first-letter, nth-letter, or first-sentence"
    ),
    n: int = typer.Option(2, "--n", help="N value for nth-letter mode"),
):
    """Extracts hidden text using Null cipher techniques."""
    try:
        inp = read_input(text_input)
        if not inp.text:
            raise ValueError("Input must be valid text.")
        raw = None
        if mode == "first-letter":
            raw = text_stego.null_cipher_first_letter(inp.text)
        elif mode == "nth-letter":
            raw = text_stego.null_cipher_nth_letter(inp.text, n)
        elif mode == "first-sentence":
            raw = text_stego.null_cipher_first_sentence(inp.text)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


app.command("text-null", hidden=True)(cmd_text_null)


@text_app.command("acrostic")
def cmd_text_acrostic(text_input: str | None = typer.Argument(None)):
    """Extracts acrostic letters (first character of each line)."""
    try:
        inp = read_input(text_input)
        if not inp.text:
            raise ValueError("Input must be valid text.")
        raw = text_stego.acrostic(inp.text)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


app.command("text-acrostic", hidden=True)(cmd_text_acrostic)


@text_app.command("reverse")
def cmd_text_reverse(text_input: str | None = typer.Argument(None)):
    """Detects or decodes reversed and upside-down text."""
    try:
        inp = read_input(text_input)
        if not inp.text:
            raise ValueError("Input must be valid text.")
        raw = text_stego.detect_reverse(inp.text)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


app.command("text-reverse", hidden=True)(cmd_text_reverse)


@app.command("ass-qr")
def cmd_ass_qr(
    file: str | None = typer.Argument(None, help="Substation Alpha (.ass) subtitle file"),
    merge: str = typer.Option("or", "--merge", "-m", help="Merge strategy across layers ('or', 'xor', 'none')"),
    unit: int | None = typer.Option(None, "--unit", "-u", help="Module size in px (auto-detected if omitted)"),
    canvas: int | None = typer.Option(None, "--canvas", "-c", help="Grid dimension in modules (auto-detected if omitted)"),
    outdir: str | None = typer.Option(None, "--outdir", "-o", help="Output directory to save extracted PNGs"),
):
    """Extracts hidden QR codes and module grids from .ass subtitle vector drawing blocks."""
    try:
        from ichnos.stego.ass_subtitle import extract_and_decode_ass

        inp = read_input(file)
        text_content = inp.data.decode("utf-8", errors="replace")
        raw = extract_and_decode_ass(
            text_content,
            merge=merge,
            unit=unit,
            canvas=canvas,
            out_dir=outdir,
        )
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))

