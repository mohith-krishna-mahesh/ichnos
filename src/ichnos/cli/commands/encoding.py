"""Encoding sub-app."""

from __future__ import annotations

import typer

import ichnos.encoding.barcode as barcode
import ichnos.encoding.bases as bases
import ichnos.encoding.compression_checksums as chk
import ichnos.encoding.esolang as esolang
import ichnos.encoding.esolang_advanced as esolang_adv
import ichnos.encoding.layered as layered
import ichnos.encoding.morse as morse
import ichnos.encoding.numerals as numerals
import ichnos.encoding.telecom as telecom
import ichnos.encoding.text as text_enc
import ichnos.encoding.text_extended as text_ext
from ichnos.cli.state import state
from ichnos.core.input import read_input
from ichnos.core.models import Finding, Result
from ichnos.core.output import print_error, render

app = typer.Typer(no_args_is_help=True)


@app.command("decode")
def cmd_decode(
    input_data: str | None = typer.Argument(None),
    fmt: str = typer.Option("", "--format", "-f", help="Format to decode from"),
):
    """Decodes data from the specified format (or auto-detects if unspecified)."""
    try:
        inp = read_input(input_data)
        if not fmt:
            candidates = layered.auto_decode(inp.data)
            res = Result(candidates=candidates)
            render(res, state.json_mode)
            return

        fmt_lower = fmt.lower().replace("_", "-")
        raw = None
        s = inp.text or ""

        # Base decoders
        if fmt_lower in ("base64", "b64"):
            raw = bases.decode_base64(s)
        elif fmt_lower in ("base64url", "b64url"):
            raw = bases.decode_base64url(s)
        elif fmt_lower in ("hex", "base16", "b16"):
            raw = bases.decode_hex(s)
        elif fmt_lower in ("base32", "b32"):
            raw = bases.decode_base32(s)
        elif fmt_lower in ("crockford", "base32-crockford"):
            raw = bases.decode_base32_crockford(s)
        elif fmt_lower in ("zbase32", "z-base-32"):
            raw = bases.decode_zbase32(s)
        elif fmt_lower in ("base45", "b45"):
            raw = bases.decode_base45(s)
        elif fmt_lower in ("base58", "b58"):
            raw = bases.decode_base58(s)
        elif fmt_lower in ("base62", "b62"):
            raw = bases.decode_base62(s)
        elif fmt_lower in ("base85", "b85", "ascii85"):
            raw = bases.decode_base85(s)
        elif fmt_lower in ("base91", "b91"):
            raw = bases.decode_base91(s)
        elif fmt_lower in ("base92", "b92"):
            raw = bases.decode_base92(s)
        elif fmt_lower in ("base100", "emoji"):
            raw = bases.decode_base100(s)
        elif fmt_lower in ("base26",):
            raw = bases.decode_base26(s)
        elif fmt_lower in ("base36",):
            raw = bases.decode_base36(s)
        # Text decoders
        elif fmt_lower == "url":
            raw = text_enc.url_decode(s)
        elif fmt_lower == "url-double":
            raw = text_enc.url_double_decode(s)
        elif fmt_lower == "html":
            raw = text_enc.html_decode(s)
        elif fmt_lower == "unicode":
            raw = text_enc.unicode_decode(s)
        elif fmt_lower == "punycode":
            raw = text_ext.punycode_decode(s)
        elif fmt_lower in ("uu", "uuencode"):
            raw = text_ext.uudecode(s)
        elif fmt_lower in ("quoted-printable", "qp"):
            raw = text_ext.quoted_printable_decode(s)
        elif fmt_lower in ("zero-width", "zw"):
            raw = text_ext.decode_zero_width(s)
        else:
            raise ValueError(f"Unsupported decode format: {fmt}")

        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("encode")
def cmd_encode(
    input_data: str | None = typer.Argument(None),
    fmt: str = typer.Option(..., "--format", "-f", help="Format to encode into"),
):
    """Encodes data into the specified format."""
    try:
        inp = read_input(input_data)
        fmt_lower = fmt.lower().replace("_", "-")
        raw = None
        data = inp.data
        s = inp.text or ""

        # Base encoders
        if fmt_lower in ("base64", "b64"):
            raw = bases.encode_base64(data)
        elif fmt_lower in ("base64url", "b64url"):
            raw = bases.encode_base64url(data)
        elif fmt_lower in ("hex", "base16", "b16"):
            raw = bases.encode_hex(data)
        elif fmt_lower in ("base32", "b32"):
            raw = bases.encode_base32(data)
        elif fmt_lower in ("crockford", "base32-crockford"):
            raw = bases.encode_base32_crockford(data)
        elif fmt_lower in ("zbase32", "z-base-32"):
            raw = bases.encode_zbase32(data)
        elif fmt_lower in ("base45", "b45"):
            raw = bases.encode_base45(data)
        elif fmt_lower in ("base58", "b58"):
            raw = bases.encode_base58(data)
        elif fmt_lower in ("base62", "b62"):
            raw = bases.encode_base62(data)
        elif fmt_lower in ("base85", "b85", "ascii85"):
            raw = bases.encode_base85(data)
        elif fmt_lower in ("base91", "b91"):
            raw = bases.encode_base91(data)
        elif fmt_lower in ("base92", "b92"):
            raw = bases.encode_base92(data)
        elif fmt_lower in ("base100", "emoji"):
            raw = bases.encode_base100(data)
        elif fmt_lower in ("base26",):
            raw = bases.encode_base26(int.from_bytes(data, "big"))
        elif fmt_lower in ("base36",):
            raw = bases.encode_base36(int.from_bytes(data, "big"))
        # Text encoders
        elif fmt_lower == "url":
            raw = text_enc.url_encode(s)
        elif fmt_lower == "url-double":
            raw = text_enc.url_double_encode(s)
        elif fmt_lower == "html":
            raw = text_enc.html_encode(s)
        elif fmt_lower == "unicode":
            raw = text_enc.unicode_encode(s)
        elif fmt_lower == "punycode":
            raw = text_ext.punycode_encode(s)
        elif fmt_lower in ("uu", "uuencode"):
            raw = text_ext.uuencode(data)
        elif fmt_lower in ("quoted-printable", "qp"):
            raw = text_ext.quoted_printable_encode(data)
        elif fmt_lower in ("zero-width", "zw"):
            raw = text_ext.encode_zero_width(data)
        else:
            raise ValueError(f"Unsupported encode format: {fmt}")

        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("morse")
def cmd_morse(
    input_data: str | None = typer.Argument(None),
    encode: bool = typer.Option(False, "--encode", help="Encode to morse instead of decode"),
):
    """Encodes or decodes Morse code."""
    try:
        inp = read_input(input_data)
        if not inp.text:
            raise ValueError("Input must be valid text.")
        if encode:
            raw = morse.encode(inp.text)
        else:
            raw = morse.decode(inp.text)
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("esolang")
def cmd_esolang(
    input_data: str | None = typer.Argument(None),
    lang: str = typer.Option(..., "--lang", "-l", help="Esolang interpreter / decoder to run"),
):
    """Executes or decodes esoteric programming languages."""
    try:
        inp = read_input(input_data)
        if not inp.text:
            raise ValueError("Input must be valid text.")
        lang_lower = lang.lower().replace("-", "").replace("_", "")
        raw = None

        if lang_lower == "brainfuck":
            raw = esolang.interpret_brainfuck(inp.text)
        elif lang_lower == "ook":
            raw = esolang.interpret_ook(inp.text)
        elif lang_lower == "jsfuck":
            raw = esolang.interpret_jsfuck(inp.text)
        elif lang_lower == "whitespace":
            raw = esolang.interpret_whitespace(inp.text)
        elif lang_lower == "lolcode":
            raw = esolang.interpret_lolcode(inp.text)
        elif lang_lower == "deadfish":
            raw = esolang.interpret_deadfish(inp.text)
        elif lang_lower == "malbolge":
            raw = esolang_adv.interpret_malbolge(inp.text)
        elif lang_lower == "aaencode":
            raw = esolang_adv.decode_aaencode(inp.text)
        else:
            raise ValueError(f"Unknown esolang: {lang}")

        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("numeral")
def cmd_numeral(
    input_data: str | None = typer.Argument(None),
    mode: str = typer.Option(
        "balanced-ternary",
        "--mode",
        "-m",
        help="Numeral format: balanced-ternary, negabinary, gray, bcd, excess3, ternary",
    ),
    decode: bool = typer.Option(False, "--decode", help="Decode to integer instead of encode"),
):
    """Encodes or decodes alternative and historical numeral systems."""
    try:
        inp = read_input(input_data)
        mode_lower = mode.lower().replace("_", "-")
        raw = None

        if decode:
            val_str = (inp.text or "").strip()
            if mode_lower in ("balanced-ternary", "bt"):
                raw = numerals.from_balanced_ternary(val_str)
            elif mode_lower in ("negabinary", "base-2"):
                raw = numerals.from_negabinary(val_str)
            elif mode_lower in ("gray", "gray-code"):
                raw = numerals.from_gray_code(int(val_str, 2))
            elif mode_lower == "bcd":
                raw = numerals.from_bcd(val_str)
            elif mode_lower == "excess3":
                raw = numerals.from_excess3(val_str)
            elif mode_lower == "ternary":
                raw = numerals.from_ternary(val_str)
            else:
                raise ValueError(f"Unknown numeral mode: {mode}")
        else:
            val = int((inp.text or "").strip())
            if mode_lower in ("balanced-ternary", "bt"):
                raw = numerals.to_balanced_ternary(val)
            elif mode_lower in ("negabinary", "base-2"):
                raw = numerals.to_negabinary(val)
            elif mode_lower in ("gray", "gray-code"):
                raw = f"{numerals.to_gray_code(val):b}"
            elif mode_lower == "bcd":
                raw = numerals.to_bcd(val)
            elif mode_lower == "excess3":
                raw = numerals.to_excess3(val)
            elif mode_lower == "ternary":
                raw = numerals.to_ternary(val)
            else:
                raise ValueError(f"Unknown numeral mode: {mode}")

        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("telecom")
def cmd_telecom(
    input_data: str | None = typer.Argument(None),
    proto: str = typer.Option(
        "baudot",
        "--proto",
        "-p",
        help="Protocol: baudot, manchester, ami, t9",
    ),
    encode: bool = typer.Option(False, "--encode", help="Encode instead of decode"),
):
    """Telecom signaling and telephony encodings (Baudot, Manchester, AMI, T9)."""
    try:
        inp = read_input(input_data)
        proto_lower = proto.lower().replace("_", "-")
        raw = None
        s = (inp.text or "").strip()

        if proto_lower == "baudot":
            raw = telecom.encode_baudot(s) if encode else telecom.decode_baudot(s)
        elif proto_lower == "manchester":
            raw = telecom.encode_manchester(s) if encode else telecom.decode_manchester(s)
        elif proto_lower == "ami":
            raw = telecom.encode_ami(s) if encode else telecom.decode_ami(s)
        elif proto_lower in ("t9", "multitap"):
            raw = telecom.encode_t9(s) if encode else telecom.decode_t9(s)
        else:
            raise ValueError(f"Unknown telecom protocol: {proto}")

        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("checksum")
def cmd_checksum(
    input_data: str | None = typer.Argument(None),
    algo: str = typer.Option(
        "crc32",
        "--algo",
        "-a",
        help="Algorithm: crc32, luhn, verhoeff, rle",
    ),
    validate: bool = typer.Option(False, "--validate", help="Validate check digit / checksum"),
):
    """Checksum and run-length compression operations."""
    try:
        inp = read_input(input_data)
        algo_lower = algo.lower().replace("_", "-")
        s = (inp.text or "").strip()
        raw = None

        if algo_lower == "crc32":
            raw = f"0x{chk.crc32(inp.data):08x}"
        elif algo_lower == "luhn":
            if validate:
                valid = chk.luhn_validate(s)
                res = Result(
                    findings=[
                        Finding(
                            title="Luhn Checksum",
                            confidence=1.0 if valid else 0.0,
                            module="encoding",
                            detail=f"Luhn check digit valid: {valid}",
                        )
                    ],
                    raw_output={"valid": valid},
                )
                render(res, state.json_mode)
                return
            raw = f"{s}{chk.luhn_generate(s)}"
        elif algo_lower == "verhoeff":
            if validate:
                valid = chk.verhoeff_validate(s)
                res = Result(
                    findings=[
                        Finding(
                            title="Verhoeff D5 Checksum",
                            confidence=1.0 if valid else 0.0,
                            module="encoding",
                            detail=f"Verhoeff check digit valid: {valid}",
                        )
                    ],
                    raw_output={"valid": valid},
                )
                render(res, state.json_mode)
                return
            raw = f"{s}{chk.verhoeff_generate(s)}"
        elif algo_lower == "rle":
            raw = chk.rle_compress(s)
        else:
            raise ValueError(f"Unknown checksum algorithm: {algo}")

        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("barcode")
def cmd_barcode(
    input_data: str | None = typer.Argument(None),
    generate: bool = typer.Option(False, "--generate", "-g", help="Generate Code 39 SVG"),
):
    """Generates pure-Python Code 39 SVG or decodes barcodes using zxing-cpp."""
    try:
        inp = read_input(input_data)
        s = (inp.text or "").strip()
        if generate:
            raw = barcode.generate_code39_svg(s)
        else:
            if not barcode.is_zxing_available():
                print_error(
                    "Barcode and QR decoding requires 'zxing-cpp'. "
                    "Install it via: uv add zxing-cpp (or pip install zxing-cpp)"
                )
                return
            raw = barcode.decode_barcode(input_data or "")
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("auto")
def cmd_auto(input_data: str | None = typer.Argument(None)):
    """Automatically detects and multi-layer unwraps stacked encodings."""
    try:
        inp = read_input(input_data)
        candidates = layered.auto_decode(inp.data)
        res = Result(candidates=candidates)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))
