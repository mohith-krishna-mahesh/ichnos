import os
import struct
import subprocess
import sys
import zlib
from pathlib import Path

from ichnos.core.input import _extract_payload_if_json_result


def run_cmd(
    args: list[str], input_bytes: bytes | None = None, env: dict | None = None
) -> subprocess.CompletedProcess:
    full_env = dict(os.environ)
    full_env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent.parent / "src")
    if env:
        full_env.update(env)
    return subprocess.run(
        [sys.executable, "-m", "ichnos", *args],
        input=input_bytes,
        capture_output=True,
        env=full_env,
        check=False,
    )


def test_extract_payload_from_json_raw_output():
    json_data = b'{\n  "raw_output": "HELLO WORLD"\n}'
    assert _extract_payload_if_json_result(json_data) == b"HELLO WORLD"


def test_extract_payload_from_json_candidates():
    json_data = b'{\n  "candidates": [\n    {"decoded": "SECRET_DATA", "confidence": 0.9}\n  ]\n}'
    assert _extract_payload_if_json_result(json_data) == b"SECRET_DATA"


def test_extract_payload_non_json_passthrough():
    raw_data = b"Just some normal text"
    assert _extract_payload_if_json_result(raw_data) == raw_data


def test_pipeline_caesar_to_atbash_with_json():
    # KHOOR decrypted with shift 3 is HELLO
    # HELLO atbash is SVOOL
    p1 = run_cmd(["--json", "crypto", "caesar", "KHOOR", "--shift", "3"])
    assert p1.returncode == 0
    assert b'"raw_output": "HELLO"' in p1.stdout

    p2 = run_cmd(["crypto", "atbash"], input_bytes=p1.stdout)
    assert p2.returncode == 0
    combined = p2.stdout + p2.stderr
    assert b"SVOOL" in combined


def test_pipeline_base64_decode_to_binary_identify_json():
    # \x7fELF in base64 is f0VMRg==
    p1 = run_cmd(["--json", "encoding", "decode", "f0VMRg==", "--format", "base64"])
    assert p1.returncode == 0

    p2 = run_cmd(["binary", "identify", "-"], input_bytes=p1.stdout)
    assert p2.returncode == 0
    combined = p2.stdout + p2.stderr
    assert b"ELF" in combined


def test_pipeline_base64_decode_to_binary_identify_raw_pipe():
    # Direct Unix pipe without --json
    p1 = run_cmd(["encoding", "decode", "f0VMRg==", "--format", "base64"])
    assert p1.returncode == 0
    assert p1.stdout == b"\x7fELF"

    p2 = run_cmd(["binary", "identify", "-"], input_bytes=p1.stdout)
    assert p2.returncode == 0
    combined = p2.stdout + p2.stderr
    assert b"ELF" in combined


def test_pipeline_stego_lsb_to_encoding_auto(tmp_path):
    # Create a tiny PNG with base64 encoded flag embedded in LSB
    # Base64 of 'FLAG{piped_success}' is 'RkxBR3twaXBlZF9zdWNjZXNzfQ=='
    secret = b"RkxBR3twaXBlZF9zdWNjZXNzfQ=="
    flag_bits = "".join(f"{b:08b}" for b in secret)

    width = 16
    height = 16
    pixels = bytearray([0] * (width * height * 3))
    for i, bit in enumerate(flag_bits):
        if i < len(pixels):
            pixels[i] = int(bit)

    png_magic = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack("!IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF
    ihdr = struct.pack("!I4s13sI", 13, b"IHDR", ihdr_data, ihdr_crc)

    scanlines = b""
    for y in range(height):
        scanlines += b"\x00" + pixels[y * (width * 3) : (y + 1) * (width * 3)]

    idat_data = zlib.compress(scanlines)
    idat_crc = zlib.crc32(b"IDAT" + idat_data) & 0xFFFFFFFF
    idat = struct.pack(f"!I4s{len(idat_data)}sI", len(idat_data), b"IDAT", idat_data, idat_crc)

    iend_crc = zlib.crc32(b"IEND") & 0xFFFFFFFF
    iend = struct.pack("!I4sI", 0, b"IEND", iend_crc)

    png_path = tmp_path / "test_lsb.png"
    png_path.write_bytes(png_magic + ihdr + idat + iend)

    # Step 1: Extract LSB with --json and --bit-order msb
    p1 = run_cmd(
        [
            "--json",
            "stego",
            "lsb",
            str(png_path),
            "--order",
            "RGB",
            "--bits",
            "1",
            "--bit-order",
            "msb",
        ]
    )
    assert p1.returncode == 0
    assert b"RkxBR3twaXBlZF9zdWNjZXNzfQ==" in p1.stdout

    # Step 2: Pipe to encoding auto
    p2 = run_cmd(["encoding", "auto"], input_bytes=p1.stdout)
    assert p2.returncode == 0
    combined = p2.stdout + p2.stderr
    assert b"FLAG{piped_success}" in combined
