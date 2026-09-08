"""Unit tests for Phase E: JPEG analysis, EXIF, Channels, Steghide, and Spectrogram."""

from __future__ import annotations

import math
import struct

from typer.testing import CliRunner

from ichnos.cli.main import app
from ichnos.stego.audio import spectrogram as audio_spec
from ichnos.stego.image import channels, jpeg, steghide

runner = CliRunner()


def make_synthetic_jpeg(
    comment: str = "FLAG{jpeg_stego_flag}",
    trailing_data: bytes = b"HIDDEN_APPENDED_BYTES",
) -> bytes:
    """Helper to build a valid minimal synthetic JPEG byte buffer."""
    data = bytearray(b"\xff\xd8")  # SOI

    # APP0 (JFIF)
    jfif = b"JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00"
    data += b"\xff\xe0" + struct.pack(">H", len(jfif) + 2) + jfif

    # COM (Comment)
    if comment:
        com_bytes = comment.encode("utf-8")
        data += b"\xff\xfe" + struct.pack(">H", len(com_bytes) + 2) + com_bytes

    # SOF0 (Baseline: 8-bit, height 100, width 200, 3 components)
    sof = b"\x08\x00\x64\x00\xc8\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01"
    data += b"\xff\xc0" + struct.pack(">H", len(sof) + 2) + sof

    # SOS (Start of Scan)
    sos = b"\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00"
    data += b"\xff\xda" + struct.pack(">H", len(sos) + 2) + sos

    # Scan data
    data += b"\x11\x22\x33\x44\x55\x66"

    # EOI
    data += b"\xff\xd9"

    # Trailing appended data
    if trailing_data:
        data += trailing_data

    return bytes(data)


def make_synthetic_exif() -> bytes:
    """Helper to build a valid TIFF EXIF buffer."""
    buf = bytearray(b"II\x2a\x00\x08\x00\x00\x00")
    # IFD0 with 2 tags at offset 8
    buf += struct.pack("<H", 2)
    # Tag 1: Make (0x010f), type 2 (ASCII), count 6, offset 38
    buf += struct.pack("<HHI", 0x010F, 2, 6) + struct.pack("<I", 38)
    # Tag 2: Model (0x0110), type 2 (ASCII), count 7, offset 44
    buf += struct.pack("<HHI", 0x0110, 2, 7) + struct.pack("<I", 44)
    buf += struct.pack("<I", 0)  # Next IFD = 0
    buf += b"Nikon\x00"
    buf += b"D850-X\x00"
    return bytes(buf)


# =============================================================================
# 1. JPEG Steganalysis Tests
# =============================================================================


def test_jpeg_parser():
    raw_jpeg = make_synthetic_jpeg()

    # Parse segments
    segments = jpeg.parse_segments(raw_jpeg)
    assert any(s.name == "SOI" for s in segments)
    assert any(s.name == "EOI" for s in segments)
    assert any("COM" in s.name for s in segments)

    # Comments
    comments = jpeg.extract_comments(raw_jpeg)
    assert "FLAG{jpeg_stego_flag}" in comments

    # Trailing data
    trailing = jpeg.detect_trailing_data(raw_jpeg)
    assert trailing == b"HIDDEN_APPENDED_BYTES"

    # Dimensions
    dims = jpeg.parse_dimensions(raw_jpeg)
    assert dims is not None
    w, h, c = dims
    assert w == 200 and h == 100 and c == 3

    # Inspect summary
    info = jpeg.inspect_jpeg(raw_jpeg)
    assert info["valid"] is True
    assert info["has_jfif"] is True
    assert info["has_trailing_data"] is True


def test_jpeg_artifacts_detection():
    raw_jpeg = make_synthetic_jpeg()
    artifacts = jpeg.detect_f5_outguess_artifacts(raw_jpeg)
    assert artifacts["suspect"] is True
    assert artifacts["trailing_bytes"] > 0


# =============================================================================
# 2. EXIF and Channels Tests
# =============================================================================


def test_exif_parser():
    exif_bytes = make_synthetic_exif()
    parsed = channels.parse_exif(exif_bytes)
    assert parsed.get("Make") == "Nikon"
    assert parsed.get("Model") == "D850-X"


def test_channel_analysis():
    # Synthetic RGB pixels (100 pixels, Blue channel deliberately high entropy)
    import random

    pixels = bytearray()
    for _ in range(100):
        r = 10
        g = 20
        b = random.randint(0, 255)
        pixels.extend([r, g, b])

    res = channels.analyze_channels(bytes(pixels), channels=3)
    assert "Red" in res and "Green" in res and "Blue" in res
    assert res["summary"]["max_entropy_channel"] == "Blue"
    assert res["Blue"]["entropy"] > res["Red"]["entropy"]


# =============================================================================
# 3. Steghide Carrier Inspection Tests
# =============================================================================


def test_steghide_inspection():
    raw_jpeg = make_synthetic_jpeg()
    info = steghide.inspect_steghide_artifacts(raw_jpeg)
    assert info["is_steghide_carrier_format"] is True
    assert info["file_type"] == "jpeg"


def test_steghide_embed_extract_and_crack():
    carrier = bytes([i % 256 for i in range(10000)])
    payload = b"FLAG{steghide_pure_python_verified}"
    pwd = "cybersecret"

    embedded = steghide.embed_steghide(carrier, payload, pwd)
    assert embedded != carrier

    # Extraction with correct passphrase
    extracted = steghide.extract_steghide(embedded, pwd)
    assert extracted == payload

    # Extraction with wrong passphrase
    assert steghide.extract_steghide(embedded, "wrongpassphrase") is None

    # Stegseek-style CRC32 cracker
    cracked = steghide.crack_steghide(embedded, ["admin", "root", "cybersecret", "qwerty"])
    assert cracked is not None
    assert cracked[0] == "cybersecret"
    assert cracked[1] == payload


# =============================================================================
# 4. Audio Spectrogram Tests
# =============================================================================


def test_audio_spectrogram():
    # Generate 500Hz sine wave tone at 8000Hz
    sample_rate = 8000
    freq = 500
    num_samples = 1024
    samples = [
        int(10000 * math.sin(2 * math.pi * freq * i / sample_rate)) for i in range(num_samples)
    ]

    # STFT Spectrogram
    spec = audio_spec.compute_spectrogram(samples, sample_rate=sample_rate, window_size=256)
    assert len(spec) > 0
    assert len(spec[0]) == 128

    # Peak detection
    peaks = audio_spec.detect_spectral_peaks(spec, sample_rate=sample_rate, window_size=256)
    assert len(peaks) > 0
    top_peak_freq = peaks[0]["frequency_hz"]
    # 500 Hz should be within one bin width (8000 / 256 = 31.25 Hz)
    assert abs(top_peak_freq - freq) <= 32.0

    # ASCII heatmap rendering
    ascii_art = audio_spec.render_ascii_spectrogram(spec, width=40, height=10)
    assert len(ascii_art.splitlines()) == 10


# =============================================================================
# 5. CLI Stego Commands Smoke Tests
# =============================================================================


def test_cli_stego_commands(tmp_path):
    # Write synthetic JPEG to temp file
    jpeg_file = tmp_path / "test.jpg"
    jpeg_file.write_bytes(make_synthetic_jpeg())

    # Test jpeg-inspect
    r1 = runner.invoke(app, ["stego", "jpeg-inspect", str(jpeg_file)])
    assert r1.exit_code == 0
    assert "FLAG{jpeg_stego_flag}" in r1.output

    # Test steghide inspection
    r2 = runner.invoke(app, ["stego", "steghide", str(jpeg_file)])
    assert r2.exit_code == 0
    assert "jpeg" in r2.output
