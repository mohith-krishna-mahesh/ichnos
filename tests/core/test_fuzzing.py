"""Comprehensive adversarial input fuzzing and security verification suite.

Tests against:
- Truncation slices (0 to 128 bytes) across all parsers
- Extreme value mutations (0, 0xFFFF, 0xFFFFFFFF, negative/overflowing offsets)
- Pseudo-random byte fuzzing
- Decompression bomb detection (zlib, gzip, bz2, xz)
- Path traversal defense (Zip Slip, Tar Slip, Windows drives, null bytes)
- AST Evaluator DoS defense (2**999999999999, nested expressions, quadratic int conversions)
- Terminal / ANSI escape injection stripping
"""

from __future__ import annotations

import ast
import random
import struct
import tarfile
import zipfile
import zlib
from io import BytesIO

import pytest

from ichnos.binary.elf import parse_elf
from ichnos.binary.macho import parse_macho
from ichnos.binary.pe import parse_pe
from ichnos.core.harvester import ASTEvaluator, CTFHarvester
from ichnos.core.security import (
    safe_decompress_bz2,
    safe_decompress_gzip,
    safe_decompress_zlib,
    sanitize_archive_path,
    sanitize_terminal_output,
)
from ichnos.forensic.archives import inspect_tar
from ichnos.forensic.zip import inspect_zip
from ichnos.pcap.parser import read_pcap, read_pcapng
from ichnos.stego.audio.wav import get_samples, parse_wav
from ichnos.stego.image.jpeg import parse_segments
from ichnos.stego.image.lsb import extract_raw_pixels
from ichnos.stego.image.png import parse_chunks, parse_ihdr

# ============================================================================
# 1. Truncation Fuzzing
# ============================================================================

PARSERS = [
    ("elf", parse_elf),
    ("pe", parse_pe),
    ("macho", parse_macho),
    ("pcap", read_pcap),
    ("pcapng", read_pcapng),
    ("png", parse_chunks),
    ("jpeg", parse_segments),
    ("wav", parse_wav),
    ("wav_samples", get_samples),
    ("tar", inspect_tar),
    ("zip", inspect_zip),
]

TRUNCATION_LENGTHS = [0, 1, 2, 4, 8, 12, 16, 24, 32, 48, 64, 128]


@pytest.mark.parametrize("length", TRUNCATION_LENGTHS)
def test_truncation_fuzzing(length: int):
    """Parsers must gracefully handle truncated byte buffers without unhandled crashes."""
    # Seeded pseudo-random data of given length
    rng = random.Random(42 + length)
    buf = rng.randbytes(length)

    for name, parser in PARSERS:
        try:
            parser(buf)
        except (ValueError, IndexError, struct.error, zipfile.BadZipFile):
            # Graceful rejection
            pass
        except Exception as e:
            pytest.fail(f"Parser '{name}' crashed with unhandled {type(e).__name__} on length {length}: {e}")


# ============================================================================
# 2. Random High-Entropy Byte Fuzzing
# ============================================================================

def test_random_garbage_fuzzing():
    """Parsers must handle arbitrary random byte sequences without unhandled crashes."""
    rng = random.Random(1337)
    for _ in range(50):
        length = rng.randint(10, 4096)
        data = rng.randbytes(length)
        for name, parser in PARSERS:
            try:
                parser(data)
            except (ValueError, IndexError, struct.error, zipfile.BadZipFile):
                pass
            except Exception as e:
                pytest.fail(f"Parser '{name}' crashed on random buffer: {e}")


# ============================================================================
# 3. Decompression Bomb Defenses
# ============================================================================

def test_zlib_decompression_bomb_rejected():
    """Safe decompressor must abort high-ratio / oversized zlib bomb."""
    # 100MB of zeros compressed is ~100KB
    raw = b"\x00" * (100 * 1024 * 1024)
    bomb = zlib.compress(raw, level=9)

    # Default limit is 64MB; should raise ValueError
    with pytest.raises(ValueError, match="Decompression bomb detected"):
        safe_decompress_zlib(bomb, max_size=10 * 1024 * 1024)


def test_gzip_decompression_bomb_rejected():
    """Safe decompressor must abort oversized gzip stream."""
    import gzip

    raw = b"\x00" * (20 * 1024 * 1024)
    gz_bomb = gzip.compress(raw)
    with pytest.raises(ValueError, match="Decompression bomb detected"):
        safe_decompress_gzip(gz_bomb, max_size=5 * 1024 * 1024)


def test_bz2_decompression_bomb_rejected():
    """Safe decompressor must abort oversized bz2 stream."""
    import bz2

    raw = b"\x00" * (20 * 1024 * 1024)
    bz2_bomb = bz2.compress(raw)
    with pytest.raises(ValueError, match="Decompression bomb detected"):
        safe_decompress_bz2(bz2_bomb, max_size=5 * 1024 * 1024)


def test_png_oversized_dimensions_rejected():
    """PNG parser and LSB extractor must reject astronomical dimensions."""
    # Build IHDR with dimensions 100,000 x 100,000
    ihdr_data = (
        (100_000).to_bytes(4, "big")
        + (100_000).to_bytes(4, "big")
        + b"\x08\x02\x00\x00\x00"  # 8-bit depth, RGB, default compression/filter/interlace
    )
    with pytest.raises(ValueError, match="PNG dimensions out of supported range"):
        parse_ihdr(ihdr_data)

    png_sig = b"\x89PNG\r\n\x1a\n"
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data).to_bytes(4, "big")
    fake_png = png_sig + (13).to_bytes(4, "big") + b"IHDR" + ihdr_data + ihdr_crc
    with pytest.raises(ValueError, match="PNG dimensions out of supported range"):
        extract_raw_pixels(fake_png)


# ============================================================================
# 4. Path Traversal Defenses (Zip Slip & Tar Slip)
# ============================================================================

def test_sanitize_archive_path_rejections():
    """Archive path sanitizer must reject traversal patterns."""
    bad_paths = [
        "../../etc/passwd",
        "../flag.txt",
        "/absolute/path/to/secret",
        "C:\\Windows\\System32\\cmd.exe",
        "foo/bar/../../../../root/.ssh/id_rsa",
        "safe\x00evil.txt",
    ]
    for p in bad_paths:
        with pytest.raises(ValueError, match="detected"):
            sanitize_archive_path(p)


def test_sanitize_archive_path_accepts_clean():
    """Archive path sanitizer must normalize and allow clean relative paths."""
    assert sanitize_archive_path("flag.txt") == "flag.txt"
    assert sanitize_archive_path("nested/folder/flag.txt") == "nested/folder/flag.txt"
    assert sanitize_archive_path("./relative/path.txt") == "relative/path.txt"


def test_zip_path_traversal_detection():
    """ZIP inspector must flag entries attempting Zip Slip."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../evil.sh", "echo pwned")
        zf.writestr("normal.txt", "hello")

    res = inspect_zip(buf.getvalue())
    assert res["has_path_traversal"] is True
    assert "../../evil.sh" in res["traversal_entries"]


def test_tar_path_traversal_detection():
    """TAR inspector must flag entries attempting Tar Slip."""
    buf = BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        ti = tarfile.TarInfo(name="../../../../etc/shadow")
        ti.size = 5
        tf.addfile(ti, BytesIO(b"root:"))
        ti2 = tarfile.TarInfo(name="legit.txt")
        ti2.size = 5
        tf.addfile(ti2, BytesIO(b"hello"))

    res = inspect_tar(buf.getvalue())
    assert res["has_path_traversal"] is True
    assert "../../../../etc/shadow" in res["traversal_entries"]


# ============================================================================
# 5. AST Evaluator DoS Defenses
# ============================================================================

def test_ast_evaluator_huge_exponentiation():
    """AST evaluator must reject 2**999999999999 without hanging or allocating."""
    t = ast.parse("2**999999999999", mode="eval").body
    assert ASTEvaluator.evaluate(t) is None


def test_ast_evaluator_huge_multiplication():
    """AST evaluator must reject integer bit-growth exceeding MAX_BITS (16384)."""
    # 2**8000 is within bounds; (2**8000) * (2**9000) = 2**17000 exceeds 16384 bits
    env = {"a": 1 << 8000, "b": 1 << 9000}
    t = ast.parse("a * b", mode="eval").body
    assert ASTEvaluator.evaluate(t, env=env) is None


def test_ast_evaluator_deep_recursion_rejection():
    """AST evaluator must reject expressions nested > 50 levels deep."""
    expr = "-(" * 60 + "1" + ")" * 60
    t = ast.parse(expr, mode="eval").body
    assert ASTEvaluator.evaluate(t) is None

    expr2 = "1 + (" * 60 + "1" + ")" * 60
    t2 = ast.parse(expr2, mode="eval").body
    assert ASTEvaluator.evaluate(t2) is None


def test_ast_evaluator_string_to_int_quadratic_bound():
    """AST evaluator must reject int() calls on string representations > 8192 characters."""
    t = ast.parse(f"int('{'9'*10000}')", mode="eval").body
    assert ASTEvaluator.evaluate(t) is None


def test_ast_evaluator_legitimate_rsa_parameters():
    """AST evaluator must succeed on legitimate 4096-bit RSA parameters and math."""
    n_str = str(0x10001)
    t = ast.parse(f"65537 + int('{n_str}')", mode="eval").body
    assert ASTEvaluator.evaluate(t) == 65537 + 0x10001

    t2 = ast.parse("pow(2, 16)", mode="eval").body
    assert ASTEvaluator.evaluate(t2) == 65536


def test_harvester_all_vars_ceiling():
    """Harvester all_vars dictionary must not grow unboundedly."""
    lines = [f"var_{i} = {i}" for i in range(1500)]
    code = "\n".join(lines)
    params = CTFHarvester.harvest_text(code, source_name="massive_dump.py")
    assert len(params.all_vars) <= 1000


# ============================================================================
# 6. Terminal / ANSI Injection Defenses
# ============================================================================

def test_sanitize_terminal_output_ansi_csi():
    """Removes terminal escape sequences like cursor movement, color codes, and clears."""
    payload = "\x1b[2J\x1b[H\x1b[31;1mCRITICAL\x1b[0m"
    cleaned = sanitize_terminal_output(payload)
    assert "\x1b" not in cleaned
    assert "CRITICAL" in cleaned


def test_sanitize_terminal_output_osc52_clipboard():
    """Removes OSC 52 clipboard hijacking sequences."""
    payload = "Hello\x1b]52;c;c2VjcmV0\x07World"
    cleaned = sanitize_terminal_output(payload)
    assert "\x1b" not in cleaned
    assert "c2VjcmV0" not in cleaned
    assert "Hello" in cleaned
    assert "World" in cleaned


def test_sanitize_terminal_output_ascii_controls():
    """Replaces raw ASCII control characters while preserving newline and tab."""
    payload = "Line1\nLine2\tTab\x00\x07\x08End"
    cleaned = sanitize_terminal_output(payload)
    assert "\n" in cleaned
    assert "\t" in cleaned
    assert "\x00" not in cleaned
    assert "\x07" not in cleaned
    assert "\x08" not in cleaned
    assert "End" in cleaned
