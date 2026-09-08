"""Unit tests for core.runner and command dispatch."""

import tempfile
from pathlib import Path

from ichnos.core.runner import run_command


def test_runner_caesar():
    # Decrypt KHOOR with shift 3 -> HELLO
    res = run_command("crypto caesar 'KHOOR' --shift 3")
    assert res.status == "success"
    assert len(res.candidates) >= 1
    assert res.candidates[0].decoded_str == "HELLO"

    # Encrypt HELLO with shift 3 -> KHOOR
    res_enc = run_command("crypto caesar 'HELLO' --shift 3 --encrypt")
    assert res_enc.status == "success"
    assert res_enc.candidates[0].decoded_str == "KHOOR"


def test_runner_encoding_auto():
    # Base64 string
    res = run_command("encoding auto 'SGVsbG8gV29ybGQ='")
    assert res.status == "success"
    assert any("Hello World" in c.decoded_str for c in res.candidates)


def test_runner_binary_strings():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"JUNK\x00FLAG{strings_runner_working}\x00MORE_JUNK")
        f_path = f.name

    try:
        res = run_command(f"binary strings '{f_path}' -n 4")
        assert res.status == "success"
        assert any("FLAG{strings_runner_working}" in find.detail for find in res.findings)
    finally:
        Path(f_path).unlink(missing_ok=True)


def test_runner_unknown_command_and_syntax_error():
    res_unknown = run_command("nonexistent module foo")
    assert res_unknown.status == "error"
    assert "Unknown Command" in res_unknown.findings[0].label

    res_syntax = run_command("crypto caesar 'unclosed quote")
    assert res_syntax.status == "error"
    assert "Syntax Error" in res_syntax.findings[0].label


def test_runner_atbash_and_hash_id():
    res = run_command("crypto atbash 'SVOOL'")
    assert res.status == "success"
    assert res.candidates[0].decoded_str == "HELLO"

    res_h = run_command("crypto hash-id '5d41402abc4b2a76b9719d911017c592'")
    assert res_h.status == "success"
    assert any("MD5" in f.label or "MD5" in f.detail for f in res_h.findings)

    # Nested crypto hash identify
    res_h2 = run_command("crypto hash identify '5d41402abc4b2a76b9719d911017c592'")
    assert res_h2.status == "success"
    assert any("MD5" in f.label or "MD5" in f.detail for f in res_h2.findings)


def test_runner_with_active_input():
    from ichnos.core.models import Input, SourceType

    inp = Input(data=b"SGVsbG8gSWNobm9z", source_type=SourceType.RAW, detected_type="text")
    # Dispatched without explicit positional string argument
    res = run_command("encoding decode --format base64", active_input=inp)
    assert res.status == "success"
    assert res.candidates[0].decoded_str == "Hello Ichnos"


def test_runner_connected_modules():
    from ichnos.core.models import Input, SourceType

    # 1. Crypto Affine & Enigma & Symboltable
    res_aff = run_command("crypto affine 'HELLO' --a 5 --b 8 --encrypt")
    assert res_aff.status == "success"
    assert res_aff.candidates[0].decoded_str == "RCLLA"

    res_enig = run_command("crypto enigma 'HELLO'")
    assert res_enig.status == "success"
    assert len(res_enig.candidates) >= 1

    res_sym = run_command("crypto symboltable 'HELLO' --table morse --encode")
    assert res_sym.status == "success"
    assert len(res_sym.candidates) >= 1

    # 2. Encoding Morse & Esolang
    res_morse = run_command("encoding morse 'HELLO' --encode")
    assert res_morse.status == "success"
    assert ".... . .-.. .-.. ---" in res_morse.candidates[0].decoded_str

    res_eso = run_command("encoding esolang 'iissso' --lang deadfish")
    assert res_eso.status == "success"
    assert len(res_eso.candidates) >= 1

    # 3. Stego Text Null (both nested and flat alias)
    res_stego = run_command("stego text null 'Heavy Eagles Land Low Often' --mode first-letter")
    assert res_stego.status == "success"
    assert res_stego.candidates[0].decoded_str == "HELLO"

    res_stego_alias = run_command(
        "stego text-null 'Heavy Eagles Land Low Often' --mode first-letter"
    )
    assert res_stego_alias.status == "success"

    # Crypto XOR Single
    res_xor = run_command("crypto xor single 'IFMMP'")
    assert res_xor.status == "success"
    assert len(res_xor.candidates) >= 1

    # 4. Forensic Timestamp
    res_ts = run_command("forensic timestamp 1700000000")
    assert res_ts.status == "success"
    assert len(res_ts.findings) >= 1
    assert "2023" in res_ts.findings[0].detail

    # 5. Password Mutate
    res_pass = run_command("password mutate 'secret'")
    assert res_pass.status == "success"
    assert len(res_pass.candidates) >= 1

    # 6. Reverse NOP (both via patch --nop and legacy nop)
    inp_bin = Input(data=b"\x55\x48\x89\xe5", source_type=SourceType.RAW, detected_type="binary")
    res_nop = run_command("reverse nop --offset 0 --length 2 --arch x86", active_input=inp_bin)
    assert res_nop.status == "success"
    assert res_nop.candidates[0].decoded == b"\x90\x90\x89\xe5"

    res_patch_nop = run_command(
        "reverse patch --nop --offset 0 --length 2 --arch x86 target_placeholder",
        active_input=inp_bin,
    )
    assert res_patch_nop.status == "success"


def test_runner_module_help_listings():
    # Typing module name directly gives available commands list with status success
    res_crypto = run_command("crypto")
    assert res_crypto.status == "success"
    assert "Available commands for 'crypto':" in res_crypto.raw_output
    assert "crypto caesar" in res_crypto.raw_output
    assert "crypto substitution" in res_crypto.raw_output
    assert "crypto playfair" in res_crypto.raw_output

    res_web = run_command("web")
    assert res_web.status == "success"
    assert "Available commands for 'web':" in res_web.raw_output
    assert "web fuzz" in res_web.raw_output
    assert "web headers" in res_web.raw_output

    res_xor = run_command("crypto xor")
    assert res_xor.status == "success"
    assert "Available commands for 'crypto xor':" in res_xor.raw_output
    assert "crypto xor single" in res_xor.raw_output
    assert "crypto xor repeating" in res_xor.raw_output

    res_help_mod = run_command("help crypto")
    assert res_help_mod.status == "success"
    assert "Available commands for 'crypto':" in res_help_mod.raw_output


def test_runner_expanded_commands():
    # Math GCD
    res_gcd = run_command("crypto math gcd 48 18")
    assert res_gcd.status == "success"
    assert res_gcd.raw_output == {"gcd": 6}

    # Text Acrostic
    text = "Save\nOur\nShip"
    res_acrostic = run_command(f"stego text acrostic '{text}'")
    assert res_acrostic.status == "success"
    assert res_acrostic.candidates[0].decoded_str == "SOS"

    # Encoding Encode
    res_enc = run_command("encoding encode 'hello' -f hex")
    assert res_enc.status == "success"
    assert res_enc.candidates[0].decoded_str == "68656c6c6f"
