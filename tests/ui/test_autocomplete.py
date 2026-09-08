"""Unit tests for registry autocomplete and filesystem path completion."""

import tempfile
from pathlib import Path

import ichnos.core.commands  # noqa: F401
from ichnos.core.registry import complete_path, registry


def test_autocomplete_token0_modules_and_builtins():
    # Token 0 matches builtins
    c_help = registry.get_completions(["hel"])
    assert any(cmd == "help" for cmd, _ in c_help)

    c_load = registry.get_completions(["lo"])
    assert any(cmd == "load" for cmd, _ in c_load)

    c_theme = registry.get_completions(["the"])
    assert any(cmd == "theme" for cmd, _ in c_theme)

    # Token 0 matches registered modules
    c_crypto = registry.get_completions(["cry"])
    assert any(mod == "crypto" for mod, _ in c_crypto)

    c_bin = registry.get_completions(["bin"])
    assert any(mod == "binary" for mod, _ in c_bin)

    # Token 0 matches top-level analyze
    c_analyze = registry.get_completions(["ana"])
    assert any(cmd == "analyze" for cmd, _ in c_analyze)


def test_autocomplete_token1_subcommands():
    # Under 'crypto'
    c_caesar = registry.get_completions(["crypto", "cae"])
    assert any(cmd == "caesar" for cmd, _ in c_caesar)

    c_vigenere = registry.get_completions(["crypto", "vig"])
    assert any(cmd == "vigenere" for cmd, _ in c_vigenere)

    # Under 'binary'
    c_strings = registry.get_completions(["binary", "str"])
    assert any(cmd == "strings" for cmd, _ in c_strings)


def test_autocomplete_flags():
    # Under 'crypto caesar --'
    c_flags = registry.get_completions(["crypto", "caesar", "--"])
    flag_names = [f for f, _ in c_flags]
    assert "--shift" in flag_names
    assert "--brute" in flag_names
    assert "--encrypt" in flag_names


def test_autocomplete_path_completion():
    with tempfile.TemporaryDirectory() as tmpdir:
        file1 = Path(tmpdir) / "sample_secret.txt"
        file2 = Path(tmpdir) / "sample_data.bin"
        sub_dir = Path(tmpdir) / "subfolder"
        file1.write_text("secret")
        file2.write_bytes(b"data")
        sub_dir.mkdir()

        # Path completion with prefix
        matches = complete_path(f"{tmpdir}/sample_")
        names = [m[0] for m in matches]
        assert any("sample_secret.txt" in n for n in names)
        assert any("sample_data.bin" in n for n in names)

        # Directory completion should append '/'
        dir_matches = complete_path(f"{tmpdir}/sub")
        assert any(n.endswith("/") and "subfolder" in n for n, _ in dir_matches)
