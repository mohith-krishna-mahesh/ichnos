"""Tests for polygraphic ciphers."""

from __future__ import annotations

from ichnos.crypto.classical.polygraphic import (
    bifid_decrypt,
    bifid_encrypt,
    four_square_decrypt,
    four_square_encrypt,
    fractionated_morse_decrypt,
    fractionated_morse_encrypt,
    morbit_decrypt,
    morbit_encrypt,
    playfair_decrypt,
    playfair_encrypt,
    playfair_solve,
    pollux_decrypt,
    pollux_encrypt,
    trifid_decrypt,
    trifid_encrypt,
    two_square_decrypt,
    two_square_encrypt,
)


def test_playfair_roundtrip():
    # Playfair uses I/J equivalence and digraph padding
    text = "INSTRUMENTS"
    key = "MONARCHY"
    enc = playfair_encrypt(text, key)
    dec = playfair_decrypt(enc, key)
    assert dec.startswith("INSTRUMENTS")


def test_playfair_solve_smoke():
    text = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    key = "CIPHER"
    enc = playfair_encrypt(text, key)
    # Run a fast 50-iteration solve
    cand = playfair_solve(enc, iterations=50, restarts=1)
    assert cand.method == "playfair"
    assert len(cand.decoded) > 0


def test_four_square_roundtrip():
    text = "ATTACKATDAWN"
    k1 = "EXAMPLE"
    k2 = "KEYWORD"
    enc = four_square_encrypt(text, k1, k2)
    dec = four_square_decrypt(enc, k1, k2)
    assert dec == text


def test_two_square_horizontal():
    text = "HELPME"
    k1 = "FIRST"
    k2 = "SECOND"
    enc = two_square_encrypt(text, k1, k2, horizontal=True)
    dec = two_square_decrypt(enc, k1, k2, horizontal=True)
    assert dec == text


def test_two_square_vertical():
    text = "HELPME"
    k1 = "FIRST"
    k2 = "SECOND"
    enc = two_square_encrypt(text, k1, k2, horizontal=False)
    dec = two_square_decrypt(enc, k1, k2, horizontal=False)
    assert dec == text


def test_bifid_roundtrip():
    text = "DEFENDTHEEASTWALL"
    key = "FLEXIBILITY"
    enc = bifid_encrypt(text, key, period=5)
    dec = bifid_decrypt(enc, key, period=5)
    assert dec == text


def test_trifid_roundtrip():
    text = "FELIXMARIE"
    key = "TRIFIDKEY"
    enc = trifid_encrypt(text, key, period=5)
    dec = trifid_decrypt(enc, key, period=5)
    assert dec == text


def test_morbit_roundtrip():
    text = "SOS"
    key = "123456789"
    enc = morbit_encrypt(text, key)
    dec = morbit_decrypt(enc, key)
    assert dec == text


def test_pollux_roundtrip():
    text = "HELLO"
    enc = pollux_encrypt(text)
    dec = pollux_decrypt(enc, dot_digits="012", dash_digits="345", space_digits="6789")
    assert dec == text


def test_fractionated_morse_roundtrip():
    text = "DEFENDTHEEAST"
    key = "ROUNDTABLE"
    enc = fractionated_morse_encrypt(text, key)
    dec = fractionated_morse_decrypt(enc, key)
    assert dec == text
