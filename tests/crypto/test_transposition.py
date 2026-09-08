"""Tests for transposition ciphers."""

from __future__ import annotations

from ichnos.crypto.classical.transposition import (
    adfgvx_decrypt,
    adfgvx_encrypt,
    adfgx_decrypt,
    adfgx_encrypt,
    amsco_decrypt,
    amsco_encrypt,
    caesar_box_decrypt,
    caesar_box_encrypt,
    columnar_decrypt,
    columnar_encrypt,
    double_transposition_decrypt,
    double_transposition_encrypt,
    myszkowski_decrypt,
    myszkowski_encrypt,
    rail_fence_brute,
    rail_fence_decrypt,
    rail_fence_encrypt,
    redefence_decrypt,
    redefence_encrypt,
    route_spiral_decrypt,
    route_spiral_encrypt,
    scytale_decrypt,
    scytale_encrypt,
    skip_decrypt,
    skip_encrypt,
    swagman_decrypt,
    swagman_encrypt,
    turning_grille_decrypt,
    turning_grille_encrypt,
    ubchi_decrypt,
    ubchi_encrypt,
)


def test_rail_fence_roundtrip():
    text = "DEFENDTHEEASTWALLOFTHECASTLE"
    for rails in [2, 3, 4, 5]:
        enc = rail_fence_encrypt(text, rails)
        dec = rail_fence_decrypt(enc, rails)
        assert dec == text


def test_rail_fence_known():
    # Standard 3-rail:
    # W . . . E . . . C . . . R . . . T
    # . E . R . D . S . O . E . E . E .
    # . . A . . . I . . . V . . . D . .
    # -> WECRT ERDSOEEE AIVD
    text = "WEAREDISCOVEREDFLEEATONCE"
    enc = rail_fence_encrypt(text, 3)
    dec = rail_fence_decrypt(enc, 3)
    assert dec == text


def test_rail_fence_brute():
    text = "THISISSECRETENGLISHPLAINTEXTFORTESTINGRAILFENCEBRUTEFORCE"
    enc = rail_fence_encrypt(text, 4)
    candidates = rail_fence_brute(enc, max_rails=6)
    assert len(candidates) > 0
    # One of the candidates should have key="4"
    match = next((c for c in candidates if c.key == "4"), None)
    assert match is not None
    assert match.decoded.decode() == text


def test_columnar_roundtrip():
    text = "DEFENDTHEEASTWALL"
    key = "GERMAN"
    enc = columnar_encrypt(text, key)
    dec = columnar_decrypt(enc, key)
    assert dec == text


def test_columnar_numeric_key():
    text = "ATTACKATDAWN"
    key = [3, 1, 4, 2]
    enc = columnar_encrypt(text, key)
    dec = columnar_decrypt(enc, key)
    assert dec == text


def test_double_transposition_roundtrip():
    text = "ATTACKPOSTPONEDUNTILDAWN"
    k1 = "ZEBRA"
    k2 = "STRIPE"
    enc = double_transposition_encrypt(text, k1, k2)
    dec = double_transposition_decrypt(enc, k1, k2)
    assert dec == text


def test_myszkowski_roundtrip():
    text = "WEAREDISCOVEREDFLEEATONCE"
    key = "TOMATO"  # Has repeated letters: O, T
    enc = myszkowski_encrypt(text, key)
    dec = myszkowski_decrypt(enc, key)
    assert dec == text


def test_route_spiral_roundtrip():
    text = "ATTACKATDAWNTOMORROW"
    for cols in [4, 5]:
        enc = route_spiral_encrypt(text, cols)
        dec = route_spiral_decrypt(enc, cols)
        assert dec == text


def test_scytale_roundtrip():
    text = "IAMHURTVERYBADLYHELP"
    for d in [3, 4, 5]:
        enc = scytale_encrypt(text, d)
        dec = scytale_decrypt(enc, d)
        assert dec == text


def test_skip_cipher_roundtrip():
    text = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    enc = skip_encrypt(text, skip=3, offset=0)
    dec = skip_decrypt(enc, skip=3, offset=0)
    assert dec == text


def test_swagman_roundtrip():
    text = "THISISASWAGMANTESTOFTRANSPOSITION"
    enc = swagman_encrypt(text, rows=3, cols=4)
    dec = swagman_decrypt(enc, rows=3, cols=4)
    assert dec == text


def test_turning_grille_roundtrip():
    # 4x4 turning grille encrypts 16-char blocks
    text = "HELLOWORLDFLAGOK"
    enc = turning_grille_encrypt(text, size=4)
    dec = turning_grille_decrypt(enc, size=4)
    assert dec == text


def test_adfgx_roundtrip():
    text = "ATTACKATDAWN"
    sq_key = "PHQGMEAYNOFDXKRCSVZWTBUIL"
    col_key = "GERMAN"
    enc = adfgx_encrypt(text, sq_key, col_key)
    # Ciphertext should only contain letters A, D, F, G, X
    assert set(enc).issubset(set("ADFGX"))
    dec = adfgx_decrypt(enc, sq_key, col_key)
    # I and J are merged in ADFGX 5x5
    assert dec == text


def test_adfgvx_roundtrip():
    text = "ATTACKAT0600HOURS"
    sq_key = "NA1C3H8TB2OME5WRPD4F6G7I9J0KLQSUVXYZ"
    col_key = "PRIVACY"
    enc = adfgvx_encrypt(text, sq_key, col_key)
    assert set(enc).issubset(set("ADFGVX"))
    dec = adfgvx_decrypt(enc, sq_key, col_key)
    assert dec == text


def test_amsco_roundtrip():
    text = "INCOMPLETECOLUMNARWITHVARIEDLENGTHS"
    key = "41325"
    enc = amsco_encrypt(text, key)
    dec = amsco_decrypt(enc, key)
    assert dec == text


def test_caesar_box_roundtrip():
    text = "FOURBYFOURGRIDOK"
    enc = caesar_box_encrypt(text, side=4)
    dec = caesar_box_decrypt(enc, side=4)
    assert dec == text


def test_redefence_roundtrip():
    text = "DEFENDTHEEASTWALLOFTHECASTLE"
    enc = redefence_encrypt(text, rails=3)
    dec = redefence_decrypt(enc, rails=3)
    assert dec == text


def test_ubchi_roundtrip():
    text = "ATTACKPOSTPONEDUNTILDAWN"
    enc = ubchi_encrypt(text, "KEYONE", "KEYTWO")
    dec = ubchi_decrypt(enc, "KEYONE", "KEYTWO")
    assert dec == text
