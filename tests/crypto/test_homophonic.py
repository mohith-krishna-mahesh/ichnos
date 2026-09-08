"""Tests for homophonic and nomenclator ciphers."""

from __future__ import annotations

from ichnos.crypto.classical.homophonic import (
    arnold_decrypt,
    arnold_encrypt,
    grandpre_decrypt,
    grandpre_encrypt,
    homophonic_decrypt,
    homophonic_encrypt,
    mexican_wheel_decrypt,
    mexican_wheel_encrypt,
    modulo_decrypt,
    modulo_encrypt,
    nomenclator_decrypt,
    nomenclator_encrypt,
)


def test_homophonic_roundtrip():
    text = "DEFENDTHEEASTWALL"
    enc = homophonic_encrypt(text)
    assert len(enc) == len(text)
    dec = homophonic_decrypt(enc)
    assert dec == text


def test_nomenclator_roundtrip():
    # Contains codebook words (THE, SECRET, FLAG) and individual letters
    text = "THE SECRET FLAG"
    enc = nomenclator_encrypt(text)
    dec = nomenclator_decrypt(enc)
    # The decrypted text should contain the words
    assert "THE" in dec
    assert "SECRET" in dec
    assert "FLAG" in dec


def test_grandpre_roundtrip():
    text = "ATTACK"
    enc = grandpre_encrypt(text)
    assert len(enc) == len(text)
    dec = grandpre_decrypt(enc)
    assert dec == text


def test_arnold_roundtrip():
    book = "Four score and seven years ago our fathers brought forth on this continent a new nation"
    text = "FOUR SCORE AND SEVEN YEARS AGO"
    enc = arnold_encrypt(text, book)
    dec = arnold_decrypt(enc, book)
    assert dec == text


def test_modulo_roundtrip():
    text = "HELLO"
    key = [3, 7, 1, 9, 2]
    enc = modulo_encrypt(text, key)
    dec = modulo_decrypt(enc, key)
    assert dec == text


def test_mexican_wheel_roundtrip():
    text = "ATTACKATDAWN"
    enc = mexican_wheel_encrypt(text, key_letters="ABCDE")
    assert len(enc) == len(text)
    dec = mexican_wheel_decrypt(enc, key_letters="ABCDE")
    assert dec == text
