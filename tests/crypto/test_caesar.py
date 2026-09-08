import pytest

from ichnos.crypto.classical.caesar import auto_detect, brute_force, decrypt, encrypt


@pytest.mark.parametrize("shift", range(26))
def test_encrypt_decrypt_roundtrip(shift):
    plaintext = "Hello World! 123"
    ciphertext = encrypt(plaintext, shift)
    decrypted = decrypt(ciphertext, shift)
    assert decrypted == plaintext


def test_caesar_rot13(caesar_rot13_text):
    ciphertext, plaintext, shift = caesar_rot13_text
    assert decrypt(ciphertext, shift) == plaintext
    assert encrypt(plaintext, shift) == ciphertext


def test_brute_force_finds_rot13(caesar_rot13_text):
    ciphertext, plaintext, shift = caesar_rot13_text
    candidates = brute_force(ciphertext)
    best = candidates[0]

    assert best.decoded_str == plaintext
    assert best.key == str(shift)
    assert best.method == "caesar"


def test_auto_detect_rot13(caesar_rot13_text):
    ciphertext, plaintext, shift = caesar_rot13_text
    best = auto_detect(ciphertext)
    assert best.decoded_str == plaintext
    assert best.key == str(shift)


def test_preserves_case():
    assert encrypt("AbCd", 1) == "BcDe"
    assert decrypt("BcDe", 1) == "AbCd"


def test_preserves_non_alpha():
    assert encrypt("Hello, World! 123", 5) == "Mjqqt, Btwqi! 123"
    assert decrypt("Mjqqt, Btwqi! 123", 5) == "Hello, World! 123"
