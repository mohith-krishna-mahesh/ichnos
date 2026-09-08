from ichnos.crypto.classical.vigenere import crack, decrypt, encrypt, index_of_coincidence


def test_encrypt_decrypt_roundtrip():
    plaintext = "Hello World! It's a sunny day."
    key = "KEY"
    ciphertext = encrypt(plaintext, key)
    decrypted = decrypt(ciphertext, key)
    assert decrypted == plaintext


def test_known_encryption(vigenere_known):
    plaintext, key, expected_ciphertext = vigenere_known
    assert encrypt(plaintext, key) == expected_ciphertext


def test_index_of_coincidence_english():
    text = "The quick brown fox jumps over the lazy dog. This sentence should have an IoC close to English."
    ioc = index_of_coincidence(text)
    # English IoC is around 0.065
    assert 0.045 < ioc < 0.08


def test_crack_recovers_key():
    plaintext = "The quick brown fox jumps over the lazy dog. It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness."
    key = "SECRET"
    ciphertext = encrypt(plaintext, key)

    candidate = crack(ciphertext)

    assert candidate.key == key
    # It might have a small difference if text is short, but this text is long enough for frequency analysis.
    # The letters case might differ based on original text and how it restores, but our implementation retains the case of original.
    assert candidate.decoded_str == plaintext


def test_preserves_non_alpha():
    plaintext = "Hello, World! 123"
    key = "AB"
    assert encrypt(plaintext, key) == "Hflmo, Xosle! 123"
    assert decrypt("Hflmo, Xosle! 123", key) == plaintext
