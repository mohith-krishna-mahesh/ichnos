from ichnos.crypto.xor.crib_drag import crib_drag, xor_bytes
from ichnos.crypto.xor.repeating_key import crack as repeating_key_crack
from ichnos.crypto.xor.repeating_key import hamming_distance, xor_repeating
from ichnos.crypto.xor.single_byte import brute_force as single_byte_brute
from ichnos.crypto.xor.single_byte import xor_single


def test_single_byte_roundtrip():
    data = b"Hello World!"
    key = 42
    enc = xor_single(data, key)
    dec = xor_single(enc, key)
    assert dec == data


def test_single_byte_brute_force():
    data = b"This is a secret message that needs to be cracked."
    key = 100
    enc = xor_single(data, key)

    candidates = single_byte_brute(enc)
    best = candidates[0]

    assert best.decoded == data
    assert best.key == hex(key)


def test_repeating_key_roundtrip():
    data = b"Hello World! This is a test."
    key = b"KEY"
    enc = xor_repeating(data, key)
    dec = xor_repeating(enc, key)
    assert dec == data


def test_hamming_distance():
    a = b"this is a test"
    b = b"wokka wokka!!!"
    assert hamming_distance(a, b) == 37


def test_repeating_key_crack():
    data = b"The quick brown fox jumps over the lazy dog. It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness. Super long text for statistical analysis."
    key = b"SECRET"
    enc = xor_repeating(data, key)

    candidate = repeating_key_crack(enc)

    assert candidate.decoded == data
    assert candidate.key == key.hex()


def test_crib_drag():
    pt1 = b"Hello World!"
    pt2 = b"Secret text!"

    # Normally you have 2 ciphertexts encrypted with same one-time pad
    pad = b"123456789012"
    ct1 = xor_bytes(pt1, pad)
    ct2 = xor_bytes(pt2, pad)

    # We guess that pt1 contains "Hello"
    results = crib_drag(ct1, ct2, "Hello")

    # The result should contain the corresponding part of pt2 at index 0, which is "Secre"
    assert len(results) > 0
    assert any(pos == 0 and text == "Secre" for pos, text in results)
