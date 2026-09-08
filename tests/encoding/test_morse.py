import pytest

from ichnos.encoding.morse import decode, encode


def test_encode_hello():
    assert encode("HELLO") == ".... . .-.. .-.. ---"


def test_decode_hello():
    assert decode(".... . .-.. .-.. ---") == "HELLO"


@pytest.mark.parametrize("text", ["SOS", "HELLO WORLD", "TEST 123"])
def test_encode_decode_roundtrip(text):
    encoded = encode(text)
    decoded = decode(encoded)
    assert decoded == text


def test_decode_flexible_separators():
    morse_with_slash = ".... . .-.. .-.. --- / .-- --- .-. .-.. -.."
    morse_with_pipe = ".... . .-.. .-.. --- | .-- --- .-. .-.. -.."
    assert decode(morse_with_slash) == "HELLO WORLD"
    assert decode(morse_with_pipe) == "HELLO WORLD"


def test_encode_numbers():
    assert encode("123") == ".---- ..--- ...--"
