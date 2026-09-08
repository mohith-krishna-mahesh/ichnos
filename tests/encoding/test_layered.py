from ichnos.encoding.bases import encode_base64, encode_hex
from ichnos.encoding.layered import auto_decode


def test_single_layer_base64():
    data = b"hello"
    enc = encode_base64(data)
    candidates = auto_decode(enc)
    assert any(c["decoded"] == data for c in candidates)


def test_double_layer():
    data = b"hi"
    enc = encode_base64(encode_hex(data).encode())
    candidates = auto_decode(enc)
    assert any(c["decoded"] == data for c in candidates)


def test_no_encoding():
    text = "this is just a normal english text sentence"
    candidates = auto_decode(text)
    assert len(candidates) == 0 or all(c["confidence"] < 0.5 for c in candidates)
