from ichnos.encoding.bases import (
    auto_detect,
    decode_base32,
    decode_base58,
    decode_base64,
    decode_base64url,
    decode_base85,
    decode_base91,
    decode_hex,
    encode_base32,
    encode_base58,
    encode_base64,
    encode_base64url,
    encode_base85,
    encode_base91,
    encode_hex,
)


def test_hex_roundtrip():
    data = b"hello"
    enc = encode_hex(data)
    assert decode_hex(enc) == data


def test_base64_roundtrip():
    data = b"hello world"
    enc = encode_base64(data)
    assert enc == "aGVsbG8gd29ybGQ="
    assert decode_base64(enc) == data


def test_base64url_roundtrip():
    data = b"\xfb\xff\xbf"
    enc = encode_base64url(data)
    assert decode_base64url(enc) == data


def test_base32_roundtrip():
    data = b"hello"
    enc = encode_base32(data)
    assert decode_base32(enc) == data


def test_base58_roundtrip():
    data = b"hello"
    enc = encode_base58(data)
    assert decode_base58(enc) == data


def test_base85_roundtrip():
    data = b"hello"
    enc = encode_base85(data)
    assert decode_base85(enc) == data


def test_base91_roundtrip():
    data = b"hello"
    enc = encode_base91(data)
    assert decode_base91(enc) == data


def test_auto_detect_base64():
    candidates = auto_detect("aGVsbG8gd29ybGQ=")
    assert any("base64" in c["encoding"].lower() for c in candidates)


def test_auto_detect_hex():
    candidates = auto_detect("48656c6c6f")
    assert any("hex" in c["encoding"].lower() for c in candidates)


def test_auto_detect_does_not_flag_file_path():
    candidates = auto_detect("/Users/username/Downloads")
    assert len(candidates) == 0
