from ichnos.binary.strings import extract_all, extract_ascii, extract_utf16le


def test_extract_ascii():
    data = b"\x00\x00hello\x00\x00world\x00\x00"
    res = list(extract_ascii(data, min_length=4))
    assert len(res) == 2
    assert res[0][1] == "hello"
    assert res[1][1] == "world"


def test_extract_ascii_min_length():
    data = b"\x00\x00hello\x00\x00world\x00\x00"
    res = list(extract_ascii(data, min_length=6))
    assert len(res) == 0


def test_extract_utf16le():
    data = b"h\x00e\x00l\x00l\x00o\x00\x00\x00w\x00o\x00r\x00l\x00d\x00"
    res = list(extract_utf16le(data, min_length=4))
    assert len(res) == 2
    assert res[0][1] == "hello"
    assert res[1][1] == "world"


def test_extract_all():
    data = b"ascii_str\x00\x00u\x00t\x00f\x001\x006\x00s\x00t\x00r\x00"
    res = list(extract_all(data, min_length=5))
    strs = [s[1] for s in res]
    assert "ascii_str" in strs
    assert "utf16str" in strs
