from ichnos.encoding.text import html_decode, html_encode, unicode_decode, url_decode, url_encode


def test_url_encode_decode_roundtrip():
    data = "hello world"
    enc = url_encode(data)
    assert enc == "hello%20world"
    assert url_decode(enc) == data


def test_url_double_encode_decode():
    data = "hello world"
    enc1 = url_encode(data)
    enc2 = url_encode(enc1)
    assert url_decode(url_decode(enc2)) == data


def test_html_encode_decode():
    data = "<script>"
    enc = html_encode(data)
    assert "&lt;" in enc or "&#60;" in enc
    assert html_decode(enc) == data


def test_unicode_encode_decode_python_style():
    data = "Hello"
    enc = "\\u0048\\u0065\\u006c\\u006c\\u006f"
    assert unicode_decode(enc) == data


def test_unicode_encode_decode_html_dec():
    data = "Hello"
    enc = "&#72;&#101;&#108;&#108;&#111;"
    assert unicode_decode(enc) == data
