from ichnos.binary.identify import identify


def test_identify_png():
    data = b"\x89PNG\r\n\x1a\n\x00\x00"
    res = identify(data)
    assert res["type"].lower() == "png"


def test_identify_elf():
    data = b"\x7fELF\x02\x01"
    res = identify(data)
    assert res["type"].lower() == "elf"


def test_identify_pdf():
    data = b"%PDF-1.4\n"
    res = identify(data)
    assert res["type"].lower() == "pdf"


def test_identify_zip():
    data = b"PK\x03\x04\x00"
    res = identify(data)
    assert res["type"].lower() == "zip"


def test_identify_unknown():
    data = b"\x12\x34\x56\x78"
    res = identify(data)
    assert res["type"].lower() == "unknown"
