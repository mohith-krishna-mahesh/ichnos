from ichnos.stego.image.lsb import brute_force_lsb, extract_lsb, extract_raw_pixels


def test_extract_raw_pixels(tiny_png_with_lsb):
    pixels, w, h, c = extract_raw_pixels(tiny_png_with_lsb)
    assert w == 8
    assert h == 8
    assert c == 3
    assert len(pixels) == 8 * 8 * 3


def test_extract_lsb(tiny_png_with_lsb):
    pixels, w, h, c = extract_raw_pixels(tiny_png_with_lsb)
    extracted = extract_lsb(pixels, w, h, c, channel_order="RGB", bit_order="msb", num_bits=1)
    assert b"FLAG{lsb_works}" in extracted


def test_brute_force_lsb(tiny_png_with_lsb):
    candidates = brute_force_lsb(tiny_png_with_lsb)
    assert len(candidates) > 0
    assert any(
        b"FLAG{lsb_works}" in (c.decoded if isinstance(c.decoded, bytes) else c.decoded.encode())
        for c in candidates
    )
