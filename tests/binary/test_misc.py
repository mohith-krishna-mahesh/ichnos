from ichnos.binary.misc import hamming_distance, hamming_weight, swap_endian


def test_swap_endian_32():
    data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    res = swap_endian(data, word_size=4)
    assert res == b"\x04\x03\x02\x01\x08\x07\x06\x05"


def test_swap_endian_16():
    data = b"\x01\x02\x03\x04"
    res = swap_endian(data, word_size=2)
    assert res == b"\x02\x01\x04\x03"


def test_hamming_distance():
    a = b"\xff"
    b_val = b"\x00"
    assert hamming_distance(a, b_val) == 8


def test_hamming_weight():
    assert hamming_weight(b"\xff") == 8
    assert hamming_weight(b"\x00") == 0
    assert hamming_weight(b"\x0f") == 4
