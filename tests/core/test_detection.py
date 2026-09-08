from ichnos.core.detection import (
    chi_square_letters,
    detect_file_type,
    english_score,
    printable_ratio,
    shannon_entropy,
)


def test_shannon_entropy_uniform():
    # uniform random bytes usually have entropy near 8.0, let's use all bytes exactly once
    data = bytes(range(256))
    entropy = shannon_entropy(data)
    assert 7.9 < entropy <= 8.0


def test_shannon_entropy_zeros():
    data = b"\x00" * 100
    entropy = shannon_entropy(data)
    assert entropy == 0.0


def test_shannon_entropy_english():
    data = b"The quick brown fox jumps over the lazy dog"
    entropy = shannon_entropy(data)
    assert 3.5 < entropy < 5.0


def test_chi_square_letters():
    english_text = "The quick brown fox jumps over the lazy dog. This is a normal english sentence."
    random_text = "qwe rty uio pas dfg hjk lzx cvb nm"

    eng_chi = chi_square_letters(english_text)
    rand_chi = chi_square_letters(random_text)

    assert eng_chi < rand_chi


def test_printable_ratio_text():
    data = b"Hello, world!\nThis is a test."
    ratio = printable_ratio(data)
    assert ratio == 1.0


def test_printable_ratio_binary():
    # 256 bytes, 95 are printable + 3 whitespaces = 98 printable
    data = bytes(range(256))
    ratio = printable_ratio(data)
    # 98 / 256 = 0.3828
    assert 0.36 < ratio < 0.39


def test_detect_file_type_png():
    data = b"\x89PNG\r\n\x1a\n" + b"extra data"
    assert detect_file_type(data) == "png"


def test_detect_file_type_elf():
    data = b"\x7fELF" + b"\x00" * 10
    assert detect_file_type(data) == "elf"


def test_detect_file_type_text():
    data = b"Just a normal ascii string here."
    assert detect_file_type(data) == "text"


def test_english_score():
    eng_score = english_score("Hello there, this is a reasonable english sentence.")
    gib_score = english_score("ZzZz XxXx QqQq")
    assert eng_score > gib_score
