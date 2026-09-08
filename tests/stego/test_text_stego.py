from ichnos.stego.text import (
    acrostic,
    cardan_grille,
    detect_reverse,
    mirror_text,
    nth_letter,
    null_cipher_first_letter,
    reverse_text,
)


def test_null_cipher_first_letter():
    assert null_cipher_first_letter("Hello Everyone Loves Pandas") == "HELP"


def test_acrostic():
    assert acrostic("Hello\nEvery\nLine\nPrints") == "HELP"


def test_reverse_text():
    assert reverse_text("olleh") == "hello"


def test_mirror_text():
    assert mirror_text("olleh\ndlrow") == "hello\nworld"


def test_detect_reverse():
    assert detect_reverse("siht si a tset")


def test_nth_letter():
    assert nth_letter("hXelXlXo", 2) == "hXelXlXo"[::2]


def test_cardan_grille():
    text = "abcde fghij"
    pos = [0, 2, 6]
    assert cardan_grille(text, pos) == "acf"
