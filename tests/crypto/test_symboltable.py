import pytest

from ichnos.crypto.classical.symboltable import (
    decode,
    encode,
    get_table,
    list_tables,
)


def test_list_tables():
    tables = list_tables()
    assert len(tables) > 0
    assert "morse" in tables
    assert "a1z26" in tables
    assert "bacon" in tables


def test_morse_encode_decode_roundtrip():
    text = "HELLO"
    encoded = encode(text, "morse")
    assert encoded == ["....", ".", ".-..", ".-..", "---"]

    decoded = decode(encoded, "morse")
    assert decoded == text


def test_a1z26_encode():
    text = "AZ"
    encoded = encode(text, "a1z26")
    assert encoded == ["1", "26"]


def test_bacon_encode():
    text = "AB"
    encoded = encode(text, "bacon")
    assert encoded == ["AAAAA", "AAAAB"]


def test_nato_encode():
    text = "AB"
    encoded = encode(text, "nato_phonetic")
    assert encoded == ["Alpha", "Bravo"]


def test_unknown_table_raises():
    with pytest.raises(ValueError):
        encode("TEST", "unknown_table")

    with pytest.raises(ValueError):
        get_table("nonexistent")


ALL_TABLES = list_tables()


def test_all_expected_tables_present():
    tables = list_tables()
    assert len(tables) >= 150
    # Verify core CTF tables are present
    core = [
        "pigpen",
        "tap_code",
        "morse",
        "braille",
        "semaphore_flag",
        "nato_phonetic",
        "a1z26",
        "bacon",
        "polybius",
        "al_bhed",
        "sheikah",
        "dovahzul",
        "futurama_alien_1",
        "theban",
        "enochian",
    ]
    for name in core:
        assert name in tables, f"Missing core table {name}"


@pytest.mark.parametrize("table_name", ALL_TABLES)
def test_symboltable_roundtrip(table_name):
    table = get_table(table_name)
    rev = {v: k for k, v in table.items()}
    injective_chars = [k for k, v in table.items() if rev.get(v) == k]
    assert len(injective_chars) >= 2, f"Table {table_name} has insufficient injective mappings"
    test_chars = "".join(injective_chars[:2])
    encoded = encode(test_chars, table_name)
    decoded = decode(encoded, table_name)
    assert decoded == test_chars
