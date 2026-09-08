from ichnos.core.input import read_input
from ichnos.core.models import SourceType


def test_read_input_file(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"File content")

    inp = read_input(str(test_file))

    assert inp.source_type == SourceType.FILE
    assert inp.data == b"File content"
    assert inp.path == test_file
    assert inp.filename == "test.txt"
    assert inp.detected_type == "text"


def test_read_input_raw():
    inp = read_input("Just a raw string")

    assert inp.source_type == SourceType.RAW
    assert inp.data == b"Just a raw string"
    assert inp.text == "Just a raw string"


def test_read_input_type_detection(tmp_path):
    # Test PNG
    png_file = tmp_path / "test.png"
    png_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"mock data")

    inp = read_input(str(png_file))
    assert inp.detected_type == "png"

    # Test ELF
    elf_file = tmp_path / "test.elf"
    elf_file.write_bytes(b"\x7fELF" + b"\x00" * 20)

    inp2 = read_input(str(elf_file))
    assert inp2.detected_type == "elf"


def test_read_input_directory(tmp_path):
    dir_path = tmp_path / "Downloads"
    dir_path.mkdir()
    (dir_path / "sample.txt").write_text("hello")

    inp = read_input(str(dir_path))
    assert inp.source_type == SourceType.DIRECTORY
    assert inp.detected_type == "directory"
    assert inp.path == dir_path
