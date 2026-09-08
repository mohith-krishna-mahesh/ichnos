import zipfile

import pytest

from ichnos.forensic.zip import extract_comments, inspect_zip, is_password_protected


@pytest.fixture
def test_zip(tmp_path):
    zpath = tmp_path / "test.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.comment = b"Archive comment here"
        zf.writestr("flag.txt", "FLAG{found_it}")
        zf.writestr("readme.md", "This is a test")
    return zpath.read_bytes()


def test_inspect_zip(test_zip):
    info = inspect_zip(test_zip)
    assert info["total_entries"] == 2
    filenames = [i["filename"] for i in info["entries"]]
    assert "flag.txt" in filenames
    assert "readme.md" in filenames


def test_extract_comments(test_zip):
    comments = extract_comments(test_zip)
    assert comments["archive_comment"] == "Archive comment here"


def test_is_password_protected_false(test_zip):
    assert is_password_protected(test_zip) is False
