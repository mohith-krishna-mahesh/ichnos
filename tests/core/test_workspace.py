"""Tests for ChallengeWorkspace and file classification."""

import tempfile
import zipfile
from pathlib import Path

from ichnos.core.workspace import ChallengeWorkspace, FileCategory, classify_file


def test_classify_file_extensions():
    assert classify_file(Path("chall.py"), b"print(1)") == FileCategory.SOURCE_CODE
    assert classify_file(Path("output.txt"), b"12345") == FileCategory.OUTPUT_LOGS
    assert (
        classify_file(Path("key.pem"), b"-----BEGIN RSA PRIVATE KEY-----")
        == FileCategory.CRYPTO_KEYS
    )
    assert classify_file(Path("image.png"), b"\x89PNG\r\n\x1a\n") == FileCategory.MEDIA
    assert classify_file(Path("archive.zip"), b"PK\x03\x04\x14\x00") == FileCategory.ARCHIVES
    assert classify_file(Path("binary.elf"), b"\x7fELF\x02\x01\x01\x00") == FileCategory.BINARIES


def test_workspace_load_directory():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        (p / "chall.py").write_text("N = 12345\ne = 65537\n")
        (p / "output.txt").write_text("c = 54321\n")
        (p / "flag.txt").write_text("FLAG{test_flag}\n")

        ws = ChallengeWorkspace.load(p)
        assert len(ws.files) == 3

        sources = ws.source_files
        assert len(sources) == 1
        assert sources[0].relative_path == "chall.py"

        logs = ws.log_files
        assert len(logs) == 2

        summary = ws.summary()
        assert summary["total_files"] == 3
        assert "source_code" in summary["categories"]


def test_workspace_zip_unpacking():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        zip_path = p / "challenge.zip"

        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("chall.py", "N = 100\n")
            zf.writestr("secret.txt", "flag_content\n")

        ws = ChallengeWorkspace.load(zip_path, extract_archives=True)
        # Should contain the zip archive plus extracted files
        assert len(ws.files) >= 2
        rel_paths = [f.relative_path for f in ws.files]
        assert any("chall.py" in rp for rp in rel_paths)
        ws.cleanup()


def test_workspace_tar_unpacking():
    import tarfile

    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        tar_path = p / "challenge.tar.gz"

        inner_file = p / "chall.py"
        inner_file.write_text("N = 99999\ne = 65537\n")

        with tarfile.open(tar_path, "w:gz") as tf:
            tf.add(inner_file, arcname="chall.py")

        ws = ChallengeWorkspace.load(tar_path, extract_archives=True)
        assert len(ws.files) >= 2
        rel_paths = [f.relative_path for f in ws.files]
        assert any("chall.py" in rp for rp in rel_paths)
        assert any(f.category == FileCategory.SOURCE_CODE for f in ws.files)
        ws.cleanup()


def test_workspace_tilde_expansion(monkeypatch):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        (p / "chall.py").write_text("e = 65537\n")

        # Mock expanduser on Path to return our temp directory when ~ is used
        orig_expanduser = Path.expanduser

        def mock_expanduser(self):
            if str(self).startswith("~"):
                rel = str(self)[1:].lstrip("/\\")
                return p / rel if rel else p
            return orig_expanduser(self)

        monkeypatch.setattr(Path, "expanduser", mock_expanduser)

        ws = ChallengeWorkspace.load("~/")
        assert len(ws.files) >= 1
        assert ws.files[0].relative_path == "chall.py"
        ws.cleanup()
