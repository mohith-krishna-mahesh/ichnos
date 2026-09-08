"""Unit tests for wordlist management, resolution, and fetching."""

import gzip
import io
from pathlib import Path
from unittest.mock import patch

import pytest

from ichnos.password.wordlists import (
    WORDLIST_BUNDLES,
    WORDLIST_REGISTRY,
    fetch_bundle,
    fetch_wordlist,
    get_repo_wordlists_dir,
    list_wordlists,
    resolve_wordlist,
)


def test_registry_contents():
    assert "rockyou" in WORDLIST_REGISTRY
    assert "top100k" in WORDLIST_REGISTRY
    assert "common-web" in WORDLIST_REGISTRY
    assert "ctf-starter" in WORDLIST_BUNDLES


def test_resolve_wordlist_explicit(tmp_path: Path):
    custom = tmp_path / "custom.txt"
    custom.write_text("password123\nadmin\n")
    resolved = resolve_wordlist(custom_path=str(custom))
    assert resolved == custom.resolve()


def test_resolve_wordlist_env(tmp_path: Path, monkeypatch):
    custom = tmp_path / "env_passwords.txt"
    custom.write_text("root\n")
    monkeypatch.setenv("ICHNOS_WORDLIST", str(custom))
    resolved = resolve_wordlist()
    assert resolved == custom.resolve()


def test_resolve_wordlist_fallback():
    # Should resolve to bundled repo wordlist (e.g. top1000.txt) if repo wordlists exist
    repo_dir = get_repo_wordlists_dir()
    resolved = resolve_wordlist()
    if repo_dir:
        assert resolved is not None
        assert resolved.exists()
        assert resolved.name.endswith(".txt")


def test_list_wordlists():
    items = list_wordlists()
    assert len(items) == len(WORDLIST_REGISTRY)
    for item in items:
        assert "key" in item
        assert "name" in item
        assert "filename" in item
        assert "category" in item
        assert "size" in item
        assert "installed" in item


def test_fetch_wordlist_unknown():
    with pytest.raises(ValueError, match="Unknown wordlist"):
        fetch_wordlist("nonexistent_wordlist_key")


def test_fetch_wordlist_plain(tmp_path: Path):
    content = b"admin\npassword\n123456\n"
    mock_resp = io.BytesIO(content)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        out = fetch_wordlist("common-web", dest_dir=tmp_path)
        assert out.is_file()
        assert out.read_bytes() == content

        # Call again: should return immediately because file exists
        out2 = fetch_wordlist("common-web", dest_dir=tmp_path)
        assert out2 == out


def test_fetch_wordlist_gzip(tmp_path: Path):
    raw_content = b"gz_pass1\ngz_pass2\n"
    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb") as gz:
        gz.write(raw_content)
    gz_data = gz_buf.getvalue()

    mock_resp = io.BytesIO(gz_data)

    # Mock rockyou with gz url
    with patch.dict(WORDLIST_REGISTRY, {"test_gz": WORDLIST_REGISTRY["rockyou"]}):
        WORDLIST_REGISTRY["test_gz"].compressed = "gz"
        with patch("urllib.request.urlopen", return_value=mock_resp):
            out = fetch_wordlist("test_gz", dest_dir=tmp_path)
            assert out.is_file()
            assert out.read_bytes() == raw_content


def test_fetch_bundle():
    with pytest.raises(ValueError, match="Unknown bundle"):
        fetch_bundle("invalid_bundle_name")

    with patch("ichnos.password.wordlists.fetch_wordlist") as mock_fetch:
        mock_fetch.return_value = Path("/tmp/dummy.txt")
        res = fetch_bundle("ctf-starter")
        assert len(res) == len(WORDLIST_BUNDLES["ctf-starter"])
        assert mock_fetch.call_count == len(WORDLIST_BUNDLES["ctf-starter"])
