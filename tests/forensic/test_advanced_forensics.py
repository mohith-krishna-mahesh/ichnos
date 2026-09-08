"""Tests for advanced forensics modules.

Covers:
- Git repository forensics (loose objects, trees, deleted file recovery)
- Docker/OCI container image layer whiteout (.wh.*) forensics
- SQLite deleted cell, freeblock, and unallocated page carver
"""

import io
import tarfile
import zlib

from ichnos.forensic.container import inspect_container_image
from ichnos.forensic.git import (
    parse_git_object,
    parse_tree_object,
    scan_git_repository,
)
from ichnos.forensic.sqlite import carve_sqlite_deleted_records, is_sqlite3


def test_git_object_parsing():
    # Test loose object decompression and header parsing
    raw_blob = b"Hello, Git Forensics!"
    header = f"blob {len(raw_blob)}\x00".encode("ascii")
    compressed = zlib.compress(header + raw_blob)

    obj_type, payload = parse_git_object(compressed)
    assert obj_type == "blob"
    assert payload == raw_blob


def test_git_tree_parsing():
    # Tree entry: mode space name null 20-byte sha
    fake_sha = bytes(range(20))
    entry1 = b"100644 flag.txt\x00" + fake_sha
    entries = parse_tree_object(entry1)
    assert len(entries) == 1
    assert entries[0]["name"] == "flag.txt"
    assert entries[0]["mode"] == "100644"
    assert entries[0]["sha"] == fake_sha.hex()


def test_git_scan_repo(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    objects_dir = git_dir / "objects"
    objects_dir.mkdir()

    # Create a loose blob
    blob_data = b"FLAG{git_dangling_commit_found}"
    header = f"blob {len(blob_data)}\x00".encode("ascii")
    comp = zlib.compress(header + blob_data)
    import hashlib

    sha = hashlib.sha1(header + blob_data).hexdigest()
    obj_sub = objects_dir / sha[:2]
    obj_sub.mkdir()
    (obj_sub / sha[2:]).write_bytes(comp)

    res = scan_git_repository(git_dir)
    assert res["blobs_count"] >= 1
    assert any("FLAG{git_dangling_commit_found}" in s["preview"] for s in res["recovered_secrets"])


def test_docker_container_layer_whiteout():
    # Construct an in-memory Docker image tar with 2 layers:
    # Layer 0: contains flag.txt
    # Layer 1: contains .wh.flag.txt (deleting flag.txt in whiteout)

    def _create_tar(files: dict[str, bytes]) -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            for name, data in files.items():
                ti = tarfile.TarInfo(name=name)
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
        return buf.getvalue()

    layer0_tar = _create_tar({"flag.txt": b"FLAG{docker_layer_leak}"})
    layer1_tar = _create_tar({".wh.flag.txt": b""})

    manifest = [{"Layers": ["layer0.tar", "layer1.tar"]}]
    import json

    outer_tar = _create_tar({
        "manifest.json": json.dumps(manifest).encode("utf-8"),
        "layer0.tar": layer0_tar,
        "layer1.tar": layer1_tar,
    })

    res = inspect_container_image(outer_tar)
    assert res["layers_count"] == 2
    assert len(res["deleted_files"]) == 1
    assert res["deleted_files"][0]["path"] == "flag.txt"
    assert "FLAG{docker_layer_leak}" in res["deleted_files"][0]["preview"]


def test_sqlite_carving():
    assert is_sqlite3(b"NOT_SQLITE") is False

    # Synthetic SQLite page 1:
    # 100 bytes DB header + leaf table b-tree page header (8 bytes)
    header = bytearray(b"SQLite format 3\x00" + b"\x00" * 84)
    # Page size at offset 16..18: 4096 (0x1000)
    header[16:18] = b"\x10\x00"

    page = bytearray(4096)
    page[:100] = header

    # Offset 100: page_type = 0x0D (leaf table)
    page[100] = 0x0D
    # first_freeblock = 0
    page[101:103] = b"\x00\x00"
    # cell_count = 0
    page[103:105] = b"\x00\x00"
    # content_start = 4000 (0x0FA0)
    page[105:107] = b"\x0f\xa0"

    # Embed deleted record in the unallocated gap (offset 108..4000)
    hidden_text = b"FLAG{sqlite_deleted_record_carved}"
    page[200 : 200 + len(hidden_text)] = hidden_text

    assert is_sqlite3(bytes(page)) is True
    res = carve_sqlite_deleted_records(bytes(page))
    assert res["leaf_pages_count"] == 1
    assert any("FLAG{sqlite_deleted_record_carved}" in s for s in res["carved_strings"])
