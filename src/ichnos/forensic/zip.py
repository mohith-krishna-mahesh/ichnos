"""ZIP forensics."""

from __future__ import annotations

import os
import tempfile
import zipfile

from ichnos.core.security import sanitize_archive_path


def inspect_zip(data: bytes) -> dict:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(data)
        tmp_name = tmp.name

    entries = []
    total_compressed = 0
    total_uncompressed = 0
    has_path_traversal = False
    traversal_entries = []

    try:
        with zipfile.ZipFile(tmp_name, "r") as zf:
            for info in zf.infolist():
                is_encrypted = bool(info.flag_bits & 0x1)
                try:
                    sanitize_archive_path(info.filename)
                except ValueError:
                    has_path_traversal = True
                    traversal_entries.append(info.filename)

                entries.append(
                    {
                        "filename": info.filename,
                        "compressed_size": info.compress_size,
                        "uncompressed_size": info.file_size,
                        "compression_method": info.compress_type,
                        "crc32": info.CRC,
                        "is_encrypted": is_encrypted,
                        "last_modified": info.date_time,
                    }
                )
                total_compressed += info.compress_size
                total_uncompressed += info.file_size
    finally:
        os.unlink(tmp_name)

    is_bomb = False
    bomb_warning = None
    if total_uncompressed > 100 * 1024 * 1024:
        ratio = total_uncompressed / max(1, total_compressed)
        if ratio > 100.0 or total_uncompressed > 1024 * 1024 * 1024:
            is_bomb = True
            bomb_warning = f"Decompression bomb detected: total uncompressed {total_uncompressed / (1024*1024):.1f}MB, ratio {ratio:.1f}:1"

    return {
        "total_entries": len(entries),
        "total_compressed": total_compressed,
        "total_uncompressed": total_uncompressed,
        "is_bomb": is_bomb,
        "bomb_warning": bomb_warning,
        "has_path_traversal": has_path_traversal,
        "traversal_entries": traversal_entries,
        "entries": entries,
    }


def extract_comments(data: bytes) -> dict:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(data)
        tmp_name = tmp.name

    archive_comment = b""
    file_comments = {}

    try:
        with zipfile.ZipFile(tmp_name, "r") as zf:
            archive_comment = (
                zf.comment.decode("utf-8", errors="replace")
                if isinstance(zf.comment, bytes)
                else str(zf.comment or "")
            )
            for info in zf.infolist():
                if info.comment:
                    file_comments[info.filename] = (
                        info.comment.decode("utf-8", errors="replace")
                        if isinstance(info.comment, bytes)
                        else str(info.comment)
                    )
    finally:
        os.unlink(tmp_name)

    return {"archive_comment": archive_comment, "file_comments": file_comments}


def is_password_protected(data: bytes) -> bool:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(data)
        tmp_name = tmp.name

    protected = False
    try:
        with zipfile.ZipFile(tmp_name, "r") as zf:
            for info in zf.infolist():
                if info.flag_bits & 0x1:
                    protected = True
                    break
    except zipfile.BadZipFile:
        pass
    finally:
        os.unlink(tmp_name)

    return protected


def crack_zip(data: bytes, wordlist_path: str | None = None) -> str | None:
    if not wordlist_path:
        from ichnos.password.wordlists import resolve_wordlist
        resolved = resolve_wordlist(preferred_name="rockyou.txt")
        if not resolved:
            return None
        wordlist_path = str(resolved)

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(data)
        tmp_name = tmp.name

    password = None
    try:
        with zipfile.ZipFile(tmp_name, "r") as zf:
            infolist = zf.infolist()
            if not infolist:
                return None
            test_file = infolist[0].filename

            with open(wordlist_path, errors="ignore") as wl:
                attempts = 0
                for line in wl:
                    attempts += 1
                    if attempts > 1000000:
                        break
                    pwd = line.strip()
                    try:
                        with zf.open(test_file, pwd=pwd.encode("utf-8")) as member_file:
                            member_file.read(4096)
                            password = pwd
                            break
                    except (RuntimeError, zipfile.BadZipFile):
                        pass
    finally:
        os.unlink(tmp_name)

    return password
