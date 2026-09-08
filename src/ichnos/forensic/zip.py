"""ZIP forensics."""

from __future__ import annotations

import os
import tempfile
import zipfile


def inspect_zip(data: bytes) -> dict:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(data)
        tmp_name = tmp.name

    entries = []
    total_compressed = 0
    total_uncompressed = 0

    try:
        with zipfile.ZipFile(tmp_name, "r") as zf:
            for info in zf.infolist():
                is_encrypted = bool(info.flag_bits & 0x1)
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

    return {
        "total_entries": len(entries),
        "total_compressed": total_compressed,
        "total_uncompressed": total_uncompressed,
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


def crack_zip(data: bytes, wordlist_path: str) -> str | None:
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
                        zf.read(test_file, pwd=pwd.encode("utf-8"))
                        password = pwd
                        break
                    except (RuntimeError, zipfile.BadZipFile):
                        pass
    finally:
        os.unlink(tmp_name)

    return password
