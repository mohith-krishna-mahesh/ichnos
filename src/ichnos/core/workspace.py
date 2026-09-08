"""Challenge workspace ingestion and classification for multi-file CTF analysis."""

from __future__ import annotations

import atexit
import shutil
import tarfile
import tempfile
import zipfile
from enum import Enum
from pathlib import Path
from typing import Any

from ichnos.core.detection import detect_file_type


class FileCategory(str, Enum):
    """Classification category for files found in a CTF challenge workspace."""

    SOURCE_CODE = "source_code"
    OUTPUT_LOGS = "output_logs"
    CRYPTO_KEYS = "crypto_keys"
    BINARIES = "binaries"
    CAPTURES = "captures"
    MEDIA = "media"
    ARCHIVES = "archives"
    DATA = "data"
    UNKNOWN = "unknown"


# Mapping extensions to preliminary categories
_EXT_MAP: dict[str, FileCategory] = {
    # Source code
    ".py": FileCategory.SOURCE_CODE,
    ".sage": FileCategory.SOURCE_CODE,
    ".c": FileCategory.SOURCE_CODE,
    ".cpp": FileCategory.SOURCE_CODE,
    ".cc": FileCategory.SOURCE_CODE,
    ".cxx": FileCategory.SOURCE_CODE,
    ".h": FileCategory.SOURCE_CODE,
    ".hpp": FileCategory.SOURCE_CODE,
    ".js": FileCategory.SOURCE_CODE,
    ".mjs": FileCategory.SOURCE_CODE,
    ".cjs": FileCategory.SOURCE_CODE,
    ".jsx": FileCategory.SOURCE_CODE,
    ".ts": FileCategory.SOURCE_CODE,
    ".tsx": FileCategory.SOURCE_CODE,
    ".lua": FileCategory.SOURCE_CODE,
    ".php": FileCategory.SOURCE_CODE,
    ".phtml": FileCategory.SOURCE_CODE,
    ".java": FileCategory.SOURCE_CODE,
    ".kt": FileCategory.SOURCE_CODE,
    ".kts": FileCategory.SOURCE_CODE,
    ".go": FileCategory.SOURCE_CODE,
    ".rs": FileCategory.SOURCE_CODE,
    ".rb": FileCategory.SOURCE_CODE,
    ".pl": FileCategory.SOURCE_CODE,
    ".pm": FileCategory.SOURCE_CODE,
    ".sh": FileCategory.SOURCE_CODE,
    ".bash": FileCategory.SOURCE_CODE,
    ".zsh": FileCategory.SOURCE_CODE,
    ".asm": FileCategory.SOURCE_CODE,
    ".s": FileCategory.SOURCE_CODE,
    ".sol": FileCategory.SOURCE_CODE,
    ".vy": FileCategory.SOURCE_CODE,
    ".zig": FileCategory.SOURCE_CODE,
    ".nim": FileCategory.SOURCE_CODE,
    ".swift": FileCategory.SOURCE_CODE,
    ".cs": FileCategory.SOURCE_CODE,
    ".d": FileCategory.SOURCE_CODE,
    # Logs and output
    ".txt": FileCategory.OUTPUT_LOGS,
    ".log": FileCategory.OUTPUT_LOGS,
    ".out": FileCategory.OUTPUT_LOGS,
    ".ans": FileCategory.OUTPUT_LOGS,
    ".hex": FileCategory.OUTPUT_LOGS,
    ".enc": FileCategory.OUTPUT_LOGS,
    # Data formats
    ".json": FileCategory.DATA,
    ".yaml": FileCategory.DATA,
    ".yml": FileCategory.DATA,
    ".toml": FileCategory.DATA,
    ".xml": FileCategory.DATA,
    ".csv": FileCategory.DATA,
    ".tsv": FileCategory.DATA,
    # Keys
    ".pem": FileCategory.CRYPTO_KEYS,
    ".pub": FileCategory.CRYPTO_KEYS,
    ".key": FileCategory.CRYPTO_KEYS,
    ".der": FileCategory.CRYPTO_KEYS,
    ".crt": FileCategory.CRYPTO_KEYS,
    ".csr": FileCategory.CRYPTO_KEYS,
    ".pfx": FileCategory.CRYPTO_KEYS,
    ".p12": FileCategory.CRYPTO_KEYS,
    ".asc": FileCategory.CRYPTO_KEYS,
    # Captures
    ".pcap": FileCategory.CAPTURES,
    ".pcapng": FileCategory.CAPTURES,
    ".cap": FileCategory.CAPTURES,
    # Media
    ".png": FileCategory.MEDIA,
    ".jpg": FileCategory.MEDIA,
    ".jpeg": FileCategory.MEDIA,
    ".gif": FileCategory.MEDIA,
    ".bmp": FileCategory.MEDIA,
    ".webp": FileCategory.MEDIA,
    ".wav": FileCategory.MEDIA,
    ".mp3": FileCategory.MEDIA,
    ".flac": FileCategory.MEDIA,
    ".ogg": FileCategory.MEDIA,
    # Archives
    ".zip": FileCategory.ARCHIVES,
    ".tar": FileCategory.ARCHIVES,
    ".gz": FileCategory.ARCHIVES,
    ".tgz": FileCategory.ARCHIVES,
    ".bz2": FileCategory.ARCHIVES,
    ".xz": FileCategory.ARCHIVES,
    ".7z": FileCategory.ARCHIVES,
    ".rar": FileCategory.ARCHIVES,
    # Executable binaries
    ".elf": FileCategory.BINARIES,
    ".exe": FileCategory.BINARIES,
    ".dll": FileCategory.BINARIES,
    ".so": FileCategory.BINARIES,
    ".dylib": FileCategory.BINARIES,
}


def classify_file(path: Path, data: bytes) -> FileCategory:
    """Classify a file based on its extension, filename, and magic bytes."""
    ext = path.suffix.lower()
    name = path.name.lower()

    # Special filenames
    if name in ("output.txt", "flag.enc", "out.txt", "secret.enc", "ciphertext.txt"):
        return FileCategory.OUTPUT_LOGS
    if name in ("chall.py", "server.py", "solve.py", "main.py", "script.py"):
        return FileCategory.SOURCE_CODE

    # Magic / header checks
    if len(data) >= 4:
        if data[:4] == b"\x7fELF":
            return FileCategory.BINARIES
        if data[:2] == b"MZ":
            return FileCategory.BINARIES
        if data[:4] in (
            b"\xfe\xed\xfa\xce",
            b"\xfe\xed\xfa\xcf",
            b"\xce\xfa\xed\xfe",
            b"\xcf\xfa\xed\xfe",
        ):
            return FileCategory.BINARIES
        if data[:4] == b"\xd4\xc3\xb2\xa1" or data[:4] == b"\x0a\x0d\x0d\x0a":
            return FileCategory.CAPTURES
        if data[:4] == b"\x89PNG" or data[:2] == b"\xff\xd8" or data[:4] == b"RIFF":
            return FileCategory.MEDIA
        if (
            data[:4] == b"PK\x03\x04"
            or data[:2] == b"\x1f\x8b"
            or data[:6] == b"7z\xbc\xaf\x27\x1c"
        ):
            return FileCategory.ARCHIVES

    # Text content check for PEM keys
    if (
        data.startswith(b"-----BEGIN ")
        or b" PRIVATE KEY-----" in data
        or b" PUBLIC KEY-----" in data
    ):
        return FileCategory.CRYPTO_KEYS

    # Extension mapping
    if ext in _EXT_MAP:
        return _EXT_MAP[ext]

    # Fall back to detect_file_type
    detected = detect_file_type(data)
    if "image" in detected or "audio" in detected:
        return FileCategory.MEDIA
    if "zip" in detected or "archive" in detected or "gzip" in detected or "tar" in detected:
        return FileCategory.ARCHIVES
    if "elf" in detected or "pe" in detected:
        return FileCategory.BINARIES
    if "text" in detected:
        return FileCategory.OUTPUT_LOGS

    return FileCategory.DATA


class WorkspaceFile:
    """Representation of an ingested file in the challenge workspace."""

    def __init__(
        self,
        path: Path,
        relative_path: str,
        data: bytes | None = None,
        category: FileCategory | None = None,
    ):
        self.path = path
        self.relative_path = relative_path
        self._data = data
        self._category = category

    @property
    def data(self) -> bytes:
        if self._data is None:
            try:
                self._data = self.path.read_bytes()
            except Exception:
                self._data = b""
        return self._data

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def text(self) -> str:
        return self.data.decode("utf-8", errors="replace")

    @property
    def category(self) -> FileCategory:
        if self._category is None:
            self._category = classify_file(self.path, self.data)
        return self._category

    def __repr__(self) -> str:
        return f"<WorkspaceFile {self.relative_path} ({self.category.value}, {self.size} B)>"


class ChallengeWorkspace:
    """Aggregates all files associated with a CTF challenge into an analyzed workspace."""

    def __init__(
        self, files: list[WorkspaceFile] | None = None, temp_dirs: list[Path] | None = None
    ):
        self.files: list[WorkspaceFile] = files or []
        self._temp_dirs: list[Path] = temp_dirs or []
        atexit.register(self.cleanup)

    def cleanup(self) -> None:
        """Clean up any temporary directories created during archive extraction."""
        for td in self._temp_dirs:
            if td.exists():
                shutil.rmtree(td, ignore_errors=True)
        self._temp_dirs.clear()

    @classmethod
    def load(
        cls,
        targets: list[str | Path] | str | Path,
        extract_archives: bool = True,
        max_extract_depth: int = 2,
    ) -> ChallengeWorkspace:
        """Ingest single or multiple paths (files or directories), extracting archives recursively."""
        if isinstance(targets, (str, Path)):
            targets = [targets]

        workspace = cls()
        for target in targets:
            try:
                p = Path(target).expanduser().resolve()
            except Exception:
                p = Path(target).resolve()
            if not p.exists():
                continue
            if p.is_file():
                workspace._add_file(p, p.name)
            elif p.is_dir():
                workspace._scan_dir(p, base_dir=p)

        if extract_archives:
            workspace._unpack_archives(depth=max_extract_depth)

        return workspace

    def _add_file(self, path: Path, rel_path: str) -> None:
        # Ignore common non-challenge files
        ignored_names = {".ds_store", "thumbs.db", ".gitignore"}
        if path.name.lower() in ignored_names:
            return
        if "__pycache__" in path.parts or ".git" in path.parts or ".venv" in path.parts:
            return

        wf = WorkspaceFile(path=path, relative_path=rel_path)
        self.files.append(wf)

    def _scan_dir(self, dir_path: Path, base_dir: Path) -> None:
        try:
            items = sorted(dir_path.iterdir())
        except OSError:
            return

        for item in items:
            try:
                if item.is_file():
                    try:
                        rel = str(item.relative_to(base_dir))
                    except ValueError:
                        rel = item.name
                    self._add_file(item, rel)
                elif item.is_dir():
                    if item.name in (".git", "__pycache__", ".venv", "node_modules"):
                        continue
                    self._scan_dir(item, base_dir=base_dir)
            except OSError:
                continue

    def _unpack_archives(self, depth: int, _extracted: set[Path] | None = None) -> None:
        if depth <= 0:
            return

        if _extracted is None:
            _extracted = set()

        archives_to_extract = [
            f
            for f in list(self.files)
            if f.category == FileCategory.ARCHIVES and f.path not in _extracted
        ]
        if not archives_to_extract:
            return

        new_files: list[Path] = []
        for arc in archives_to_extract:
            _extracted.add(arc.path)
            is_zip = arc.path.suffix.lower() == ".zip" or arc.data.startswith(b"PK\x03\x04")
            is_tar = (
                arc.path.suffix.lower() in (".tar", ".tgz", ".bz2", ".xz")
                or ".tar." in arc.path.name.lower()
                or arc.path.name.lower().endswith((".tar.gz", ".tar.bz2", ".tar.xz"))
                or (len(arc.data) >= 262 and arc.data[257:262] == b"ustar")
                or arc.data.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00"))
            )

            if is_zip:
                try:
                    td = Path(tempfile.mkdtemp(prefix="ichnos_chall_"))
                    self._temp_dirs.append(td)
                    with zipfile.ZipFile(arc.path, "r") as zf:
                        zf.extractall(td)
                    # Add unpacked files
                    for item in sorted(td.rglob("*")):
                        if item.is_file():
                            rel = f"{arc.relative_path}/{item.relative_to(td)}"
                            self._add_file(item, rel)
                            new_files.append(item)
                except Exception:
                    pass
            elif is_tar or tarfile.is_tarfile(arc.path):
                try:
                    td = Path(tempfile.mkdtemp(prefix="ichnos_chall_"))
                    self._temp_dirs.append(td)
                    with tarfile.open(arc.path, "r:*") as tf:
                        if hasattr(tarfile, "data_filter"):
                            tf.extractall(td, filter="data")
                        else:
                            for member in tf.getmembers():
                                member_path = (td / member.name).resolve()
                                if (
                                    td.resolve() in member_path.parents
                                    or member_path == td.resolve()
                                ):
                                    tf.extract(member, td)
                    for item in sorted(td.rglob("*")):
                        if item.is_file():
                            rel = f"{arc.relative_path}/{item.relative_to(td)}"
                            self._add_file(item, rel)
                            new_files.append(item)
                except Exception:
                    pass

        if new_files and depth > 1:
            self._unpack_archives(depth=depth - 1, _extracted=_extracted)

    # Category accessors
    def get_by_category(self, category: FileCategory) -> list[WorkspaceFile]:
        return [f for f in self.files if f.category == category]

    @property
    def source_files(self) -> list[WorkspaceFile]:
        return self.get_by_category(FileCategory.SOURCE_CODE)

    @property
    def log_files(self) -> list[WorkspaceFile]:
        return self.get_by_category(FileCategory.OUTPUT_LOGS)

    @property
    def key_files(self) -> list[WorkspaceFile]:
        return self.get_by_category(FileCategory.CRYPTO_KEYS)

    @property
    def binary_files(self) -> list[WorkspaceFile]:
        return self.get_by_category(FileCategory.BINARIES)

    @property
    def capture_files(self) -> list[WorkspaceFile]:
        return self.get_by_category(FileCategory.CAPTURES)

    @property
    def media_files(self) -> list[WorkspaceFile]:
        return self.get_by_category(FileCategory.MEDIA)

    @property
    def archive_files(self) -> list[WorkspaceFile]:
        return self.get_by_category(FileCategory.ARCHIVES)

    def summary(self) -> dict[str, Any]:
        """Summary breakdown of files in the workspace."""
        cats: dict[str, int] = {}
        for f in self.files:
            c = f.category.value
            cats[c] = cats.get(c, 0) + 1
        return {
            "total_files": len(self.files),
            "categories": cats,
            "file_list": [f.relative_path for f in self.files],
        }
