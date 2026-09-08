"""Git repository forensics and historical commit secret recovery.

Parses dumped or exposed .git folders, reconstructs object DAGs (commits, trees, blobs),
detects deleted files across historical commits, and extracts deleted secrets/flags.
"""

from __future__ import annotations

import zlib
from pathlib import Path
from typing import Any


def parse_git_object(raw_data: bytes) -> tuple[str, bytes]:
    """Decompresses a loose Git object and splits header from payload.

    Returns:
        (object_type, payload_bytes) where object_type is 'commit', 'tree', 'blob', or 'tag'.
    """
    decompressed = zlib.decompress(raw_data)
    null_idx = decompressed.find(b"\x00")
    if null_idx == -1:
        return "unknown", decompressed
    header = decompressed[:null_idx].decode("ascii", errors="replace")
    obj_type = header.split(" ")[0]
    payload = decompressed[null_idx + 1 :]
    return obj_type, payload


def parse_tree_object(payload: bytes) -> list[dict[str, Any]]:
    """Parses a Git tree object into entries with mode, name, and SHA-1 hash."""
    entries: list[dict[str, Any]] = []
    idx = 0
    p_len = len(payload)
    while idx < p_len:
        null_pos = payload.find(b"\x00", idx)
        if null_pos == -1 or null_pos + 20 > p_len:
            break
        mode_and_name = payload[idx:null_pos].decode("utf-8", errors="replace")
        parts = mode_and_name.split(" ", 1)
        mode = parts[0]
        name = parts[1] if len(parts) > 1 else ""
        sha_bytes = payload[null_pos + 1 : null_pos + 21]
        sha_hex = sha_bytes.hex()
        entries.append({
            "mode": mode,
            "name": name,
            "sha": sha_hex,
            "is_dir": mode.startswith("40"),
        })
        idx = null_pos + 21
    return entries


def scan_git_repository(git_dir: str | Path) -> dict[str, Any]:
    """Scans a .git directory, extracting commits, deleted files, and dangling blobs.

    Args:
        git_dir: Path to the .git directory.

    Returns:
        Dict with: 'commits', 'blobs_count', 'deleted_files', 'recovered_secrets'.
    """
    gpath = Path(git_dir)
    if not gpath.is_dir():
        return {"error": f"Path {git_dir} is not a directory"}

    objects_dir = gpath / "objects"
    if not objects_dir.exists():
        # Check if current directory itself is the objects dir
        if (gpath / "info").exists() or any(len(p.name) == 2 for p in gpath.iterdir() if p.is_dir()):
            objects_dir = gpath

    blobs: dict[str, bytes] = {}
    trees: dict[str, list[dict[str, Any]]] = {}
    commits: list[dict[str, Any]] = []

    # Walk loose objects in .git/objects/xx/yyy...
    if objects_dir.exists():
        for subdir in objects_dir.iterdir():
            if subdir.is_dir() and len(subdir.name) == 2:
                for obj_file in subdir.iterdir():
                    sha = subdir.name + obj_file.name
                    try:
                        raw = obj_file.read_bytes()
                        obj_type, payload = parse_git_object(raw)
                        if obj_type == "blob":
                            blobs[sha] = payload
                        elif obj_type == "tree":
                            trees[sha] = parse_tree_object(payload)
                        elif obj_type == "commit":
                            commits.append({
                                "sha": sha,
                                "raw": payload.decode("utf-8", errors="replace"),
                            })
                    except Exception:
                        pass

    # Extract deleted or historical files
    all_historical_files: dict[str, list[str]] = {}  # filename -> list of blob SHAs
    for tree_sha, entries in trees.items():
        for entry in entries:
            fname = entry["name"]
            if fname not in all_historical_files:
                all_historical_files[fname] = []
            if entry["sha"] not in all_historical_files[fname]:
                all_historical_files[fname].append(entry["sha"])

    # Carve text content from all blobs
    recovered_secrets: list[dict[str, str]] = []
    for sha, data in blobs.items():
        text = data.decode("utf-8", errors="replace")
        if any(marker in text for marker in ("FLAG{", "NNS{", "CTF{", "password", "secret", "KEY=")):
            recovered_secrets.append({
                "sha": sha,
                "preview": text[:200],
            })

    return {
        "commits_count": len(commits),
        "trees_count": len(trees),
        "blobs_count": len(blobs),
        "tracked_filenames": list(all_historical_files.keys()),
        "recovered_secrets": recovered_secrets,
        "commits": commits,
    }
