"""Unified wordlist management, resolution hierarchy, and streaming fetcher for Ichnos."""

from __future__ import annotations

import gzip
import os
import shutil
import sys
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ichnos.ui.state import DEFAULT_CONFIG_DIR

DEFAULT_WORDLISTS_DIR = Path(
    os.environ.get("ICHNOS_WORDLISTS_DIR", str(DEFAULT_CONFIG_DIR / "wordlists"))
)

# Standard known OS wordlist search directories
SYSTEM_SEARCH_PATHS = [
    Path("/usr/share/wordlists"),
    Path("/usr/share/seclists"),
    Path("/opt/homebrew/share/wordlists"),
    Path("/usr/local/share/wordlists"),
    Path.home() / "Developer" / "CYBERSEC" / "Dictionaries",
]


@dataclass
class WordlistMeta:
    key: str
    name: str
    filename: str
    category: str  # passwords, web, dns, users, fuzz
    size_str: str
    description: str
    urls: list[str]
    compressed: str | None = None  # None, "gz", "zip"


WORDLIST_REGISTRY: dict[str, WordlistMeta] = {
    "rockyou": WordlistMeta(
        key="rockyou",
        name="RockYou Password Corpus",
        filename="rockyou.txt",
        category="passwords",
        size_str="134 MB (~53 MB gz)",
        description="Standard 14.3M password dictionary from the 2009 RockYou breach",
        urls=[
            "https://raw.githubusercontent.com/brannondorsey/naive-hashcat/master/data/rockyou.txt",
            "https://github.com/praetorian-inc/Hobbits/raw/master/wordlists/rockyou.txt.gz",
        ],
        compressed=None,
    ),
    "top100k": WordlistMeta(
        key="top100k",
        name="Top 100k Passwords",
        filename="top100k.txt",
        category="passwords",
        size_str="~850 KB",
        description="SecLists top 100,000 most common passwords",
        urls=[
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt"
        ],
    ),
    "raft-large": WordlistMeta(
        key="raft-large",
        name="Raft Large Web Words",
        filename="raft-large-words.txt",
        category="web",
        size_str="~1.0 MB",
        description="SecLists Raft large words for web directory and file discovery",
        urls=[
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt"
        ],
    ),
    "common-web": WordlistMeta(
        key="common-web",
        name="Common Web Endpoints",
        filename="common-web.txt",
        category="web",
        size_str="~38 KB",
        description="High-frequency web endpoints, administration panels, and sensitive files",
        urls=[
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
        ],
    ),
    "dir-medium": WordlistMeta(
        key="dir-medium",
        name="Directory List 2.3 Medium",
        filename="directory-list-2.3-medium.txt",
        category="web",
        size_str="~2.5 MB",
        description="Standard Raft/SecLists medium directory discovery list",
        urls=[
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt"
        ],
    ),
    "subdomains-top100k": WordlistMeta(
        key="subdomains-top100k",
        name="Top 100k Subdomains",
        filename="subdomains-top100k.txt",
        category="dns",
        size_str="~650 KB",
        description="High-frequency DNS hostnames and subdomains for network reconnaissance",
        urls=[
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt"
        ],
    ),
    "top-usernames": WordlistMeta(
        key="top-usernames",
        name="Top Common Usernames",
        filename="top-usernames.txt",
        category="users",
        size_str="~250 KB",
        description="Common default and administrative usernames across services",
        urls=[
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt"
        ],
    ),
    "fuzz-lfi-sqli": WordlistMeta(
        key="fuzz-lfi-sqli",
        name="LFI & Traversal Fuzzing Payloads",
        filename="fuzz-lfi-sqli.txt",
        category="fuzz",
        size_str="~150 KB",
        description="SecLists path traversal, dot-dot-slash, and LFI probes",
        urls=[
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt"
        ],
    ),
}

WORDLIST_BUNDLES: dict[str, list[str]] = {
    "ctf-starter": ["top100k", "common-web", "subdomains-top100k", "fuzz-lfi-sqli"],
    "all": list(WORDLIST_REGISTRY.keys()),
}


def get_user_wordlists_dir() -> Path:
    """Returns the persistent user wordlists directory."""
    try:
        DEFAULT_WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return DEFAULT_WORDLISTS_DIR


def get_repo_wordlists_dir() -> Path | None:
    """Locates bundled repository wordlists directory if present."""
    candidates = [
        Path.cwd() / "wordlists",
        Path.cwd().resolve() / "wordlists",
        Path(__file__).resolve().parents[3] / "wordlists",
        Path(__file__).resolve().parents[2] / "wordlists",
        Path(__file__).resolve().parents[1] / "wordlists",
        Path(sys.executable).resolve().parent / "wordlists",
    ]
    if "GITHUB_WORKSPACE" in os.environ:
        candidates.insert(0, Path(os.environ["GITHUB_WORKSPACE"]) / "wordlists")

    for c in candidates:
        if c.is_dir() and any(c.glob("*.txt")):
            return c
    return None


def _is_readable(p: Path | None) -> bool:
    if not p:
        return False
    try:
        if p.is_file():
            with open(p, "rb") as f:
                f.read(1)
            return True
    except Exception:
        pass
    return False


def resolve_wordlist(
    custom_path: str | Path | None = None,
    preferred_name: str = "rockyou.txt",
) -> Path | None:
    """Resolves an optimal wordlist path using the Ichnos hierarchy.

    Hierarchy:
    1. Explicit custom_path argument
    2. ICHNOS_WORDLIST environment variable
    3. Exact match in user config directory (~/.config/ichnos/wordlists/)
    4. Exact match across standard system paths (/usr/share/wordlists/)
    5. Fallback to bundled fast-triage lists (top1000.txt)
    """
    # 1. Explicit path
    if custom_path:
        p = Path(custom_path).expanduser().resolve()
        if _is_readable(p):
            return p

    # 2. Environment variable
    if "ICHNOS_WORDLIST" in os.environ:
        p = Path(os.environ["ICHNOS_WORDLIST"]).expanduser().resolve()
        if _is_readable(p):
            return p

    # 3. User config directory
    try:
        user_dir = get_user_wordlists_dir()
        candidate = user_dir / preferred_name
        if _is_readable(candidate):
            return candidate

        # Check for any .txt file in user dir if preferred_name not found
        for f in user_dir.glob("*.txt"):
            if _is_readable(f):
                return f
    except Exception:
        pass

    # 4. Standard system search paths
    for base in SYSTEM_SEARCH_PATHS:
        try:
            if base.is_dir():
                target = base / preferred_name
                if _is_readable(target):
                    return target
                if preferred_name == "rockyou.txt" and _is_readable(base / "rockyou.txt.gz"):
                    return base / "rockyou.txt.gz"
                # Subdirectory search (e.g. /usr/share/wordlists/seclists)
                sub = base / "SecLists" / "Passwords" / preferred_name
                if _is_readable(sub):
                    return sub
        except Exception:
            continue

    # 5. Bundled repo / fast-triage list
    try:
        repo_dir = get_repo_wordlists_dir()
        if repo_dir:
            # Prefer top1000.txt for fast triage
            triage = repo_dir / "top1000.txt"
            if triage.is_file():
                return triage
            for f in repo_dir.glob("*.txt"):
                if f.is_file():
                    return f
    except Exception:
        pass

    return None


def list_wordlists() -> list[dict[str, Any]]:
    """Returns status report of all registry wordlists across local and system paths."""
    user_dir = get_user_wordlists_dir()
    repo_dir = get_repo_wordlists_dir()
    results = []

    for key, meta in WORDLIST_REGISTRY.items():
        is_installed = False
        user_file = user_dir / meta.filename
        try:
            is_installed = user_file.is_file()
        except Exception:
            pass

        # Check system
        sys_path = None
        for s in SYSTEM_SEARCH_PATHS:
            try:
                p = s / meta.filename
                if p.is_file():
                    sys_path = p
                    break
            except Exception:
                continue

        # Check repo
        repo_path = None
        if repo_dir:
            try:
                candidate = repo_dir / meta.filename
                if candidate.is_file():
                    repo_path = candidate
            except Exception:
                pass

        active_path = (
            user_file
            if is_installed
            else (sys_path if sys_path else (repo_path if repo_path else None))
        )

        results.append({
            "key": key,
            "name": meta.name,
            "filename": meta.filename,
            "category": meta.category,
            "size": meta.size_str,
            "description": meta.description,
            "installed": is_installed,
            "path": str(active_path) if active_path else None,
        })

    return results


def fetch_wordlist(key: str, dest_dir: Path | None = None) -> Path:
    """Streams and unpacks a registered wordlist into destination directory."""
    if key not in WORDLIST_REGISTRY:
        raise ValueError(f"Unknown wordlist '{key}'. Available: {list(WORDLIST_REGISTRY.keys())}")

    meta = WORDLIST_REGISTRY[key]
    target_dir = dest_dir or get_user_wordlists_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    out_file = target_dir / meta.filename

    # If already downloaded, return
    if out_file.is_file() and out_file.stat().st_size > 0:
        return out_file

    tmp_file = target_dir / f"{meta.filename}.tmp"
    last_err = None

    for url in meta.urls:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; IchnosSecurityToolkit/0.1)"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp, open(tmp_file, "wb") as f:
                shutil.copyfileobj(resp, f)

            # Decompress if needed
            if url.endswith(".gz") or meta.compressed == "gz":
                with gzip.open(tmp_file, "rb") as gz_in, open(out_file, "wb") as f_out:
                    shutil.copyfileobj(gz_in, f_out)
                tmp_file.unlink(missing_ok=True)
            elif url.endswith(".zip") or meta.compressed == "zip":
                with zipfile.ZipFile(tmp_file, "r") as zf:
                    # extract primary file
                    member = zf.namelist()[0]
                    with zf.open(member) as zf_in, open(out_file, "wb") as f_out:
                        shutil.copyfileobj(zf_in, f_out)
                tmp_file.unlink(missing_ok=True)
            else:
                tmp_file.replace(out_file)

            return out_file
        except Exception as e:
            last_err = e
            tmp_file.unlink(missing_ok=True)
            continue

    raise RuntimeError(f"Failed to fetch '{key}' from all mirrors: {last_err}")


def fetch_bundle(bundle_name: str) -> list[Path]:
    """Fetches all wordlists in a named bundle."""
    if bundle_name not in WORDLIST_BUNDLES:
        raise ValueError(f"Unknown bundle '{bundle_name}'. Available: {list(WORDLIST_BUNDLES.keys())}")

    downloaded = []
    for key in WORDLIST_BUNDLES[bundle_name]:
        path = fetch_wordlist(key)
        downloaded.append(path)
    return downloaded
