#!/usr/bin/env python3
"""Reproducible Nuitka build script for Project Ichnos.

Supports:
- Standalone build: builds self-contained folder under build/standalone/ichnos.dist
- Onefile build: builds single-binary distribution artifact under dist/ichnos

Ensures package data (theme.tcss), entry points, and Pydantic plugins are bundled correctly.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
ENTRY_POINT = SRC_DIR / "ichnos" / "__main__.py"


def run_command(cmd: list[str], env: dict[str, str] | None = None) -> None:
    print(f"[*] Executing: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=str(REPO_ROOT), env=env)
    if result.returncode != 0:
        print(f"[!] Command failed with exit code {result.returncode}", file=sys.stderr)
        sys.exit(result.returncode)


def build_standalone(output_dir: Path, clean: bool = False) -> Path:
    """Compiles Ichnos into a standalone distribution directory."""
    print("\n========================================================")
    print(" BUILDING NUITKA STANDALONE EXECUTABLE")
    print("========================================================")
    if clean and output_dir.exists():
        print(f"[*] Cleaning previous output dir: {output_dir}")
        shutil.rmtree(output_dir, ignore_errors=True)

    output_dir.mkdir(parents=True, exist_ok=True)

    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC_DIR)

    cmd = [
        sys.executable,
        "-m",
        "nuitka",
        "--standalone",
        "--follow-imports",
        "--include-package=ichnos",
        "--disable-cache=ccache",
        "--assume-yes-for-downloads",
        f"--output-dir={output_dir}",
        f"--output-filename=ichnos{'.exe' if sys.platform == 'win32' else ''}",
        str(ENTRY_POINT),
    ]

    run_command(cmd, env=env)
    dist_dir = output_dir / ("__main__.dist" if (output_dir / "__main__.dist").exists() else "ichnos.dist")
    themes_src = REPO_ROOT / "themes"
    if themes_src.exists():
        themes_dest = dist_dir / "themes"
        if themes_dest.exists():
            shutil.rmtree(themes_dest)
        shutil.copytree(themes_src, themes_dest)
    binary_name = "ichnos.exe" if sys.platform == "win32" else "ichnos"
    binary_path = dist_dir / binary_name
    print(f"[+] Standalone build completed at: {binary_path}")
    return binary_path


def build_onefile(output_dir: Path, clean: bool = False) -> Path:
    """Compiles Ichnos into a single-file executable."""
    print("\n========================================================")
    print(" BUILDING NUITKA ONEFILE EXECUTABLE")
    print("========================================================")
    if clean and output_dir.exists():
        print(f"[*] Cleaning previous output dir: {output_dir}")
        shutil.rmtree(output_dir, ignore_errors=True)

    output_dir.mkdir(parents=True, exist_ok=True)

    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC_DIR)

    binary_name = "ichnos.exe" if sys.platform == "win32" else "ichnos"
    cmd = [
        sys.executable,
        "-m",
        "nuitka",
        "--onefile",
        "--follow-imports",
        "--include-package=ichnos",
        "--disable-cache=ccache",
        "--assume-yes-for-downloads",
        f"--output-dir={output_dir}",
        f"--output-filename={binary_name}",
        str(ENTRY_POINT),
    ]

    run_command(cmd, env=env)
    themes_src = REPO_ROOT / "themes"
    if themes_src.exists():
        themes_dest = output_dir / "themes"
        if themes_dest.exists():
            shutil.rmtree(themes_dest)
        shutil.copytree(themes_src, themes_dest)
    binary_path = output_dir / binary_name
    print(f"[+] Onefile build completed at: {binary_path}")
    return binary_path


def main():
    parser = argparse.ArgumentParser(description="Build Ichnos via Nuitka")
    parser.add_argument(
        "--mode",
        choices=["standalone", "onefile", "all"],
        default="standalone",
        help="Build mode: standalone directory or single executable (default: standalone)",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean previous build output directories before compiling",
    )
    args = parser.parse_args()

    if args.mode in ("standalone", "all"):
        build_standalone(REPO_ROOT / "build" / "standalone", clean=args.clean)

    if args.mode in ("onefile", "all"):
        build_onefile(REPO_ROOT / "dist", clean=args.clean)


if __name__ == "__main__":
    main()
