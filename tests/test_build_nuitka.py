"""Tests for the Nuitka release build script."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


def load_build_script() -> ModuleType:
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "build_nuitka.py"
    spec = importlib.util.spec_from_file_location("build_nuitka", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_onefile_build_embeds_theme_package_data(tmp_path, monkeypatch):
    """Release binaries must include .theme files without a sidecar themes directory."""
    build_nuitka = load_build_script()
    captured: dict[str, list[str]] = {}

    def fake_run_command(cmd: list[str], env: dict[str, str] | None = None) -> None:
        captured["cmd"] = cmd

    monkeypatch.setattr(build_nuitka, "run_command", fake_run_command)

    build_nuitka.build_onefile(tmp_path, clean=True)

    cmd = captured["cmd"]
    expected_data_arg = (
        f"--include-data-dir={build_nuitka.SRC_DIR / 'ichnos' / 'themes'}=ichnos/themes"
    )
    assert expected_data_arg in cmd


def test_standalone_build_embeds_theme_package_data(tmp_path, monkeypatch):
    """Standalone builds should use the same embedded theme source as onefile builds."""
    build_nuitka = load_build_script()
    captured: dict[str, list[str]] = {}

    def fake_run_command(cmd: list[str], env: dict[str, str] | None = None) -> None:
        captured["cmd"] = cmd

    monkeypatch.setattr(build_nuitka, "run_command", fake_run_command)

    build_nuitka.build_standalone(tmp_path, clean=True)

    cmd = captured["cmd"]
    expected_data_arg = (
        f"--include-data-dir={build_nuitka.SRC_DIR / 'ichnos' / 'themes'}=ichnos/themes"
    )
    assert expected_data_arg in cmd
