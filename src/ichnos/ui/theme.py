"""Theme management and configuration for Ichnos TUI.

All themes are loaded exclusively from external .theme JSON files located in the
user's configuration directory (~/.config/ichnos/themes/ or %APPDATA%/ichnos/themes/).
This module contains zero hardcoded theme palettes or Python Theme definitions.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from textual.theme import Theme

from ichnos.ui.state import DEFAULT_CONFIG_DIR

if TYPE_CHECKING:
    from textual.app import App

DEFAULT_CONFIG_FILE = Path(
    os.environ.get("ICHNOS_CONFIG_FILE", str(DEFAULT_CONFIG_DIR / "config.json"))
)


def get_user_themes_dir() -> Path:
    """Returns directory containing user-provided custom .theme files."""
    if "ICHNOS_THEMES_DIR" in os.environ:
        return Path(os.environ["ICHNOS_THEMES_DIR"])
    return DEFAULT_CONFIG_DIR / "themes"


def get_default_themes_dir() -> Path | None:
    """Finds the directory containing shipped canonical .theme files."""
    candidates = [
        # 1. Bundled inside the package: ichnos/themes
        Path(__file__).resolve().parent.parent / "themes",
        # 2. Next to executable (for standalone / onefile binary distributions)
        Path(sys.executable).resolve().parent / "themes",
        # 3. Source repository root themes/ directory
        Path(__file__).resolve().parents[3] / "themes",
    ]
    for candidate in candidates:
        if candidate.is_dir() and any(candidate.glob("*.theme")):
            return candidate
    return None


def load_theme_file(path: Path) -> Theme | None:
    """Parses a standalone .theme (or .json) file into a Textual Theme object.

    Expected JSON schema:
    {
      "name": "theme-name",
      "primary": "#hex",
      "background": "#hex",
      "secondary": "#hex",  # optional
      "accent": "#hex",     # optional
      "foreground": "#hex", # optional
      "surface": "#hex",    # optional
      "panel": "#hex",      # optional
      "warning": "#hex",    # optional
      "error": "#hex",      # optional
      "success": "#hex",    # optional
      "dark": true,         # optional
      "variables": { ... }  # optional CSS variables
    }

    Returns:
        Theme instance if valid, or None if unreadable, malformed, or missing required keys.
    """
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        name = data.get("name") or path.stem
        primary = data.get("primary")
        background = data.get("background")
        if not primary or not background:
            return None

        return Theme(
            name=name,
            primary=primary,
            secondary=data.get("secondary", primary),
            accent=data.get("accent", primary),
            foreground=data.get("foreground", "#BBBBBB"),
            background=background,
            surface=data.get("surface", background),
            panel=data.get("panel", background),
            warning=data.get("warning", "#c29b38"),
            error=data.get("error", "#c96565"),
            success=data.get("success", "#8ea4a2"),
            dark=data.get("dark", True),
            variables=data.get("variables", {}),
        )
    except Exception:
        return None


def seed_user_themes_dir() -> None:
    """Ensures user themes directory exists and contains default .theme files.

    Copies shipped canonical .theme files from the package or binary directory
    to the user config directory (~/.config/ichnos/themes/). Existing files
    are never overwritten, preserving all user modifications.
    """
    themes_dir = get_user_themes_dir()
    try:
        themes_dir.mkdir(parents=True, exist_ok=True)
        src_dir = get_default_themes_dir()
        if src_dir is not None:
            for src_file in src_dir.glob("*.theme"):
                dest_file = themes_dir / src_file.name
                if not dest_file.exists():
                    shutil.copy2(src_file, dest_file)
    except Exception:
        pass


def discover_user_themes() -> dict[str, Theme]:
    """Discovers all .theme and .json files in the user themes directory.

    Seeds the themes directory with default files if empty, then parses
    every .theme file found on disk.
    """
    seed_user_themes_dir()
    themes_dir = get_user_themes_dir()
    discovered: dict[str, Theme] = {}
    if not themes_dir.exists():
        return discovered

    try:
        for p in sorted(themes_dir.iterdir()):
            if p.is_file() and p.suffix.lower() in (".theme", ".json"):
                theme = load_theme_file(p)
                if theme:
                    discovered[theme.name] = theme
    except OSError:
        pass

    # If user themes dir had no readable themes, attempt fallback to default themes dir
    if not discovered:
        src_dir = get_default_themes_dir()
        if src_dir and src_dir != themes_dir:
            try:
                for p in sorted(src_dir.iterdir()):
                    if p.is_file() and p.suffix.lower() in (".theme", ".json"):
                        theme = load_theme_file(p)
                        if theme:
                            discovered[theme.name] = theme
            except OSError:
                pass

    return discovered


def load_config() -> dict[str, Any]:
    """Loads user configuration dictionary from DEFAULT_CONFIG_FILE."""
    if not DEFAULT_CONFIG_FILE.exists():
        return {"theme": "hacker"}

    try:
        data = json.loads(DEFAULT_CONFIG_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {"theme": "hacker"}


def save_config(cfg: dict[str, Any]) -> None:
    """Saves user configuration dictionary to DEFAULT_CONFIG_FILE."""
    try:
        DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        DEFAULT_CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except Exception:
        pass


def get_available_themes() -> list[str]:
    """Returns list of all available theme names discovered from .theme files."""
    user_themes = list(discover_user_themes().keys())
    cfg = load_config()
    config_customs = list(cfg.get("custom_themes", {}).keys())

    seen: set[str] = set()
    result: list[str] = []
    for name in user_themes + config_customs:
        if name not in seen:
            seen.add(name)
            result.append(name)
    return result


def get_active_theme_name() -> str:
    """Returns the name of the currently configured theme, defaulting to 'hacker' or first available."""
    cfg = load_config()
    theme_name = cfg.get("theme", "hacker")
    avail = get_available_themes()
    if theme_name in avail:
        return theme_name
    if "hacker" in avail:
        return "hacker"
    return avail[0] if avail else "hacker"


def set_active_theme_name(theme_name: str) -> None:
    """Persists chosen theme name to the configuration file."""
    cfg = load_config()
    cfg["theme"] = theme_name
    save_config(cfg)


def register_ichnos_themes(app: App) -> None:
    """Registers all discovered .theme files and config-defined themes into the Textual application."""
    # 1. Register all themes loaded from the user config directory
    all_themes = discover_user_themes()
    for theme in all_themes.values():
        app.register_theme(theme)

    # 2. Register any custom themes defined in config.json
    cfg = load_config()
    custom = cfg.get("custom_themes", {})
    if isinstance(custom, dict):
        for name, spec in custom.items():
            if isinstance(spec, dict) and "primary" in spec and "background" in spec:
                try:
                    custom_theme = Theme(
                        name=name,
                        primary=spec.get("primary", spec.get("background")),
                        secondary=spec.get("secondary", spec.get("primary", spec.get("background"))),
                        accent=spec.get("accent", spec.get("primary", spec.get("background"))),
                        foreground=spec.get("foreground", "#BBBBBB"),
                        background=spec.get("background"),
                        surface=spec.get("surface", spec.get("background")),
                        panel=spec.get("panel", spec.get("background")),
                        warning=spec.get("warning", "#c29b38"),
                        error=spec.get("error", "#c96565"),
                        success=spec.get("success", "#8ea4a2"),
                        dark=spec.get("dark", True),
                        variables=spec.get("variables", {}),
                    )
                    app.register_theme(custom_theme)
                except Exception:
                    pass

    target_theme = get_active_theme_name()
    try:
        app.theme = target_theme
    except Exception:
        avail = get_available_themes()
        if avail:
            app.theme = avail[0]
