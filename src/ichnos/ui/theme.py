"""Theme management and configuration for Ichnos TUI."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from textual.theme import Theme

from ichnos.ui.state import DEFAULT_CONFIG_DIR

if TYPE_CHECKING:
    from textual.app import App

DEFAULT_CONFIG_FILE = Path(
    os.environ.get("ICHNOS_CONFIG_FILE", str(DEFAULT_CONFIG_DIR / "config.json"))
)

# Reference Hacker theme (tactical graphite, deep obsidian #0A0B0A, ice-slate #8ba4b0, sage #8ea4a2)
HACKER_THEME = Theme(
    name="hacker",
    primary="#8ba4b0",
    secondary="#8992a7",
    accent="#8ea4a2",
    foreground="#BBBBBB",
    background="#0A0B0A",
    surface="#111111",
    panel="#12120f",
    warning="#c29b38",
    error="#c96565",
    success="#8ea4a2",
    dark=True,
    variables={
        "border-color": "#393836",
        "border-focused": "#8ba4b0",
        "border-variant": "#8992a7",
        "text-muted": "#858585",
        "text-dim": "#625e5a",
        "header-bg": "#111111",
        "status-bg": "#111111",
        "prompt-bg": "#0A0B0A",
        "output-bg": "#0D0E0D",
    },
)

CYBER_THEME = Theme(
    name="cyber",
    primary="#00e5ff",
    secondary="#38bdf8",
    accent="#a855f7",
    foreground="#f8fafc",
    background="#070a12",
    surface="#0f172a",
    panel="#090d16",
    warning="#fbbf24",
    error="#ef4444",
    success="#22c55e",
    dark=True,
    variables={
        "border-color": "#1e293b",
        "border-focused": "#00e5ff",
        "border-variant": "#38bdf8",
        "text-muted": "#94a3b8",
        "text-dim": "#64748b",
        "header-bg": "#0f172a",
        "status-bg": "#1e293b",
        "prompt-bg": "#090d16",
        "output-bg": "#090d16",
    },
)

MATRIX_THEME = Theme(
    name="matrix",
    primary="#00ff66",
    secondary="#00cc55",
    accent="#88ff88",
    foreground="#d4ffd4",
    background="#050a05",
    surface="#0a140a",
    panel="#0d1a0d",
    warning="#d4aa00",
    error="#cc3333",
    success="#00ff66",
    dark=True,
    variables={
        "border-color": "#1b381b",
        "border-focused": "#00ff66",
        "border-variant": "#00cc55",
        "text-muted": "#4d994d",
        "text-dim": "#2e5c2e",
        "header-bg": "#0a140a",
        "status-bg": "#0a140a",
        "prompt-bg": "#050a05",
        "output-bg": "#070f07",
    },
)

MONOCHROME_THEME = Theme(
    name="monochrome",
    primary="#ffffff",
    secondary="#cccccc",
    accent="#aaaaaa",
    foreground="#e0e0e0",
    background="#000000",
    surface="#121212",
    panel="#1a1a1a",
    warning="#cccccc",
    error="#ffffff",
    success="#cccccc",
    dark=True,
    variables={
        "border-color": "#333333",
        "border-focused": "#ffffff",
        "border-variant": "#666666",
        "text-muted": "#777777",
        "text-dim": "#555555",
        "header-bg": "#121212",
        "status-bg": "#121212",
        "prompt-bg": "#000000",
        "output-bg": "#050505",
    },
)

DRACULA_THEME = Theme(
    name="dracula",
    primary="#bd93f9",
    secondary="#ff79c6",
    accent="#8be9fd",
    foreground="#f8f8f2",
    background="#1e1f29",
    surface="#282a36",
    panel="#21222c",
    warning="#ffb86c",
    error="#ff5555",
    success="#50fa7b",
    dark=True,
    variables={
        "border-color": "#44475a",
        "border-focused": "#bd93f9",
        "border-variant": "#ff79c6",
        "text-muted": "#6272a4",
        "text-dim": "#44475a",
        "header-bg": "#282a36",
        "status-bg": "#21222c",
        "prompt-bg": "#1e1f29",
        "output-bg": "#1e1f29",
    },
)

NORD_THEME = Theme(
    name="nord",
    primary="#88c0d0",
    secondary="#81a1c1",
    accent="#8fbcbb",
    foreground="#eceff4",
    background="#242933",
    surface="#2e3440",
    panel="#3b4252",
    warning="#ebcb8b",
    error="#bf616a",
    success="#a3be8c",
    dark=True,
    variables={
        "border-color": "#434c5e",
        "border-focused": "#88c0d0",
        "border-variant": "#81a1c1",
        "text-muted": "#d8dee9",
        "text-dim": "#4c566a",
        "header-bg": "#2e3440",
        "status-bg": "#2e3440",
        "prompt-bg": "#242933",
        "output-bg": "#242933",
    },
)

BUILTIN_THEMES: dict[str, Theme] = {
    "hacker": HACKER_THEME,
    "cyber": CYBER_THEME,
    "matrix": MATRIX_THEME,
    "monochrome": MONOCHROME_THEME,
    "dracula": DRACULA_THEME,
    "nord": NORD_THEME,
}


def get_user_themes_dir() -> Path:
    """Returns directory containing user-provided custom .theme files."""
    if "ICHNOS_THEMES_DIR" in os.environ:
        return Path(os.environ["ICHNOS_THEMES_DIR"])
    return DEFAULT_CONFIG_DIR / "themes"


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


def discover_user_themes() -> dict[str, Theme]:
    """Discovers all external .theme and .json files in the user themes directory."""
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
    """Returns list of all available theme names (builtins + discovered user .theme files + config custom themes)."""
    builtins = list(BUILTIN_THEMES.keys())
    user_themes = list(discover_user_themes().keys())
    cfg = load_config()
    config_customs = list(cfg.get("custom_themes", {}).keys())

    seen: set[str] = set()
    result: list[str] = []
    for name in builtins + user_themes + config_customs:
        if name not in seen:
            seen.add(name)
            result.append(name)
    return result


def get_active_theme_name() -> str:
    """Returns the name of the currently configured theme, defaulting to 'hacker'."""
    cfg = load_config()
    theme_name = cfg.get("theme", "hacker")
    if theme_name in get_available_themes():
        return theme_name
    return "hacker"


def set_active_theme_name(theme_name: str) -> None:
    """Persists chosen theme name to the configuration file."""
    cfg = load_config()
    cfg["theme"] = theme_name
    save_config(cfg)


def register_ichnos_themes(app: App) -> None:
    """Registers all built-in, external .theme, and config-defined themes into the Textual application."""
    # 1. Register built-ins
    for theme in BUILTIN_THEMES.values():
        app.register_theme(theme)

    # 2. Register discovered user .theme files (overriding built-ins if name matches)
    user_themes = discover_user_themes()
    for theme in user_themes.values():
        app.register_theme(theme)

    # 3. Register custom themes from config.json
    cfg = load_config()
    custom = cfg.get("custom_themes", {})
    if isinstance(custom, dict):
        for name, spec in custom.items():
            if isinstance(spec, dict) and "primary" in spec and "background" in spec:
                try:
                    custom_theme = Theme(
                        name=name,
                        primary=spec.get("primary", "#8ba4b0"),
                        secondary=spec.get("secondary", "#8992a7"),
                        accent=spec.get("accent", "#8ea4a2"),
                        foreground=spec.get("foreground", "#BBBBBB"),
                        background=spec.get("background", "#0A0B0A"),
                        surface=spec.get("surface", "#111111"),
                        panel=spec.get("panel", "#12120f"),
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
        app.theme = "hacker"
