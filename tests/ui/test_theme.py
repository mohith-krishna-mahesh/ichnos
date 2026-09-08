"""Unit tests for Ichnos theme management, configuration, and switching."""

import asyncio

from ichnos.ui.app import IchnosApp
from ichnos.ui.theme import (
    HACKER_THEME,
    get_active_theme_name,
    get_available_themes,
    load_config,
    save_config,
    set_active_theme_name,
)
from ichnos.ui.widgets.output import IchnosOutput


def test_theme_defaults_and_builtins(monkeypatch, tmp_path):
    conf_file = tmp_path / "config.json"
    monkeypatch.setattr("ichnos.ui.theme.DEFAULT_CONFIG_FILE", conf_file)
    monkeypatch.setattr("ichnos.ui.theme.DEFAULT_CONFIG_DIR", tmp_path)

    # Defaults to hacker
    assert get_active_theme_name() == "hacker"
    themes = get_available_themes()
    for name in ["hacker", "cyber", "matrix", "monochrome", "dracula", "nord"]:
        assert name in themes

    # Check Hacker theme palette references
    assert HACKER_THEME.name == "hacker"
    assert HACKER_THEME.background == "#0A0B0A"
    assert HACKER_THEME.surface == "#111111"
    assert HACKER_THEME.variables.get("border-color") == "#393836"


def test_theme_persistence_and_custom_themes(monkeypatch, tmp_path):
    conf_file = tmp_path / "config.json"
    monkeypatch.setattr("ichnos.ui.theme.DEFAULT_CONFIG_FILE", conf_file)
    monkeypatch.setattr("ichnos.ui.theme.DEFAULT_CONFIG_DIR", tmp_path)

    # Set theme to cyber
    set_active_theme_name("cyber")
    assert get_active_theme_name() == "cyber"
    assert conf_file.exists()

    # Load raw config via load_config
    cfg = load_config()
    assert cfg["theme"] == "cyber"

    # Add custom theme
    cfg["custom_themes"] = {
        "custom_amber": {
            "primary": "#ffaa00",
            "background": "#1a1100",
            "surface": "#2a1e05",
        }
    }
    save_config(cfg)

    avail = get_available_themes()
    assert "custom_amber" in avail

    # Switch to custom theme
    set_active_theme_name("custom_amber")
    assert get_active_theme_name() == "custom_amber"

    # Invalid theme falls back to hacker
    set_active_theme_name("non_existent_theme_404")
    assert get_active_theme_name() == "hacker"


def test_app_theme_command_dispatch(monkeypatch, tmp_path):
    conf_file = tmp_path / "config.json"
    monkeypatch.setattr("ichnos.ui.theme.DEFAULT_CONFIG_FILE", conf_file)
    monkeypatch.setattr("ichnos.ui.theme.DEFAULT_CONFIG_DIR", tmp_path)

    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            await pilot.press("enter")  # enter main screen
            output = app.screen.query_one("#output-view", IchnosOutput)

            # Default active theme should be hacker
            assert app.theme == "hacker"

            # 1. Run 'theme' to list available themes
            app.dispatch_command("theme")
            assert any(
                "Themes:" in str(c._render()) for c in output.children if hasattr(c, "_render")
            )

            # 2. Run 'theme cyber' to switch theme
            app.dispatch_command("theme cyber")
            assert app.theme == "cyber"
            assert get_active_theme_name() == "cyber"

            # 3. Run 'theme hacker' to switch back
            app.dispatch_command("theme hacker")
            assert app.theme == "hacker"
            assert get_active_theme_name() == "hacker"

            # 4. Unknown theme shows error and doesn't change theme
            app.dispatch_command("theme invalid_theme_xyz")
            assert app.theme == "hacker"
            assert any(
                "Unknown theme" in str(c._render())
                for c in output.children
                if hasattr(c, "_render")
            )

    asyncio.run(_test())
