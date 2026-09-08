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


def test_canonical_theme_files_exist_and_valid():
    """Verify that all canonical .theme files in themes/ exist and parse as valid Theme objects."""
    from pathlib import Path

    from ichnos.ui.theme import BUILTIN_THEMES, load_theme_file

    themes_repo_dir = Path(__file__).parent.parent.parent / "themes"
    assert themes_repo_dir.is_dir()

    for name in ["hacker", "cyber", "matrix", "monochrome", "dracula", "nord"]:
        theme_path = themes_repo_dir / f"{name}.theme"
        assert theme_path.exists(), f"Missing canonical theme file: {theme_path}"

        loaded = load_theme_file(theme_path)
        assert loaded is not None, f"Failed to parse {theme_path}"
        assert loaded.name == name
        builtin = BUILTIN_THEMES[name]
        assert str(loaded.primary).lower() == str(builtin.primary).lower()
        assert str(loaded.background).lower() == str(builtin.background).lower()


def test_discover_user_themes_from_directory(tmp_path, monkeypatch):
    """Verify that placing a .theme file into the user themes directory makes it available."""
    from ichnos.ui.theme import discover_user_themes, get_available_themes

    themes_dir = tmp_path / "themes"
    themes_dir.mkdir()
    monkeypatch.setenv("ICHNOS_THEMES_DIR", str(themes_dir))
    monkeypatch.setenv("ICHNOS_CONFIG_DIR", str(tmp_path))

    # Write a new theme file: synthwave.theme
    synthwave_path = themes_dir / "synthwave.theme"
    synthwave_path.write_text(
        '{"name": "synthwave", "primary": "#ff007f", "background": "#120024"}'
    )

    discovered = discover_user_themes()
    assert "synthwave" in discovered
    assert str(discovered["synthwave"].primary).lower() == "#ff007f"

    avail = get_available_themes()
    assert "synthwave" in avail


def test_user_theme_overrides_builtin(tmp_path, monkeypatch):
    """Verify that a user .theme file with a built-in name overrides the built-in theme."""
    from ichnos.ui.theme import HACKER_THEME, discover_user_themes, register_ichnos_themes

    themes_dir = tmp_path / "themes"
    themes_dir.mkdir()
    monkeypatch.setenv("ICHNOS_THEMES_DIR", str(themes_dir))
    monkeypatch.setenv("ICHNOS_CONFIG_DIR", str(tmp_path))

    # Override hacker theme with customized primary color
    override_path = themes_dir / "hacker.theme"
    override_path.write_text(
        '{"name": "hacker", "primary": "#00ffff", "background": "#000000"}'
    )

    discovered = discover_user_themes()
    assert "hacker" in discovered
    assert str(discovered["hacker"].primary).lower() == "#00ffff"
    assert str(HACKER_THEME.primary).lower() != "#00ffff"

    # In Textual app, registering themes should register the overridden hacker theme
    app = IchnosApp()
    register_ichnos_themes(app)
    app.theme = "hacker"
    assert str(app.current_theme.primary).lower() == "#00ffff"


def test_malformed_theme_file_resilience(tmp_path, monkeypatch):
    """Verify that invalid JSON or incomplete theme files are safely skipped without crash."""
    from ichnos.ui.theme import discover_user_themes, load_theme_file

    themes_dir = tmp_path / "themes"
    themes_dir.mkdir()
    monkeypatch.setenv("ICHNOS_THEMES_DIR", str(themes_dir))

    # 1. Invalid JSON
    bad_json = themes_dir / "corrupt.theme"
    bad_json.write_text("NOT VALID JSON {{{")
    assert load_theme_file(bad_json) is None

    # 2. Missing primary or background
    missing_fields = themes_dir / "missing.theme"
    missing_fields.write_text('{"name": "missing", "secondary": "#112233"}')
    assert load_theme_file(missing_fields) is None

    # 3. discover_user_themes skips both without errors
    discovered = discover_user_themes()
    assert "corrupt" not in discovered
    assert "missing" not in discovered

