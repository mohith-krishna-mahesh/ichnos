"""Unit tests for Ichnos theme management, configuration, and switching."""

import asyncio

from ichnos.ui.app import IchnosApp
from ichnos.ui.theme import (
    get_active_theme_name,
    get_available_themes,
    load_config,
    save_config,
    set_active_theme_name,
)
from ichnos.ui.widgets.output import IchnosOutput


def test_theme_defaults_and_builtins(monkeypatch, tmp_path):
    conf_file = tmp_path / "config.json"
    themes_dir = tmp_path / "themes"
    monkeypatch.setattr("ichnos.ui.theme.DEFAULT_CONFIG_FILE", conf_file)
    monkeypatch.setattr("ichnos.ui.theme.DEFAULT_CONFIG_DIR", tmp_path)
    monkeypatch.setenv("ICHNOS_THEMES_DIR", str(themes_dir))

    # Defaults to hacker
    assert get_active_theme_name() == "hacker"
    themes = get_available_themes()
    for name in ["hacker", "cyber", "matrix", "monochrome", "dracula", "nord"]:
        assert name in themes

    # Check Hacker theme loaded from seeded .theme file
    from ichnos.ui.theme import discover_user_themes

    user_themes = discover_user_themes()
    hacker = user_themes["hacker"]
    assert hacker.name == "hacker"
    assert str(hacker.background).lower() == "#0a0b0a"
    assert str(hacker.surface).lower() == "#111111"
    assert hacker.variables.get("border-color") == "#393836"


def test_theme_persistence_and_custom_themes(monkeypatch, tmp_path):
    conf_file = tmp_path / "config.json"
    themes_dir = tmp_path / "themes"
    monkeypatch.setattr("ichnos.ui.theme.DEFAULT_CONFIG_FILE", conf_file)
    monkeypatch.setattr("ichnos.ui.theme.DEFAULT_CONFIG_DIR", tmp_path)
    monkeypatch.setenv("ICHNOS_THEMES_DIR", str(themes_dir))

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
    themes_dir = tmp_path / "themes"
    monkeypatch.setattr("ichnos.ui.theme.DEFAULT_CONFIG_FILE", conf_file)
    monkeypatch.setattr("ichnos.ui.theme.DEFAULT_CONFIG_DIR", tmp_path)
    monkeypatch.setenv("ICHNOS_THEMES_DIR", str(themes_dir))

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

    from ichnos.ui.theme import _DEFAULT_THEME_SPECS, load_theme_file

    themes_repo_dir = Path(__file__).parent.parent.parent / "themes"
    assert themes_repo_dir.is_dir()

    for name in ["hacker", "cyber", "matrix", "monochrome", "dracula", "nord"]:
        theme_path = themes_repo_dir / f"{name}.theme"
        assert theme_path.exists(), f"Missing canonical theme file: {theme_path}"

        loaded = load_theme_file(theme_path)
        assert loaded is not None, f"Failed to parse {theme_path}"
        assert loaded.name == name
        # Verify the repo .theme files match the embedded defaults
        spec = _DEFAULT_THEME_SPECS[name]
        assert str(loaded.primary).lower() == spec["primary"].lower()
        assert str(loaded.background).lower() == spec["background"].lower()


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


def test_user_theme_overrides_default(tmp_path, monkeypatch):
    """Verify that a user .theme file with a default name overrides the seeded theme."""
    from ichnos.ui.theme import discover_user_themes, register_ichnos_themes

    themes_dir = tmp_path / "themes"
    themes_dir.mkdir()
    monkeypatch.setenv("ICHNOS_THEMES_DIR", str(themes_dir))
    monkeypatch.setenv("ICHNOS_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr("ichnos.ui.theme.DEFAULT_CONFIG_FILE", tmp_path / "config.json")
    monkeypatch.setattr("ichnos.ui.theme.DEFAULT_CONFIG_DIR", tmp_path)

    # Override hacker theme with customized primary color
    override_path = themes_dir / "hacker.theme"
    override_path.write_text(
        '{"name": "hacker", "primary": "#00ffff", "background": "#000000"}'
    )

    discovered = discover_user_themes()
    assert "hacker" in discovered
    assert str(discovered["hacker"].primary).lower() == "#00ffff"

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


def test_seed_user_themes_dir(tmp_path, monkeypatch):
    """Verify that seed_user_themes_dir populates an empty directory with all default .theme files."""
    from ichnos.ui.theme import seed_user_themes_dir

    themes_dir = tmp_path / "seeded_themes"
    monkeypatch.setenv("ICHNOS_THEMES_DIR", str(themes_dir))

    seed_user_themes_dir()

    for name in ("hacker", "cyber", "matrix", "monochrome", "dracula", "nord"):
        theme_file = themes_dir / f"{name}.theme"
        assert theme_file.exists(), f"Expected {theme_file} to be seeded"
        assert "name" in theme_file.read_text(encoding="utf-8")


def test_seed_does_not_overwrite_existing(tmp_path, monkeypatch):
    """Verify that seed_user_themes_dir does not overwrite user-customised .theme files."""
    from ichnos.ui.theme import seed_user_themes_dir

    themes_dir = tmp_path / "themes"
    themes_dir.mkdir()
    monkeypatch.setenv("ICHNOS_THEMES_DIR", str(themes_dir))

    # User has a custom hacker.theme
    custom_content = '{"name": "hacker", "primary": "#ff0000", "background": "#000000"}'
    (themes_dir / "hacker.theme").write_text(custom_content)

    seed_user_themes_dir()

    # hacker.theme should be preserved, not overwritten
    assert (themes_dir / "hacker.theme").read_text() == custom_content
    # Other themes should still be seeded
    assert (themes_dir / "cyber.theme").exists()
