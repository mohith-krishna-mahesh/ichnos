"""Tests for Ichnos TUI application shell, startup transition, and prompt widget."""

import asyncio

from ichnos.ui.app import IchnosApp
from ichnos.ui.screens.main import MainScreen
from ichnos.ui.screens.startup import StartupScreen
from ichnos.ui.widgets.prompt import IchnosPrompt


def test_startup_to_main_screen_transition():
    """Verify app mounts to StartupScreen, and Enter transitions to MainScreen."""

    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            assert isinstance(app.screen, StartupScreen)
            await pilot.press("enter")
            assert isinstance(app.screen, MainScreen)

    asyncio.run(_test())


def test_prompt_history_navigation():
    """Verify Up/Down keys recall command history."""

    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            await pilot.press("enter")  # enter main screen
            prompt = app.screen.query_one("#command-prompt", IchnosPrompt)

            # Feed some history
            app.ui_state.add_command("binary strings test.bin")
            app.ui_state.add_command("crypto caesar 'test'")

            # Press Up to recall latest
            await pilot.press("up")
            assert prompt.value == "crypto caesar 'test'"

            # Press Up again to recall earlier
            await pilot.press("up")
            assert prompt.value == "binary strings test.bin"

            # Press Down to go back forward
            await pilot.press("down")
            assert prompt.value == "crypto caesar 'test'"

    asyncio.run(_test())


def test_ctrl_c_priority_rule():
    """Verify Ctrl+C priority: clears buffer when text is typed and no worker is running."""

    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            await pilot.press("enter")
            prompt = app.screen.query_one("#command-prompt", IchnosPrompt)

            # Type some text
            prompt.value = "partial command"
            await pilot.press("ctrl+c")

            # Uncommitted buffer should be cleared
            assert prompt.value == ""

            # Press Ctrl+C on empty prompt: app remains running, status updated
            await pilot.press("ctrl+c")
            assert app.is_running
            assert "Ctrl+D" in app.ui_state.status_message

    asyncio.run(_test())


def test_startup_enter_only():
    """Verify only Enter advances the animation to MainScreen, arbitrary keys do not."""

    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            assert isinstance(app.screen, StartupScreen)
            # Press arbitrary key mid-animation: does not advance
            await pilot.press("x")
            assert isinstance(app.screen, StartupScreen)
            # Press Enter: advances to MainScreen
            await pilot.press("enter")
            assert isinstance(app.screen, MainScreen)

    asyncio.run(_test())


def test_startup_narrow_fallback():
    """Verify narrow terminal width uses compact fallback art and loads cleanly."""

    async def _test():
        # Terminal width 48 (< 60)
        app = IchnosApp()
        async with app.run_test(size=(48, 20)) as pilot:
            screen = app.screen
            assert isinstance(screen, StartupScreen)
            logo_widget = screen.query_one("#startup-logo")
            assert any(c in str(logo_widget.render()) for c in ("▀", "█", "▒"))
            await pilot.press("enter")
            assert isinstance(app.screen, MainScreen)

    asyncio.run(_test())


def test_startup_quit_key():
    """Verify pressing 'q' on the startup screen exits the application."""

    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            assert isinstance(app.screen, StartupScreen)
            await pilot.press("q")
            assert not app.is_running

    asyncio.run(_test())


def test_module_command_listing_in_tui():
    """Verify typing module name (e.g. crypto, web) in TUI outputs available commands."""
    from rich.text import Text
    from textual.widgets import Static

    from ichnos.ui.widgets.output import IchnosOutput

    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            await pilot.press("enter")  # enter main screen
            assert isinstance(app.screen, MainScreen)
            output = app.screen.query_one("#output-view", IchnosOutput)

            app.dispatch_command("crypto")
            await pilot.pause()
            statics = [s.render() for s in output.query(Static)]
            text_content = "\n".join(s.plain if isinstance(s, Text) else str(s) for s in statics)
            assert "Available commands for 'crypto':" in text_content
            assert "crypto caesar" in text_content

            app.dispatch_command("web")
            await pilot.pause()
            statics = [s.render() for s in output.query(Static)]
            text_content = "\n".join(s.plain if isinstance(s, Text) else str(s) for s in statics)
            assert "Available commands for 'web':" in text_content
            assert "web fuzz" in text_content

    asyncio.run(_test())


def test_load_directory_in_tui(tmp_path):
    """Verify loading a directory sets target without error."""
    import tempfile
    from pathlib import Path

    from rich.text import Text
    from textual.widgets import Static

    from ichnos.core.models import SourceType
    from ichnos.ui.widgets.output import IchnosOutput

    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        (p / "chall.py").write_text("print(1)")
        (p / "output.txt").write_text("123")

        async def _test():
            app = IchnosApp()
            async with app.run_test() as pilot:
                await pilot.press("enter")
                output = app.screen.query_one("#output-view", IchnosOutput)

                app.dispatch_command(f"load {p}")
                await pilot.pause()

                assert app.ui_state.active_input is not None
                assert app.ui_state.active_input.source_type == SourceType.DIRECTORY
                statics = [s.render() for s in output.query(Static)]
                text_content = "\n".join(
                    s.plain if isinstance(s, Text) else str(s) for s in statics
                )
                assert "Target directory set" in text_content
                assert "Type 'solve'" in text_content

        asyncio.run(_test())


def test_help_displays_solve_and_solve_help():
    """Verify typing help shows solve workflow, and help solve shows solve details."""
    from rich.text import Text
    from textual.widgets import Static

    from ichnos.ui.widgets.output import IchnosOutput

    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            await pilot.press("enter")
            output = app.screen.query_one("#output-view", IchnosOutput)

            # Test general help
            app.dispatch_command("help")
            await pilot.pause()
            statics = [s.render() for s in output.query(Static)]
            text_content = "\n".join(s.plain if isinstance(s, Text) else str(s) for s in statics)
            assert "solve [path]" in text_content
            assert "Load file or directory as target" in text_content

            # Test help solve
            app.dispatch_command("help solve")
            await pilot.pause()
            statics = [s.render() for s in output.query(Static)]
            text_content = "\n".join(s.plain if isinstance(s, Text) else str(s) for s in statics)
            assert "Command: solve" in text_content
            assert "Autonomously solve CTF challenges" in text_content

    asyncio.run(_test())
