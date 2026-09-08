"""Unit tests for IchnosApp command dispatch, builtins, and async workers."""

import asyncio

from ichnos.ui.app import IchnosApp
from ichnos.ui.widgets.output import IchnosOutput


def test_app_builtins_dispatch():
    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            await pilot.press("enter")  # enter main screen
            output = app.screen.query_one("#output-view", IchnosOutput)

            # Test 'help' builtin
            app.dispatch_command("help")
            assert any(
                "Ichnos Interactive Shell" in str(child._render())
                for child in output.children
                if hasattr(child, "_render")
            )

            # Test 'set' builtin
            app.dispatch_command("set FLAG{secret_data}")
            assert app.ui_state.active_input is not None
            assert b"FLAG{secret_data}" in app.ui_state.active_input.data

            # Test 'input' / 'target' builtin
            app.dispatch_command("target")
            assert any(
                "target:" in str(child._render()).lower()
                for child in output.children
                if hasattr(child, "_render")
            )

            # Test 'history' builtin
            app.ui_state.add_command("test command 1")
            app.dispatch_command("history")
            assert any(
                "Command History" in str(child._render())
                for child in output.children
                if hasattr(child, "_render")
            )

    asyncio.run(_test())


def test_app_command_execution():
    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            await pilot.press("enter")

            # Run a synchronous crypto caesar command
            app.dispatch_command("crypto caesar 'KHOOR' --shift 3")
            assert app.ui_state.active_result is not None
            assert app.ui_state.active_result.status == "success"
            assert app.ui_state.active_result.candidates[0].decoded_str == "HELLO"

    asyncio.run(_test())


def test_app_ctrl_c_worker_cancellation():
    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            await pilot.press("enter")
            output = app.screen.query_one("#output-view", IchnosOutput)

            # Simulate an active background operation
            app.ui_state.running_operation = "stego lsb --brute"

            # Hit Ctrl+C
            await pilot.press("ctrl+c")

            # Worker operation should be cancelled
            assert app.ui_state.running_operation is None
            # [Interrupted] should be displayed in output
            assert any(
                "Interrupted" in str(child._render())
                for child in output.children
                if hasattr(child, "_render")
            )

    asyncio.run(_test())
