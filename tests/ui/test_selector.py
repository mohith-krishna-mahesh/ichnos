"""Unit tests for CandidateSelectorScreen, inspection, and workflow chaining (d, a, x)."""

import asyncio

from ichnos.core.models import Candidate, Result
from ichnos.ui.app import IchnosApp
from ichnos.ui.screens.result import CandidateSelectorScreen
from ichnos.ui.state import DEFAULT_SCRATCH_DIR


def test_candidate_selector_mount_and_navigation():
    res = Result(
        command="crypto caesar --brute",
        candidates=[
            Candidate(
                decoded="FLAG{first_candidate}", method="caesar_shift_1", confidence=0.9, key="1"
            ),
            Candidate(
                decoded="FLAG{second_candidate}", method="caesar_shift_2", confidence=0.7, key="2"
            ),
        ],
        status="success",
    )

    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            await pilot.press("enter")  # enter main screen
            selector = CandidateSelectorScreen(res)
            await app.push_screen(selector)
            assert isinstance(app.screen, CandidateSelectorScreen)

            # Check candidate details are populated
            detail = selector.query_one("#candidate-detail")
            assert detail is not None

            # Test dismiss with Escape
            await pilot.press("escape")
            assert not isinstance(app.screen, CandidateSelectorScreen)

    asyncio.run(_test())


def test_candidate_selector_chain_decode():
    res = Result(
        command="test command",
        candidates=[
            Candidate(decoded="SGVsbG8gV29ybGQ=", method="test_base64", confidence=0.85, key="b64"),
        ],
        status="success",
    )

    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            await pilot.press("enter")
            selector = CandidateSelectorScreen(res)
            await app.push_screen(selector)

            # Press 'd' to trigger chain decode
            await pilot.press("d")
            # Should have returned to main screen and set active input
            assert app.ui_state.active_input is not None
            assert b"SGVsbG8gV29ybGQ=" in app.ui_state.active_input.data

    asyncio.run(_test())


def test_candidate_selector_chain_analyze():
    res = Result(
        command="test command",
        candidates=[
            Candidate(decoded="SAMPLE TEXT", method="test_method", confidence=0.8),
        ],
        status="success",
    )

    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            await pilot.press("enter")
            selector = CandidateSelectorScreen(res)
            await app.push_screen(selector)

            # Press 'a' to trigger chain analyze
            await pilot.press("a")
            assert app.ui_state.active_input is not None
            assert b"SAMPLE TEXT" in app.ui_state.active_input.data

    asyncio.run(_test())


def test_candidate_selector_chain_extract():
    res = Result(
        command="test command",
        candidates=[
            Candidate(
                decoded=b"\x89PNG\r\n\x1a\nfake_image_bytes", method="lsb_RGB_1bit", confidence=0.9
            ),
        ],
        status="success",
    )

    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            await pilot.press("enter")
            selector = CandidateSelectorScreen(res)
            await app.push_screen(selector)

            # Press 'x' to trigger extract to scratch
            await pilot.press("x")
            assert app.ui_state.active_input is not None
            extracted_path = app.ui_state.active_input.path
            assert extracted_path is not None
            assert (
                DEFAULT_SCRATCH_DIR in extracted_path.parents
                or extracted_path.parent == DEFAULT_SCRATCH_DIR
                or extracted_path.parent.name == "scratch"
            )
            assert extracted_path.read_bytes() == b"\x89PNG\r\n\x1a\nfake_image_bytes"

            # Clean up test file
            extracted_path.unlink(missing_ok=True)

    asyncio.run(_test())


def test_candidate_selector_enter_use_as_target():
    res = Result(
        command="test command",
        candidates=[
            Candidate(decoded="FLAG{promoted_candidate}", method="caesar_shift_3", confidence=0.95),
        ],
        status="success",
    )

    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            await pilot.press("enter")  # enter main screen
            selector = CandidateSelectorScreen(res)
            await app.push_screen(selector)

            # Press Enter to use candidate as target
            await pilot.press("enter")
            assert not isinstance(app.screen, CandidateSelectorScreen)
            assert app.ui_state.active_input is not None
            assert app.ui_state.active_input.data == b"FLAG{promoted_candidate}"

    asyncio.run(_test())
