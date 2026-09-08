"""Unit tests for structured Result rendering in IchnosOutput."""

import asyncio

from ichnos.core.models import Candidate, Finding, Result
from ichnos.ui.app import IchnosApp
from ichnos.ui.widgets.output import IchnosOutput


def test_render_result_findings():
    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            await pilot.press("enter")
            output = app.screen.query_one("#output-view", IchnosOutput)
            initial_count = len(output.children)

            res = Result(
                command="analyze",
                findings=[
                    Finding(
                        label="Test Finding High",
                        confidence=0.95,
                        detail="Detailed info",
                        module="crypto",
                    ),
                    Finding(
                        label="Test Finding Mid",
                        confidence=0.6,
                        detail="Medium info",
                        module="encoding",
                    ),
                    Finding(
                        label="Test Finding Low", confidence=0.2, detail="Low info", module="binary"
                    ),
                ],
                status="success",
            )
            output.render_result(res)
            assert len(output.children) > initial_count

    asyncio.run(_test())


def test_render_result_candidates():
    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            await pilot.press("enter")
            output = app.screen.query_one("#output-view", IchnosOutput)
            initial_count = len(output.children)

            res = Result(
                command="crypto caesar --brute",
                candidates=[
                    Candidate(
                        decoded="FLAG{caesar_decoded}",
                        method="caesar_shift_3",
                        confidence=0.92,
                        key="3",
                    ),
                    Candidate(
                        decoded="JUNK TEXT", method="caesar_shift_4", confidence=0.3, key="4"
                    ),
                ],
                status="success",
            )
            output.render_result(res)
            assert len(output.children) > initial_count

    asyncio.run(_test())


def test_render_result_raw_and_error():
    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            await pilot.press("enter")
            output = app.screen.query_one("#output-view", IchnosOutput)
            initial_count = len(output.children)

            res = Result(
                command="custom error command",
                status="error",
                raw_output={"error": "Something went wrong"},
            )
            output.render_result(res)
            assert len(output.children) > initial_count

    asyncio.run(_test())
