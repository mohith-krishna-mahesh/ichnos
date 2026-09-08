"""Tests for Learner and Expert mode, DeductionStep, keybindings, and clean clipboard copy."""

from ichnos.core.models import Candidate, DeductionStep, Finding, Result
from ichnos.core.pedagogy import get_pedagogical_note
from ichnos.ui.screens.result import CandidateSelectorScreen, StepSelectorScreen
from ichnos.ui.screens.startup import StartupScreen
from ichnos.ui.state import UIState
from ichnos.ui.widgets.prompt import IchnosPrompt


def test_deduction_step_models():
    step = DeductionStep(
        label="Key Length Determination",
        detail="Tested periods 1..20; period 6 yielded maximum IoC = 0.0654",
        intermediate_values={"detected_period": 6, "ioc": 0.0654},
        rationale="Kasiski examination + Index of Coincidence",
    )
    assert step.label == "Key Length Determination"
    assert step.intermediate_values["detected_period"] == 6

    finding = Finding(
        label="Vigenère Cipher",
        confidence=0.95,
        steps=[step],
        learner_note="Polyalphabetic periodic Caesar cipher",
    )
    assert len(finding.steps) == 1
    assert finding.learner_note != ""

    cand = Candidate(
        decoded="FLAG{example}",
        method="vigenere",
        confidence=0.98,
        steps=[step],
        learner_note="Solved via IoC and chi-square",
    )
    assert len(cand.steps) == 1

    res = Result(
        command="crypto vigenere --crack",
        candidates=[cand],
        steps=[step],
        learner_note="Full deduction trail",
    )
    assert len(res.steps) == 1
    assert res.learner_note == "Full deduction trail"


def test_ui_state_mode():
    state = UIState()
    assert state.mode == "expert"
    state.mode = "learner"
    assert state.mode == "learner"


def test_pedagogical_notes():
    note_v = get_pedagogical_note("vigenere")
    assert "Index of Coincidence" in note_v

    note_w = get_pedagogical_note("rsa_wiener")
    assert "convergents" in note_w.lower() or "continued fraction" in note_w.lower()

    note_s = get_pedagogical_note("ssti")
    assert "Template" in note_s

    note_d = get_pedagogical_note("docker_whiteout")
    assert "whiteout" in note_d.lower()


def test_prompt_line_editing_shortcuts():
    import asyncio

    from ichnos.ui.app import IchnosApp

    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            app.switch_screen("main")
            await pilot.pause()
            prompt = app.screen.query_one("#command-prompt", IchnosPrompt)
            app.ui_state.command_history = ["crypto caesar --brute", "encoding auto", "stego png"]

            # Test Ctrl+U: clear to start of line
            prompt.value = "crypto vigenere --key SECRET"
            prompt.cursor_position = 15
            prompt.action_handle_ctrl_u()
            assert prompt.value == " --key SECRET"
            assert prompt.cursor_position == 0

            # Test Ctrl+W: delete word to left
            prompt.value = "crypto vigenere test_word"
            prompt.cursor_position = len(prompt.value)
            prompt.action_handle_ctrl_w()
            assert prompt.value == "crypto vigenere "
            prompt.action_handle_ctrl_w()
            assert prompt.value == "crypto "

            # Test Ctrl+R: reverse history search
            prompt.value = "caesar"
            prompt.action_handle_ctrl_r()
            assert prompt.value == "crypto caesar --brute"

    asyncio.run(_test())


def test_startup_screen_enter_only():
    from textual import events

    startup = StartupScreen()
    # Enter key advances to main screen
    called = []
    startup.action_continue_to_main = lambda: called.append("enter_advanced")
    startup.action_quit_app = lambda: called.append("quit")

    # Space or arbitrary key should do nothing
    startup.on_key(events.Key("space", " "))
    assert len(called) == 0

    startup.on_key(events.Key("a", "a"))
    assert len(called) == 0

    # Enter should advance
    startup.on_key(events.Key("enter", "\r"))
    assert called == ["enter_advanced"]

    # q should quit
    startup.on_key(events.Key("q", "q"))
    assert called == ["enter_advanced", "quit"]


def test_modal_screens():
    cand = Candidate(decoded="FLAG{secret}", method="caesar", key=13, confidence=0.99)
    step = DeductionStep(label="Brute Shift", detail="Shift 13 matches", rationale="chi-square")
    res = Result(candidates=[cand], steps=[step])

    cand_screen = CandidateSelectorScreen(res)
    assert len(cand_screen.candidates) == 1
    # Verify navigation action methods exist
    assert hasattr(cand_screen, "action_scroll_top")
    assert hasattr(cand_screen, "action_scroll_bottom")
    assert hasattr(cand_screen, "action_filter_search")

    step_screen = StepSelectorScreen(res)
    assert len(step_screen.steps) == 1
    assert hasattr(step_screen, "action_scroll_top")
    assert hasattr(step_screen, "action_scroll_bottom")
    assert hasattr(step_screen, "action_filter_search")


def test_mode_command_and_copy():
    import asyncio

    from ichnos.ui.app import IchnosApp

    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            app.switch_screen("main")
            await pilot.pause()

            # Test mode command
            assert app.ui_state.mode == "expert"
            app.dispatch_command("mode learner")
            assert app.ui_state.mode == "learner"
            app.dispatch_command("mode expert")
            assert app.ui_state.mode == "expert"

            # Set a result and test copy command
            res = Result(
                candidates=[Candidate(decoded="FLAG{copied_clean}", method="test", confidence=1.0)]
            )
            app.ui_state.add_result(res)
            # Dispatch copy command without crashing
            app.dispatch_command("copy")

    asyncio.run(_test())
