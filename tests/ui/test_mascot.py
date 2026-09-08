"""Unit tests for Ichnos mascot frames, animation state machine, renderer, and Textual widget."""

import asyncio

from rich.align import Align
from textual.app import App, ComposeResult

from ichnos.ui.app import IchnosApp
from ichnos.ui.mascot.animation import MascotAnimation
from ichnos.ui.mascot.frames import (
    ANIMATIONS,
    BLINK,
    IDLE,
    IDLE_FRAMES,
    SCANNING_FRAMES,
    STARTUP_FRAMES,
    MascotFrame,
    MascotState,
    get_frames_for_state,
)
from ichnos.ui.mascot.renderer import MascotRenderer
from ichnos.ui.mascot.widget import MascotWidget
from ichnos.ui.screens.main import MainScreen
from ichnos.ui.screens.startup import StartupScreen
from ichnos.ui.widgets.output import IchnosOutput


def test_mascot_frames_structure_and_dimensions():
    # 3-stage startup reveal [IDLE, BLINK, IDLE]
    assert len(STARTUP_FRAMES) == 3
    assert STARTUP_FRAMES == [IDLE, BLINK, IDLE]

    # 3-stage scanning loop [IDLE, BLINK, IDLE]
    assert len(SCANNING_FRAMES) == 3
    assert SCANNING_FRAMES == [IDLE, BLINK, IDLE]

    # Idle frame
    assert len(IDLE_FRAMES) >= 1
    assert IDLE_FRAMES[0] == IDLE

    # ANIMATIONS dictionary mapping
    assert ANIMATIONS["idle"] == [IDLE]
    assert ANIMATIONS["blink"] == [IDLE, BLINK, IDLE]
    assert ANIMATIONS["scanning"] == SCANNING_FRAMES

    # Check uniform vertical height across all frames to prevent visual jitter
    expected_height = 24
    expected_width = 96

    all_frames = STARTUP_FRAMES + SCANNING_FRAMES + IDLE_FRAMES
    for frame in all_frames:
        assert isinstance(frame, MascotFrame)
        assert isinstance(frame, str)
        assert frame.height == expected_height
        assert frame.width == expected_width
        assert frame.description
        assert any(c in frame.raw_ansi for c in ("▀", "█", "▒"))
        assert "\x1b[48;" in frame.raw_ansi  # Background codes used for 1-to-1 sub-pixel fidelity


def test_mascot_theme_coupling():
    """Verify that mascot background and logo adapt to different themes."""
    hacker_frames = get_frames_for_state(MascotState.IDLE, theme_name="hacker")
    cyber_frames = get_frames_for_state(MascotState.IDLE, theme_name="cyber")
    matrix_frames = get_frames_for_state(MascotState.IDLE, theme_name="matrix")

    assert len(hacker_frames) == 1
    assert len(cyber_frames) == 1
    assert len(matrix_frames) == 1

    # Hacker theme uses surface #111111 (17, 17, 17)
    assert "\x1b[48;2;17;17;17m" in hacker_frames[0].raw_ansi
    # Cyber theme uses surface #0f172a (15, 23, 42) and cyan logo #00e5ff (0, 229, 255)
    assert "\x1b[48;2;15;23;42m" in cyber_frames[0].raw_ansi
    assert "\x1b[38;2;0;229;255m" in cyber_frames[0].raw_ansi
    # Matrix theme uses surface #0a140a (10, 20, 10) and green logo #00ff66 (0, 255, 102)
    assert "\x1b[48;2;10;20;10m" in matrix_frames[0].raw_ansi
    assert "\x1b[38;2;0;255;102m" in matrix_frames[0].raw_ansi


def test_get_frames_for_state():
    assert get_frames_for_state(MascotState.STARTUP) == STARTUP_FRAMES
    assert get_frames_for_state(MascotState.SCANNING) == SCANNING_FRAMES
    assert get_frames_for_state(MascotState.IDLE) == IDLE_FRAMES
    assert get_frames_for_state(MascotState.BLINK) == ANIMATIONS["blink"]
    # Placeholder states fallback to IDLE_FRAMES
    for state in [MascotState.FOUND, MascotState.ERROR, MascotState.SUCCESS, MascotState.THINKING]:
        assert get_frames_for_state(state) == IDLE_FRAMES


def test_mascot_animation_startup_sequencing():
    completed = False

    def on_done():
        nonlocal completed
        completed = True

    anim = MascotAnimation(initial_state=MascotState.STARTUP, on_complete=on_done)
    assert anim.state == MascotState.STARTUP
    assert anim.frame_index == 0
    assert not anim.loop

    # Step through all 3 frames
    for i in range(len(STARTUP_FRAMES) - 1):
        f = anim.step()
        assert f == STARTUP_FRAMES[i + 1]

    # Stepping at end triggers completion
    anim.step()
    assert anim.is_finished
    assert completed


def test_mascot_animation_scanning_loop():
    anim = MascotAnimation(initial_state=MascotState.SCANNING)
    assert anim.loop

    num_scan = len(SCANNING_FRAMES)
    # Step through entire cycle
    for i in range(num_scan):
        assert anim.frame_index == i
        anim.step()

    # Verify loop resets to index 0
    assert anim.frame_index == 0


def test_mascot_renderer_responsiveness():
    renderer = MascotRenderer()
    idle_frame = IDLE_FRAMES[0]

    # Standard wide terminal (100 columns)
    wide_render = renderer.render(idle_frame, viewport_width=100, viewport_height=30)
    assert isinstance(wide_render, Align)

    # Preferred dimensions
    w_pref, h_pref = renderer.get_preferred_dimensions(idle_frame, 100)
    assert w_pref == 96
    assert h_pref == 24


def test_mascot_widget_textual_lifecycle():
    class MascotTestApp(App):
        def compose(self) -> ComposeResult:
            yield MascotWidget(id="test-mascot")

    async def _test():
        app = MascotTestApp()
        async with app.run_test() as pilot:
            widget = app.query_one("#test-mascot", MascotWidget)
            assert widget is not None

            # Test startup play and skip
            widget.play_startup()
            assert widget.animation.is_running
            assert widget.animation.state == MascotState.STARTUP

            widget.skip_to_idle()
            assert widget.animation.state == MascotState.IDLE
            assert not widget.animation.is_running

            # Test scanning animation
            widget.play_scanning()
            assert widget.animation.is_running
            assert widget.animation.state == MascotState.SCANNING

            widget.set_idle()
            assert widget.animation.state == MascotState.IDLE
            assert not widget.animation.is_running

            await pilot.pause()

    asyncio.run(_test())


def test_startup_screen_with_mascot():
    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            assert isinstance(app.screen, StartupScreen)
            mascot = app.screen.query_one(MascotWidget)
            assert mascot is not None

            # Press enter to continue to MainScreen
            await pilot.press("enter")
            assert isinstance(app.screen, MainScreen)

    asyncio.run(_test())


def test_startup_screen_skip_ahead_key():
    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            screen = app.screen
            assert isinstance(screen, StartupScreen)
            mascot = screen.query_one(MascotWidget)
            assert mascot is not None

            # Non-enter key does not advance
            await pilot.press("s")
            assert isinstance(app.screen, StartupScreen)

            # Enter advances to main screen
            await pilot.press("enter")
            assert isinstance(app.screen, MainScreen)

    asyncio.run(_test())


def test_app_mascot_command():
    async def _test():
        app = IchnosApp()
        async with app.run_test() as pilot:
            await pilot.press("enter")  # enter main screen
            output = app.screen.query_one("#output-view", IchnosOutput)

            app.dispatch_command("mascot")
            rendered_children = [str(c._render()) for c in output.children if hasattr(c, "_render")]
            assert any(c in text for text in rendered_children for c in ("▀", "█", "▒"))

    asyncio.run(_test())
