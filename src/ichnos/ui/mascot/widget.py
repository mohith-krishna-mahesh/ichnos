"""Textual Widget component for rendering and animating the Ichnos terminal mascot."""

from __future__ import annotations

from typing import Callable

from textual.timer import Timer
from textual.widgets import Static

from ichnos.ui.mascot.animation import MascotAnimation
from ichnos.ui.mascot.frames import MascotState
from ichnos.ui.mascot.renderer import MascotRenderer


class MascotWidget(Static):
    """Reusable Textual widget that displays and animates the Ichnos mascot."""

    DEFAULT_CSS = """
    MascotWidget {
        width: 100%;
        height: auto;
        content-align: center middle;
        align: center middle;
    }
    """

    def __init__(
        self,
        initial_state: MascotState = MascotState.IDLE,
        style: str = "bold",
        **kwargs,
    ) -> None:
        super().__init__("", **kwargs)
        self.animation = MascotAnimation(initial_state=initial_state)
        self.renderer = MascotRenderer(default_style=style)
        self._timer: Timer | None = None
        self._on_sequence_complete: Callable[[], None] | None = None

    def on_mount(self) -> None:
        """Initial render on mount and timer startup if already set to run."""
        self._render_current()
        if self.animation.is_running:
            self._start_timer()

    def on_unmount(self) -> None:
        """Stops and clears any active timers upon unmounting."""
        self.stop_animation()

    def on_resize(self) -> None:
        """Re-renders dynamically with updated viewport width."""
        self._render_current()

    def play_startup(self, on_complete: Callable[[], None] | None = None) -> None:
        """Starts the one-shot startup animation sequence (Frames 0 to 6)."""
        self.stop_animation()
        self._on_sequence_complete = on_complete
        self.animation.set_state(MascotState.STARTUP, on_complete=self._handle_startup_finished)
        self.animation.start()
        self._render_current()
        self._start_timer()

    def play_scanning(self) -> None:
        """Starts subtle looping scanning animation for long-running operations."""
        self.stop_animation()
        self._on_sequence_complete = None
        self.animation.set_state(MascotState.SCANNING)
        self.animation.start()
        self._render_current()
        self._start_timer()

    def set_idle(self) -> None:
        """Stops active animations and presents the static idle mascot."""
        self.stop_animation()
        self.animation.set_state(MascotState.IDLE)
        self.animation.stop()
        self._render_current()

    def stop_animation(self) -> None:
        """Cancels active timer and stops animation."""
        if self._timer is not None:
            self._timer.stop()
            self._timer = None
        self.animation.stop()

    def skip_to_idle(self) -> None:
        """Immediately skips any playing animation and reveals the complete idle frame."""
        self.set_idle()
        if self._on_sequence_complete:
            cb = self._on_sequence_complete
            self._on_sequence_complete = None
            try:
                cb()
            except Exception:
                pass

    def _start_timer(self) -> None:
        if self._timer is not None:
            self._timer.stop()
        interval = self.animation.current_duration
        self._timer = self.set_interval(interval, self._tick)

    def _tick(self) -> None:
        """Advances animation by one frame and re-renders."""
        if not self.animation.is_running:
            return

        self.animation.step()
        self._render_current()

        if self.animation.is_finished and not self.animation.loop:
            self.stop_animation()

    def _handle_startup_finished(self) -> None:
        """Called when one-shot startup sequence finishes."""
        self.set_idle()
        if self._on_sequence_complete:
            cb = self._on_sequence_complete
            self._on_sequence_complete = None
            try:
                cb()
            except Exception:
                pass

    def render(self):
        """Returns the Rich renderable for the current frame."""
        width = self.app.size.width if self.is_mounted and self.app else 80
        height = self.app.size.height if self.is_mounted and self.app else 24
        if self.is_mounted and self.app:
            app_theme = getattr(self.app, "theme", None)
            if app_theme and app_theme != self.animation.theme_name:
                self.animation.update_theme(app_theme)
        return self.renderer.render(
            self.animation.current_frame,
            viewport_width=width,
            viewport_height=height,
        )

    def _render_current(self) -> None:
        """Renders the current frame through MascotRenderer with responsive dimensions."""
        self.update(self.render())
