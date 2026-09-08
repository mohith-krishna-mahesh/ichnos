"""State machine and animation controller for Ichnos terminal mascot."""

from __future__ import annotations

from typing import Callable

from ichnos.ui.mascot.frames import (
    IDLE_FRAMES,
    MascotFrame,
    MascotState,
    get_frames_for_state,
)


class MascotAnimation:
    """Manages frame sequencing, timing, and state transitions for the mascot."""

    def __init__(
        self,
        initial_state: MascotState = MascotState.IDLE,
        on_complete: Callable[[], None] | None = None,
        theme_name: str | None = None,
    ) -> None:
        self.theme_name: str | None = theme_name
        self.state: MascotState = initial_state
        self.frame_index: int = 0
        self.frames: list[MascotFrame] = get_frames_for_state(initial_state, theme_name=theme_name)
        self.is_running: bool = False
        self.loop: bool = initial_state == MascotState.SCANNING
        self.on_complete: Callable[[], None] | None = on_complete
        self._is_finished: bool = False

    @property
    def current_frame(self) -> MascotFrame:
        """Returns the current active MascotFrame."""
        if not self.frames:
            return IDLE_FRAMES[0]
        idx = max(0, min(self.frame_index, len(self.frames) - 1))
        return self.frames[idx]

    @property
    def current_duration(self) -> float:
        """Returns the recommended duration (seconds) for the current frame."""
        return self.current_frame.duration

    @property
    def is_finished(self) -> bool:
        """Returns True if a one-shot animation has reached its final frame."""
        return self._is_finished

    def update_theme(self, theme_name: str) -> None:
        """Updates animation frames for the active theme while preserving state and progress."""
        if self.theme_name == theme_name:
            return
        self.theme_name = theme_name
        curr_index = self.frame_index
        self.frames = get_frames_for_state(self.state, theme_name=theme_name)
        self.frame_index = min(curr_index, len(self.frames) - 1)

    def set_state(
        self,
        state: MascotState,
        on_complete: Callable[[], None] | None = None,
    ) -> None:
        """Switches animation state, resetting frame index and loading state frames."""
        self.state = state
        self.frame_index = 0
        self.frames = get_frames_for_state(state, theme_name=self.theme_name)
        self.loop = state == MascotState.SCANNING
        self.on_complete = on_complete
        self._is_finished = False

    def step(self) -> MascotFrame:
        """Advances animation by one frame and returns the new current frame."""
        num_frames = len(self.frames)
        if num_frames <= 1:
            self._is_finished = True
            return self.current_frame

        if self.frame_index + 1 < num_frames:
            self.frame_index += 1
        elif self.loop:
            self.frame_index = 0
        else:
            self._is_finished = True
            if self.on_complete:
                try:
                    self.on_complete()
                except Exception:
                    pass

        return self.current_frame

    def reset(self) -> None:
        """Resets the frame index to 0."""
        self.frame_index = 0
        self._is_finished = False

    def start(self) -> None:
        """Marks animation as actively running."""
        self.is_running = True

    def stop(self) -> None:
        """Stops/pauses the animation."""
        self.is_running = False
