"""Progress indicator widget for background operations in Ichnos TUI."""

from __future__ import annotations

from rich.text import Text
from textual.widgets import Static


class IchnosProgress(Static):
    """Animated progress/spinner indicator for async workers."""

    SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, **kwargs):
        super().__init__("", **kwargs)
        self._frame_idx = 0
        self._operation: str | None = None
        self._timer = None

    def start(self, operation: str) -> None:
        """Starts the spinner animation with the given operation description."""
        self._operation = operation
        self._frame_idx = 0
        self.update_display()
        if self._timer is None:
            self._timer = self.set_interval(0.1, self._advance_frame)

    def stop(self) -> None:
        """Stops the spinner and clears the display."""
        if self._timer:
            self._timer.stop()
            self._timer = None
        self._operation = None
        self.update("")

    def _advance_frame(self) -> None:
        self._frame_idx = (self._frame_idx + 1) % len(self.SPINNER_FRAMES)
        self.update_display()

    def update_display(self) -> None:
        if not self._operation:
            self.update("")
            return

        primary = "#8ba4b0"
        warning = "#c29b38"
        if hasattr(self, "app") and hasattr(self.app, "current_theme") and self.app.current_theme:
            primary = self.app.current_theme.primary
            warning = self.app.current_theme.warning

        frame = self.SPINNER_FRAMES[self._frame_idx]
        text = Text.from_markup(f"[bold {warning}]{frame}[/] [bold {primary}]{self._operation}[/]")
        self.update(text)
