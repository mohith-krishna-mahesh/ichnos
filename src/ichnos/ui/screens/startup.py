"""Startup splash screen for Ichnos TUI with terminal mascot animation and skip-ahead."""

from __future__ import annotations

import os

from rich.align import Align
from rich.text import Text
from textual import events
from textual.binding import Binding
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Static

from ichnos.ui.mascot.widget import MascotWidget

DISCLAIMER = (
    "Ichnos is a security research & CTF analysis toolkit.\n"
    "Use only on systems, files, and challenges you own or have explicit authorization to test."
)


class StartupScreen(Screen):
    """Initial splash screen with animated mascot reveal and session status."""

    BINDINGS = [
        Binding("enter", "continue_to_main", "Continue", show=True),
        Binding("ctrl+c", "quit_app", "Quit", show=False),
        Binding("q", "quit_app", "Quit", show=True),
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._animation_completed: bool = False

    def compose(self):
        with Container(id="startup-container"):
            yield MascotWidget(id="startup-logo", classes="startup-mascot")
            yield Static(Align.center(Text(DISCLAIMER, justify="center")), id="startup-disclaimer")
            yield Static("", id="startup-prompt")

    def on_mount(self) -> None:
        mascot: MascotWidget = self.query_one("#startup-logo", MascotWidget)

        if not self._should_animate():
            mascot.set_idle()
            self._display_ready_prompts()
            self._animation_completed = True
            return

        self._animation_completed = False
        mascot.play_startup(on_complete=self._on_startup_animation_complete)

    def _should_animate(self) -> bool:
        """Determines if animation is supported and enabled in current terminal."""
        if os.environ.get("NO_COLOR") or os.environ.get("ICHNOS_NO_ANIMATION"):
            return False
        # Degrade gracefully to static display on small/constrained terminals
        if self.app.size.width < 50 or self.app.size.height < 15:
            return False
        return True

    def _on_startup_animation_complete(self) -> None:
        """Callback invoked when the mascot startup sequence reaches the idle frame."""
        self._animation_completed = True
        self._display_ready_prompts()

    def _display_ready_prompts(self) -> None:
        """Renders the continue prompt."""
        prompt_widget = self.query_one("#startup-prompt", Static)
        prompt_widget.update(Align.center(Text("Press Enter to start", justify="center")))

    def on_key(self, event: events.Key) -> None:
        """Only Enter advances past startup screen."""
        if event.key == "enter":
            self.action_continue_to_main()
        elif event.key in ("ctrl+c", "q"):
            self.action_quit_app()

    def action_continue_to_main(self) -> None:
        """Advances directly to the main terminal screen."""
        mascot: MascotWidget = self.query_one("#startup-logo", MascotWidget)
        mascot.stop_animation()
        if self.app.screen is self:
            self.app.switch_screen("main")

    def action_quit_app(self) -> None:
        """Exits the application cleanly."""
        mascot: MascotWidget = self.query_one("#startup-logo", MascotWidget)
        mascot.stop_animation()
        self.app.exit()
