"""Interactive command input prompt widget with history and keybindings."""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.binding import Binding
from textual.message import Message
from textual.widgets import Input

if TYPE_CHECKING:
    from ichnos.ui.state import UIState


class IchnosPrompt(Input):
    """Command line input widget with history recall, tab completion, and Ctrl shortcuts."""

    DEFAULT_CSS = """
    IchnosPrompt {
        border: solid $border-color;
        padding: 0 1;
        background: $prompt-bg;
        color: $foreground;
    }
    IchnosPrompt:focus {
        border: double $border-focused;
    }
    """

    BINDINGS = [
        Binding("up", "history_up", "Previous Command", show=False),
        Binding("down", "history_down", "Next Command", show=False),
        Binding("pageup", "handle_page_up", "Scroll Up", show=False),
        Binding("pagedown", "handle_page_down", "Scroll Down", show=False),
        Binding("ctrl+c", "handle_ctrl_c", "Cancel / Clear", show=False),
        Binding("ctrl+d", "handle_ctrl_d", "Exit", show=False),
        Binding("ctrl+l", "handle_ctrl_l", "Clear View", show=False),
        Binding("ctrl+u", "handle_ctrl_u", "Clear to Start", show=False),
        Binding("ctrl+w", "handle_ctrl_w", "Delete Word Left", show=False),
        Binding("ctrl+r", "handle_ctrl_r", "Reverse Search", show=False),
        Binding("ctrl+shift+c", "handle_copy_result", "Copy Result", show=False),
        Binding("tab", "handle_tab", "Autocomplete", show=False),
    ]

    class SubmittedCommand(Message):
        """Posted when a command is submitted with Enter."""

        def __init__(self, command: str) -> None:
            super().__init__()
            self.command = command

    class AutocompleteRequested(Message):
        """Posted when Tab is pressed."""

        def __init__(self, current_text: str, cursor_pos: int) -> None:
            super().__init__()
            self.current_text = current_text
            self.cursor_pos = cursor_pos

    class ClearViewRequested(Message):
        """Posted when Ctrl+L is pressed."""

    class ExitRequested(Message):
        """Posted when Ctrl+D or exit command is given."""

    class CancelRequested(Message):
        """Posted when Ctrl+C is pressed."""

    class PageUpRequested(Message):
        """Posted when Page Up is pressed."""

    class PageDownRequested(Message):
        """Posted when Page Down is pressed."""

    class CopyResultRequested(Message):
        """Posted when Ctrl+Shift+C is pressed."""

    def __init__(self, state: UIState, **kwargs):
        super().__init__(placeholder="Type a command or 'help' (Tab to autocomplete)...", **kwargs)
        self.ui_state = state
        self._history_index: int | None = None
        self._temp_buffer: str = ""

    def on_input_submitted(self, event: Input.Submitted) -> None:
        cmd = self.value.strip()
        self.value = ""
        self._history_index = None
        self._temp_buffer = ""
        if cmd:
            self.post_message(self.SubmittedCommand(cmd))

    def action_history_up(self) -> None:
        """Recall earlier command from history."""
        history = self.ui_state.command_history
        if not history:
            return

        if self._history_index is None:
            self._temp_buffer = self.value
            self._history_index = len(history) - 1
        elif self._history_index > 0:
            self._history_index -= 1

        self.value = history[self._history_index]
        self.cursor_position = len(self.value)

    def action_history_down(self) -> None:
        """Recall later command from history."""
        history = self.ui_state.command_history
        if not history or self._history_index is None:
            return

        if self._history_index < len(history) - 1:
            self._history_index += 1
            self.value = history[self._history_index]
        else:
            self._history_index = None
            self.value = self._temp_buffer

        self.cursor_position = len(self.value)

    def action_handle_ctrl_c(self) -> None:
        """Deterministic Ctrl+C state priority rule."""
        self.post_message(self.CancelRequested())

    def action_handle_ctrl_d(self) -> None:
        """Ctrl+D exits the application."""
        self.post_message(self.ExitRequested())

    def action_handle_ctrl_l(self) -> None:
        """Ctrl+L clears the output view."""
        self.post_message(self.ClearViewRequested())

    def action_handle_tab(self) -> None:
        """Tab triggers context-aware autocomplete."""
        self.post_message(self.AutocompleteRequested(self.value, self.cursor_position))

    def action_handle_page_up(self) -> None:
        """Page Up scrolls output view up."""
        self.post_message(self.PageUpRequested())

    def action_handle_page_down(self) -> None:
        """Page Down scrolls output view down."""
        self.post_message(self.PageDownRequested())

    def action_handle_copy_result(self) -> None:
        """Ctrl+Shift+C triggers clean result clipboard copy."""
        self.post_message(self.CopyResultRequested())

    def action_handle_ctrl_u(self) -> None:
        """Ctrl+U: clears from cursor position back to start of line."""
        pos = self.cursor_position
        self.value = self.value[pos:]
        self.cursor_position = 0

    def action_handle_ctrl_w(self) -> None:
        """Ctrl+W: deletes previous word to the left of cursor."""
        pos = self.cursor_position
        text_before = self.value[:pos]
        stripped = text_before.rstrip()
        last_space = stripped.rfind(" ")
        if last_space == -1:
            new_before = ""
        else:
            new_before = stripped[: last_space + 1]
        self.value = new_before + self.value[pos:]
        self.cursor_position = len(new_before)

    def action_handle_ctrl_r(self) -> None:
        """Ctrl+R: reverse history search."""
        history = self.ui_state.command_history
        if not history:
            return
        query = self.value.strip().lower()
        if not query:
            self.action_history_up()
            return
        start_idx = len(history) - 1 if self._history_index is None else self._history_index - 1
        for i in range(start_idx, -1, -1):
            if query in history[i].lower():
                self._history_index = i
                self.value = history[i]
                self.cursor_position = len(self.value)
                return
