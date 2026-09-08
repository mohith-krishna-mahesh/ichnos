"""Status bar widget for Ichnos TUI."""

from __future__ import annotations

from rich.text import Text
from textual.widgets import Static

from ichnos.ui.state import UIState


def _format_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"


class IchnosStatusBar(Static):
    """Bottom status bar displaying quiet session state and key hints."""

    def __init__(self, state: UIState, **kwargs):
        super().__init__(**kwargs)
        self.ui_state = state

    def update_status(self, message: str | None = None) -> None:
        if message:
            self.ui_state.status_message = message
        self.refresh()

    def render(self) -> Text:
        fg = "#BBBBBB"
        secondary = "#8992a7"
        warning = "#c29b38"
        if hasattr(self, "app") and hasattr(self.app, "current_theme") and self.app.current_theme:
            fg = self.app.current_theme.foreground
            secondary = self.app.current_theme.secondary
            warning = self.app.current_theme.warning

        # Left zone: Target
        if self.ui_state.active_input:
            inp = self.ui_state.active_input
            src = (
                inp.path.name
                if inp.path
                else (inp.filename if inp.filename else str(inp.source_type.value))
            )
            size_str = _format_size(len(inp.data))
            dtype = inp.detected_type if inp.detected_type else "raw"
            target_val = f"{src} ({size_str}, {dtype})"
            target_style = fg
        else:
            target_val = "none"
            target_style = "dim"

        left_prefix = " target: "
        left_len = len(left_prefix) + len(target_val)

        # Middle zone: Activity
        if self.ui_state.running_operation:
            op_str = f"{self.ui_state.running_operation}..."
            op_style = f"bold {warning}"
        else:
            msg = self.ui_state.status_message or "ready"
            op_str = msg.lower()
            op_style = "dim"

        # Right zone: Minimalist key hints
        right_len = len("^C cancel    Tab complete ")

        # Terminal width spacing
        width = self.size.width if self.size.width > 0 else 80
        total_content = left_len + len(op_str) + right_len
        if width > total_content:
            space_left = (width - total_content) // 2
            space_right = width - total_content - space_left
            pad1 = " " * max(2, space_left)
            pad2 = " " * max(2, space_right)
        else:
            pad1 = "  "
            pad2 = "  "

        t = Text()
        t.append(left_prefix, style="dim")
        t.append(target_val, style=target_style)
        t.append(pad1)
        t.append(op_str, style=op_style)
        t.append(pad2)
        t.append("^C", style=f"bold {secondary}")
        t.append(" cancel    ", style="dim")
        t.append("Tab", style=f"bold {secondary}")
        t.append(" complete ", style="dim")

        return t
