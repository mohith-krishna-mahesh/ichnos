"""Banner and ASCII art headers for Ichnos TUI."""

from __future__ import annotations

from rich.text import Text
from textual.widgets import Static

from ichnos import __version__

ASCII_LOGO_LINES = [
    "██╗ ██████╗██╗  ██╗███╗   ██╗ ██████╗ ███████╗",
    "██║██╔════╝██║  ██║████╗  ██║██╔═══██╗██╔════╝",
    "██║██║     ███████║██╔██╗ ██║██║   ██║███████╗",
    "██║██║     ██╔══██║██║╚██╗██║██║   ██║╚════██║",
    "██║╚██████╗██║  ██║██║ ╚████║╚██████╔╝███████║",
    "╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝",
]


class IchnosHeader(Static):
    """Top application header showing logo, version, and subtitle."""

    def render(self) -> Text:
        primary = "#8ba4b0"
        secondary = "#8992a7"
        bg = "#0A0B0A"
        fg = "#BBBBBB"
        if hasattr(self, "app") and hasattr(self.app, "current_theme") and self.app.current_theme:
            theme = self.app.current_theme
            primary = getattr(theme, "primary", None) or primary
            secondary = getattr(theme, "secondary", None) or secondary
            bg = getattr(theme, "background", None) or bg
            fg = getattr(theme, "foreground", None) or fg

        t = Text()
        t.append(" ICHNOS ", style=f"bold {bg} on {primary}")
        t.append(f" v{__version__}", style=f"bold {fg}")
        t.append(" │ ", style="dim")
        t.append("Security Research & CTF Terminal", style=f"{secondary}")
        return t
