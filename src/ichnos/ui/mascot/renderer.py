"""Terminal-safe renderer for Mascot frames with responsive viewport support."""

from __future__ import annotations

from rich.align import Align
from rich.text import Text

from ichnos.ui.mascot.frames import MascotFrame


class MascotRenderer:
    """Renders MascotFrame objects to Rich/Textual renderables with responsive degradation."""

    COMPACT_WIDTH_THRESHOLD = 66

    def __init__(self, default_style: str = "") -> None:
        self.default_style = default_style

    def render(
        self,
        frame: MascotFrame | str,
        viewport_width: int = 100,
        viewport_height: int = 25,
        style_override: str | None = None,
    ) -> Align:
        """Renders the frame, choosing full or compact representation based on viewport width.

        Returns an Align.center instance suitable for Textual Static/Widget update().
        """
        compact_lines = getattr(frame, "compact_lines", None)
        use_compact = viewport_width < self.COMPACT_WIDTH_THRESHOLD and compact_lines is not None

        if use_compact and compact_lines:
            raw_text = "\n".join(compact_lines)
        elif hasattr(frame, "raw_ansi"):
            raw_text = frame.raw_ansi
        else:
            raw_text = str(frame)

        # Parse truecolor ANSI escapes into styled Rich Text with no wrapping
        rich_text = Text.from_ansi(raw_text, no_wrap=True, overflow="crop")
        return Align.center(rich_text)

    def get_preferred_dimensions(
        self, frame: MascotFrame | str, viewport_width: int
    ) -> tuple[int, int]:
        """Returns (width, height) for layout sizing calculations."""
        compact_lines = getattr(frame, "compact_lines", None)
        use_compact = viewport_width < self.COMPACT_WIDTH_THRESHOLD and compact_lines is not None
        if use_compact and compact_lines:
            compact_width = getattr(
                frame, "compact_width", max(len(line) for line in compact_lines)
            )
            return compact_width, len(compact_lines)
        width = getattr(frame, "width", 88)
        height = getattr(frame, "height", 24)
        return width, height
