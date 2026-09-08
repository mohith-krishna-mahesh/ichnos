"""Terminal-native Unicode mascot frames for Ichnos.

Uses truecolor ANSI escape sequences and block characters provided for Ichnos baby-cyclops mascot.
"""

from __future__ import annotations

import re
from enum import Enum

from ichnos.ui.mascot.raw_frames import (
    BLINK as RAW_BLINK,
)
from ichnos.ui.mascot.raw_frames import (
    IDLE as RAW_IDLE,
)
from ichnos.ui.mascot.raw_frames import (
    get_themed_ansi,
)

# Re-export raw strings
IDLE: str = RAW_IDLE
BLINK: str = RAW_BLINK


class MascotState(str, Enum):
    """Supported mascot animation and lifecycle states."""

    STARTUP = "startup"
    IDLE = "idle"
    SCANNING = "scanning"
    BLINK = "blink"
    FOUND = "found"
    ERROR = "error"
    SUCCESS = "success"
    THINKING = "thinking"


class MascotFrame(str):
    """Single terminal animation frame wrapping ANSI truecolor string with metadata.

    Subclasses str so that frames compare equal to their raw ANSI strings
    while exposing properties for width, height, duration, and lines.
    """

    description: str
    duration: float
    compact_lines: list[str] | None
    metadata: dict[str, str]

    def __new__(
        cls,
        raw_ansi: str,
        description: str = "",
        duration: float = 0.20,
        compact_lines: list[str] | None = None,
        metadata: dict[str, str] | None = None,
    ) -> MascotFrame:
        obj = super().__new__(cls, raw_ansi)
        obj.description = description
        obj.duration = duration
        obj.compact_lines = compact_lines
        obj.metadata = metadata or {}
        return obj

    @property
    def raw_ansi(self) -> str:
        """Returns the raw ANSI truecolor string."""
        return str(self)

    @property
    def lines(self) -> list[str]:
        """Returns individual lines of the frame."""
        return self.split("\n")

    @property
    def height(self) -> int:
        """Number of vertical rows in the frame."""
        return len(self.lines)

    @property
    def width(self) -> int:
        """Maximum visual character width stripping ANSI escape codes."""
        ansi_regex = re.compile(r"\x1b\[[0-9;]*[mK]")
        return max((len(ansi_regex.sub("", line)) for line in self.lines), default=0)

    @property
    def compact_width(self) -> int:
        """Width of compact representation if present, otherwise full width."""
        if not self.compact_lines:
            return self.width
        ansi_regex = re.compile(r"\x1b\[[0-9;]*[mK]")
        return max((len(ansi_regex.sub("", line)) for line in self.compact_lines), default=0)


# Standard frame instances with durations
FRAME_IDLE = MascotFrame(IDLE, description="idle", duration=0.20)
FRAME_BLINK = MascotFrame(BLINK, description="blink", duration=0.15)

IDLE_FRAME_MAIN = FRAME_IDLE
IDLE_FRAMES: list[MascotFrame] = [FRAME_IDLE]

STARTUP_FRAMES: list[MascotFrame] = [
    MascotFrame(IDLE, description="startup_idle_1", duration=0.25),
    MascotFrame(BLINK, description="startup_blink", duration=0.15),
    MascotFrame(IDLE, description="startup_idle_2", duration=0.25),
]

SCANNING_FRAMES: list[MascotFrame] = [
    MascotFrame(IDLE, description="scanning_idle_1", duration=0.30),
    MascotFrame(BLINK, description="scanning_blink", duration=0.15),
    MascotFrame(IDLE, description="scanning_idle_2", duration=0.30),
]

ANIMATIONS: dict[str, list[MascotFrame]] = {
    "idle": [FRAME_IDLE],
    "blink": [FRAME_IDLE, FRAME_BLINK, FRAME_IDLE],
    "scanning": SCANNING_FRAMES,
}


def get_frames_for_state(
    state: MascotState | str, theme_name: str | None = None
) -> list[MascotFrame]:
    """Returns the frame list for the specified MascotState, optionally themed."""
    if theme_name is None or theme_name == "hacker":
        if state == MascotState.STARTUP:
            return list(STARTUP_FRAMES)
        elif state == MascotState.SCANNING:
            return list(SCANNING_FRAMES)
        elif state == MascotState.BLINK:
            return list(ANIMATIONS["blink"])
        elif state == MascotState.IDLE:
            return list(IDLE_FRAMES)
        return list(IDLE_FRAMES)

    idle_ansi = get_themed_ansi("idle", theme_name=theme_name)
    blink_ansi = get_themed_ansi("blink", theme_name=theme_name)
    themed_idle = MascotFrame(idle_ansi, description="idle", duration=0.20)
    themed_blink = MascotFrame(blink_ansi, description="blink", duration=0.15)

    if state == MascotState.STARTUP:
        return [
            MascotFrame(idle_ansi, description="startup_idle_1", duration=0.25),
            MascotFrame(blink_ansi, description="startup_blink", duration=0.15),
            MascotFrame(idle_ansi, description="startup_idle_2", duration=0.25),
        ]
    elif state == MascotState.SCANNING:
        return [
            MascotFrame(idle_ansi, description="scanning_idle_1", duration=0.30),
            MascotFrame(blink_ansi, description="scanning_blink", duration=0.15),
            MascotFrame(idle_ansi, description="scanning_idle_2", duration=0.30),
        ]
    elif state == MascotState.BLINK:
        return [themed_idle, themed_blink, themed_idle]
    elif state == MascotState.IDLE:
        return [themed_idle]

    return [themed_idle]
