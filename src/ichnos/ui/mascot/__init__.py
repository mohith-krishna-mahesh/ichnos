"""Ichnos Terminal Mascot & Animation System."""

from ichnos.ui.mascot.animation import MascotAnimation
from ichnos.ui.mascot.frames import (
    IDLE_FRAMES,
    SCANNING_FRAMES,
    STARTUP_FRAMES,
    MascotFrame,
    MascotState,
    get_frames_for_state,
)
from ichnos.ui.mascot.renderer import MascotRenderer
from ichnos.ui.mascot.widget import MascotWidget

__all__ = [
    "MascotState",
    "MascotFrame",
    "MascotRenderer",
    "MascotAnimation",
    "MascotWidget",
    "STARTUP_FRAMES",
    "IDLE_FRAMES",
    "SCANNING_FRAMES",
    "get_frames_for_state",
]
