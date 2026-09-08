"""Pydantic state model for the Ichnos interactive terminal session."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field

from ichnos.core.models import Candidate, Input, Result

DEFAULT_CONFIG_DIR = Path(
    os.environ.get("ICHNOS_CONFIG_DIR", str(Path.home() / ".config" / "ichnos"))
)
DEFAULT_HISTORY_FILE = Path(
    os.environ.get("ICHNOS_HISTORY_FILE", str(DEFAULT_CONFIG_DIR / "history"))
)
DEFAULT_SCRATCH_DIR = Path(
    os.environ.get("ICHNOS_SCRATCH_DIR", str(DEFAULT_CONFIG_DIR / "scratch"))
)


class UIState(BaseModel):
    """Holds active session state, loaded inputs, results, and history."""

    model_config = {"arbitrary_types_allowed": True}

    command_history: list[str] = Field(default_factory=list)
    loaded_inputs: list[Input] = Field(default_factory=list)
    active_input: Input | None = None
    result_history: list[Result] = Field(default_factory=list)
    active_result: Result | None = None
    selected_candidate: Candidate | None = None
    running_operation: str | None = None
    current_screen: str = "startup"
    status_message: str = "Ready"
    mode: str = "expert"  # "learner" or "expert"

    def set_active_input(self, inp: Input) -> None:
        self.active_input = inp
        if inp not in self.loaded_inputs:
            self.loaded_inputs.append(inp)

    def add_result(self, res: Result) -> None:
        self.active_result = res
        self.result_history.append(res)
        if res.candidates:
            self.selected_candidate = res.candidates[0]
        else:
            self.selected_candidate = None

    def add_command(self, cmd: str) -> None:
        trimmed = cmd.strip()
        if trimmed and (not self.command_history or self.command_history[-1] != trimmed):
            self.command_history.append(trimmed)
            self._persist_history_line(trimmed)

    def load_history(self) -> None:
        try:
            if DEFAULT_HISTORY_FILE.exists():
                lines = [
                    line.strip()
                    for line in DEFAULT_HISTORY_FILE.read_text(
                        encoding="utf-8", errors="ignore"
                    ).splitlines()
                    if line.strip()
                ]
                self.command_history = lines[-1000:]
        except Exception:
            pass

    def _persist_history_line(self, line: str) -> None:
        try:
            DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            with open(DEFAULT_HISTORY_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass
