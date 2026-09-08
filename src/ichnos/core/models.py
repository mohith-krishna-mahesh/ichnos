"""Pydantic data models used across all Ichnos modules."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class SourceType(str, Enum):
    """How the input was provided."""

    FILE = "file"
    STDIN = "stdin"
    RAW = "raw"
    DIRECTORY = "directory"


class Input(BaseModel):
    """Normalized input abstraction — every command receives one of these."""

    data: bytes
    source_type: SourceType
    detected_type: str = "unknown"
    path: Path | None = None
    filename: str | None = None

    @property
    def text(self) -> str:
        """Best-effort UTF-8 decode of the raw data."""
        return self.data.decode("utf-8", errors="replace")

    @property
    def size(self) -> int:
        return len(self.data)

    model_config = {"arbitrary_types_allowed": True}


class DeductionStep(BaseModel):
    """A single atomic step in an analytical or solver deduction trail."""

    label: str
    detail: str = ""
    intermediate_values: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""

    model_config = {"arbitrary_types_allowed": True}


class Finding(BaseModel):
    """A single detection / analysis result."""

    label: str
    confidence: float = Field(ge=0.0, le=1.0)
    detail: str = ""
    module: str = ""
    command_hint: str | None = None
    steps: list[DeductionStep] = Field(default_factory=list)
    learner_note: str = ""

    def __lt__(self, other: Finding) -> bool:
        return self.confidence < other.confidence


class Candidate(BaseModel):
    """A decoded / cracked candidate output."""

    decoded: str | bytes = ""
    method: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    layers: list[str] = Field(default_factory=list)
    key: str | int | None = None
    steps: list[DeductionStep] = Field(default_factory=list)
    learner_note: str = ""

    @property
    def decoded_str(self) -> str:
        if isinstance(self.decoded, bytes):
            return self.decoded.decode("utf-8", errors="replace")
        return self.decoded

    def __getitem__(self, item: str) -> Any:
        if item == "encoding":
            return self.method
        if item == "data":
            return self.decoded
        return getattr(self, item)

    model_config = {"arbitrary_types_allowed": True}


class Result(BaseModel):
    """Aggregated output from any command — wraps findings + raw data."""

    findings: list[Finding] = Field(default_factory=list)
    raw_output: Any = None
    input_summary: str | dict[str, Any] = ""
    candidates: list[Candidate] = Field(default_factory=list)
    status: str = "success"
    command: str = ""
    steps: list[DeductionStep] = Field(default_factory=list)
    learner_note: str = ""

    @property
    def top_finding(self) -> Finding | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.confidence)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.confidence, reverse=True)
