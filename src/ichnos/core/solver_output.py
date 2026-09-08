"""Stepwise deduction trace and proof-of-exploit report models for the CTF solver."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SolverStep:
    """A single atomic step or deduction in the solver pipeline."""

    phase: str
    title: str
    details: list[str] = field(default_factory=list)
    status: str = "success"  # success, info, failed, warning


@dataclass
class DeductionTrace:
    """Complete auditable trace of all deductions, parameters, and attacks executed."""

    steps: list[SolverStep] = field(default_factory=list)
    flag: str | None = None
    solved: bool = False
    attack_name: str = ""
    candidate_plaintexts: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_step(
        self,
        phase: str,
        title: str,
        details: list[str] | str | None = None,
        status: str = "success",
    ) -> SolverStep:
        """Record a step in the trace."""
        if details is None:
            dt_list = []
        elif isinstance(details, str):
            dt_list = [details]
        else:
            dt_list = details
        step = SolverStep(phase=phase, title=title, details=dt_list, status=status)
        self.steps.append(step)
        return step

    def render_text(self) -> str:
        """Render a clean, formatted stepwise report suitable for terminal viewing."""
        lines = []

        # Group steps by phase
        phases: dict[str, list[SolverStep]] = {}
        for s in self.steps:
            phases.setdefault(s.phase, []).append(s)

        phase_num = 1
        for phase_name, phase_steps in phases.items():
            lines.append(f"[{phase_num}. {phase_name.upper()}]")
            for step in phase_steps:
                lines.append(f"  • {step.title}")
                for d in step.details:
                    lines.append(f"    - {d}")
            lines.append("")
            phase_num += 1

        if self.solved and self.flag:
            lines.append("[FINAL RESULT]")
            lines.append(f"  ★ FLAG FOUND: {self.flag}")
            lines.append(f"  ★ Attack:     {self.attack_name}")
        elif self.candidate_plaintexts:
            lines.append("[RECOVERED PLAINTEXT CANDIDATES]")
            for c in self.candidate_plaintexts[:5]:
                lines.append(f"  → {c}")
        else:
            lines.append("[STATUS: NOT SOLVED]")
            lines.append("  No deterministic exploit succeeded with the harvested parameters.")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Convert trace to structured dictionary for JSON reporting."""
        return {
            "solved": self.solved,
            "flag": self.flag,
            "attack_name": self.attack_name,
            "candidate_plaintexts": self.candidate_plaintexts,
            "metadata": self.metadata,
            "steps": [
                {
                    "phase": s.phase,
                    "title": s.title,
                    "details": s.details,
                    "status": s.status,
                }
                for s in self.steps
            ],
        }
