"""Output rendering — Rich human view or JSON, shared across every command."""

from __future__ import annotations

import json
import sys
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ichnos.core.models import Candidate, Finding, Result
from ichnos.core.pipeline import is_stdout_piped
from ichnos.core.security import sanitize_terminal_output

# Human-readable output goes to stderr so stdout stays clean for piping
_console = Console(stderr=True)
_stdout = Console(file=sys.stdout)


def _confidence_color(confidence: float) -> str:
    if confidence >= 0.8:
        return "bold green"
    if confidence >= 0.5:
        return "yellow"
    if confidence >= 0.3:
        return "dim yellow"
    return "dim red"


def _confidence_bar(confidence: float, width: int = 10) -> str:
    filled = round(confidence * width)
    return "█" * filled + "░" * (width - filled)


def render(result: Result, json_mode: bool = False) -> None:
    """Render a Result to the terminal — Rich table or JSON."""
    if json_mode:
        _render_json(result)
    else:
        _render_human(result)


def _render_json(result: Result) -> None:
    """Write JSON to stdout for piping."""
    output: dict[str, Any] = {
        "input_summary": result.input_summary,
        "findings": [f.model_dump() for f in result.sorted_findings()],
    }
    if result.candidates:
        serialized_candidates = []
        for c in result.candidates:
            cd = c.model_dump()
            if isinstance(cd.get("decoded"), (bytes, bytearray)):
                try:
                    cd["decoded"] = cd["decoded"].decode("utf-8")
                except UnicodeDecodeError:
                    cd["decoded"] = cd["decoded"].decode("latin-1")
            serialized_candidates.append(cd)
        output["candidates"] = serialized_candidates

    if result.raw_output is not None:
        if isinstance(result.raw_output, (bytes, bytearray)):
            try:
                output["raw_output"] = result.raw_output.decode("utf-8")
            except UnicodeDecodeError:
                output["raw_output"] = result.raw_output.decode("latin-1")
        else:
            try:
                json.dumps(result.raw_output)
                output["raw_output"] = result.raw_output
            except (TypeError, ValueError):
                output["raw_output"] = str(result.raw_output)
    print(json.dumps(output, indent=2, default=str))


def _render_human(result: Result) -> None:
    """Render Rich-formatted human output to stderr, and pipeable raw output to stdout if piped."""
    piped = is_stdout_piped()

    if result.input_summary:
        summary_text = (
            ", ".join(f"{k}: {v}" for k, v in result.input_summary.items())
            if isinstance(result.input_summary, dict)
            else str(result.input_summary)
        )
        _console.print(Panel(summary_text, title="[bold]Input[/bold]", border_style="blue"))

    if result.findings:
        print_findings(result.findings)

    if result.candidates:
        print_candidates(result.candidates)
        if piped:
            top = max(result.candidates, key=lambda c: c.confidence)
            print_raw(top.decoded)

    if result.raw_output is not None:
        if piped:
            print_raw(result.raw_output)
        else:
            if not result.findings and not result.candidates:
                _console.print()
                raw_str = (
                    result.raw_output
                    if isinstance(result.raw_output, str)
                    else str(result.raw_output)
                )
                _console.print(sanitize_terminal_output(raw_str))


def print_findings(findings: list[Finding]) -> None:
    """Print a sorted table of findings."""
    sorted_findings = sorted(findings, key=lambda f: f.confidence, reverse=True)

    table = Table(title="Findings", show_lines=True)
    table.add_column("Confidence", width=14)
    table.add_column("Module", style="cyan", width=10)
    table.add_column("Label", style="bold")
    table.add_column("Detail")
    table.add_column("Try", style="dim")

    for f in sorted_findings:
        color = _confidence_color(f.confidence)
        conf_text = Text(f"{_confidence_bar(f.confidence)} {f.confidence:.0%}")
        conf_text.stylize(color)
        table.add_row(
            conf_text,
            sanitize_terminal_output(f.module),
            sanitize_terminal_output(f.label),
            sanitize_terminal_output(f.detail),
            sanitize_terminal_output(f.command_hint or ""),
        )

    _console.print(table)


def print_candidates(candidates: list[Candidate], max_display: int = 20) -> None:
    """Print decoded candidates, sorted by confidence."""
    sorted_cands = sorted(candidates, key=lambda c: c.confidence, reverse=True)[:max_display]

    table = Table(title="Candidates", show_lines=True)
    table.add_column("Confidence", width=14)
    table.add_column("Method", style="cyan")
    table.add_column("Key", style="yellow")
    table.add_column("Decoded", max_width=80)

    for c in sorted_cands:
        color = _confidence_color(c.confidence)
        conf_text = Text(f"{_confidence_bar(c.confidence)} {c.confidence:.0%}")
        conf_text.stylize(color)
        decoded_preview = c.decoded_str[:200]
        if len(c.decoded_str) > 200:
            decoded_preview += "…"
        table.add_row(
            conf_text,
            sanitize_terminal_output(c.method),
            sanitize_terminal_output(str(c.key) if c.key is not None else ""),
            sanitize_terminal_output(decoded_preview),
        )

    _console.print(table)

    if c_layers := [c for c in sorted_cands if c.layers]:
        _console.print("\n[dim]Decode chains:[/dim]")
        for c in c_layers:
            _console.print(f"  {sanitize_terminal_output(' → '.join(c.layers))}")


def print_raw(data: str | bytes) -> None:
    """Print raw data to stdout (for piping)."""
    if isinstance(data, bytes):
        sys.stdout.buffer.write(data)
    else:
        print(data, end="")


def print_error(message: str) -> None:
    """Print an error message to stderr."""
    _console.print(f"[bold red]Error:[/bold red] {sanitize_terminal_output(message)}")


def print_success(message: str) -> None:
    """Print a success message to stderr."""
    _console.print(f"[bold green]✓[/bold green] {sanitize_terminal_output(message)}")


def print_info(message: str) -> None:
    """Print an info message to stderr."""
    _console.print(f"[blue]ℹ[/blue] {sanitize_terminal_output(message)}")
