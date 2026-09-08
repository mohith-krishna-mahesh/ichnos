"""Autonomous CTF challenge solver command."""

from __future__ import annotations

import sys

import typer
from rich.console import Console

from ichnos.cli.state import state
from ichnos.core.output import print_error, render
from ichnos.core.solver import AutoSolver

app = typer.Typer()
console = Console()


@app.callback(invoke_without_command=True)
def solve(
    targets: list[str] | None = typer.Argument(
        None,
        help="Challenge files, directories, or raw text to analyze and solve.",
    ),
) -> None:
    """Ingests challenge files or text, harvests parameters, and executes deterministic attacks."""
    try:
        active_text = None
        # If no target specified and stdin is piped
        if not targets and not sys.stdin.isatty():
            active_text = sys.stdin.read()

        trace, result = AutoSolver.solve(targets=targets, active_text=active_text)

        if state.json_mode:
            render(result, json_mode=True)
        else:
            # Print the formatted stepwise deduction trace
            console.print(trace.render_text())

    except Exception as e:
        print_error(f"Solver failed: {e}")
