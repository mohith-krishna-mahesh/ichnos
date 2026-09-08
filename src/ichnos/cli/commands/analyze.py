"""Analyze command."""

import typer

import ichnos.binary.analyzers  # noqa: F401

# Import analyzers to trigger registration
import ichnos.crypto.analyzers  # noqa: F401
import ichnos.encoding.analyzers  # noqa: F401
import ichnos.forensic.analyzers  # noqa: F401
import ichnos.stego.analyzers  # noqa: F401
from ichnos.cli.state import state
from ichnos.core.input import read_input
from ichnos.core.models import Result
from ichnos.core.output import print_error, render
from ichnos.core.registry import registry

app = typer.Typer()


@app.callback(invoke_without_command=True)
def analyze(input_data: str | None = typer.Argument(None)):
    """Analyze input automatically."""
    try:
        inp = read_input(input_data)
        findings = registry.query_all(inp)

        result = Result(
            findings=findings,
            raw_output=None,
            input_summary={"size": len(inp.data), "type": inp.detected_type},
            candidates=[],
        )
        render(result, state.json_mode)
    except Exception as e:
        print_error(str(e))
