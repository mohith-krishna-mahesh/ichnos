"""Web application reconnaissance sub-app."""

from __future__ import annotations

from pathlib import Path

import typer

import ichnos.web.extract as extract_mod
import ichnos.web.fuzz as fuzz_mod
import ichnos.web.headers as headers_mod
from ichnos.cli.state import state
from ichnos.core.input import read_input
from ichnos.core.models import Result
from ichnos.core.output import print_error, render

app = typer.Typer(no_args_is_help=True)


@app.command("headers")
def cmd_headers(
    url: str = typer.Argument(..., help="Target URL (e.g. https://example.com)"),
    timeout: float = typer.Option(5.0, "--timeout", "-t", help="Request timeout"),
):
    """Audits HTTP response security headers (HSTS, CSP, X-Frame-Options, CORS)."""
    try:
        report = headers_mod.fetch_and_audit(url, timeout=timeout)
        res = Result(raw_output=report)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


app.command("audit-headers", hidden=True)(cmd_headers)


@app.command("fuzz")
def cmd_fuzz(
    url: str = typer.Argument(..., help="Base URL (e.g. https://example.com)"),
    wordlist: str = typer.Option(..., "--wordlist", "-w", help="Path to dictionary wordlist"),
    status: str | None = typer.Option(
        None, "--status", "-s", help="Comma-separated status codes to show (e.g. 200,301,302)"
    ),
    workers: int = typer.Option(10, "--workers", help="Concurrent threads"),
    timeout: float = typer.Option(3.0, "--timeout", "-t", help="Timeout per request"),
):
    """Concurrently probes endpoints and directories against base URL."""
    try:
        w_path = Path(wordlist)
        if not w_path.exists():
            raise FileNotFoundError(f"Wordlist '{wordlist}' not found")

        paths = [
            line.strip()
            for line in w_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.strip()
        ]
        allowed_statuses = [int(s.strip()) for s in status.split(",")] if status else None

        results = fuzz_mod.fuzz_paths(
            base_url=url,
            wordlist=paths,
            allowed_status=allowed_statuses,
            max_workers=workers,
            timeout=timeout,
        )
        res = Result(raw_output={"base_url": url, "count": len(results), "endpoints": results})
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("extract")
def cmd_extract(
    source: str | None = typer.Argument(None, help="HTML file path or raw HTML string"),
):
    """Extracts links, scripts, comments, forms, and emails from HTML."""
    try:
        inp = read_input(source)
        html_str = inp.data.decode("utf-8", errors="replace")
        extracted = extract_mod.extract_assets(html_str)
        res = Result(raw_output=extracted)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))
