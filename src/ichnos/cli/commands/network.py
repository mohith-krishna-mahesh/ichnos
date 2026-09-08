"""Network reconnaissance sub-app."""

from __future__ import annotations

import typer

import ichnos.network.banner as banner_mod
import ichnos.network.scanner as scanner_mod
import ichnos.network.tls as tls_mod
from ichnos.cli.state import state
from ichnos.core.models import Result
from ichnos.core.output import print_error, render

app = typer.Typer(no_args_is_help=True)


@app.command("scan")
def cmd_scan(
    host: str = typer.Argument(..., help="Target IP or hostname"),
    ports: str | None = typer.Option(
        None, "--ports", "-p", help="Port specification, e.g. '80,443,8000-8080'"
    ),
    timeout: float = typer.Option(0.5, "--timeout", "-t", help="Timeout per port probe in seconds"),
    workers: int = typer.Option(50, "--workers", "-w", help="Concurrent worker threads"),
):
    """Scans TCP ports on target host."""
    try:
        results = scanner_mod.scan_ports(host, ports=ports, timeout=timeout, max_workers=workers)
        res = Result(raw_output={"host": host, "open_ports": results, "count": len(results)})
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("banner")
def cmd_banner(
    host: str = typer.Argument(..., help="Target IP or hostname"),
    port: int = typer.Argument(..., help="Port number"),
    timeout: float = typer.Option(2.0, "--timeout", "-t", help="Timeout in seconds"),
):
    """Grabs service banner from open port."""
    try:
        banner = banner_mod.grab_banner(host, port, timeout=timeout)
        res = Result(raw_output={"host": host, "port": port, "banner": banner})
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("tls")
def cmd_tls(
    host: str = typer.Argument(..., help="Target hostname"),
    port: int = typer.Option(443, "--port", "-p", help="TLS port"),
    timeout: float = typer.Option(3.0, "--timeout", "-t", help="Connection timeout"),
):
    """Inspects TLS/SSL certificate, cipher suite, and validity."""
    try:
        cert_info = tls_mod.inspect_tls(host, port=port, timeout=timeout)
        res = Result(raw_output=cert_info)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))
