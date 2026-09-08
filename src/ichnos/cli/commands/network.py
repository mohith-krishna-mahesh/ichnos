"""Network reconnaissance sub-app."""

from __future__ import annotations

import typer

import ichnos.network.banner as banner_mod
import ichnos.network.oracle as oracle_mod
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


@app.command("oracle-crack")
def cmd_oracle_crack(
    url: str = typer.Option(..., "--url", help="Target oracle API URL"),
    token: str | None = typer.Option(None, "--token", help="Bearer authorization token"),
    length: int = typer.Option(16, "--length", "-l", help="Expected secret length in bytes"),
    batch_size: int = typer.Option(16, "--batch-size", "-b", help="Guesses per request batch"),
    template: str = typer.Option(
        oracle_mod.DEFAULT_PROGRAM_TEMPLATE,
        "--template",
        help="Program format string with {addr} and {guess}",
    ),
    success_value: str = typer.Option("HALTED", "--success-value", help="Response value indicating success"),
    success_key: str | None = typer.Option(None, "--success-key", help="JSON field containing the response value"),
    request_key: str = typer.Option("programs", "--request-key", help="JSON key for programs"),
    response_key: str = typer.Option("results", "--response-key", help="JSON key for results"),
    submit_key: str = typer.Option("key", "--submit-key", help="JSON key for submission"),
    workers: int = typer.Option(1, "--workers", "-w", help="Concurrent worker threads across addresses"),
    resume_file: str | None = typer.Option(None, "--resume-file", help="Path to checkpoint progress JSON"),
    submit: bool = typer.Option(False, "--submit", help="Submit secret to endpoint on finish"),
):
    """Recover an unknown byte sequence from a remote side-channel / error oracle."""
    try:
        client = oracle_mod.OracleClient(
            url=url,
            token=token,
            request_key=request_key,
            response_key=response_key,
            submit_key=submit_key,
        )
        resume = oracle_mod.ResumeState(resume_file) if resume_file else None
        result = oracle_mod.recover_secret(
            client=client,
            length=length,
            batch_size=batch_size,
            program_template=template,
            success_value=success_value,
            success_key=success_key,
            workers=workers,
            resume=resume,
            submit_on_finish=submit,
        )
        raw = {
            "success": True,
            "secret_hex": result.secret_hex,
            "recovered_count": result.recovered_count,
            "total_length": result.total_length,
            "submit_response": result.submit_response,
        }
        res = Result(raw_output=raw)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))

