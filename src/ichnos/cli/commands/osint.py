"""Open-source intelligence sub-app."""

from __future__ import annotations

from pathlib import Path

import typer

import ichnos.osint.dns_lookup as dns_mod
import ichnos.osint.subdomains as subdomains_mod
import ichnos.osint.whois as whois_mod
from ichnos.cli.state import state
from ichnos.core.models import Result
from ichnos.core.output import print_error, render

app = typer.Typer(no_args_is_help=True)


@app.command("dns")
def cmd_dns(
    domain: str = typer.Argument(..., help="Target domain (e.g. example.com)"),
    types: str | None = typer.Option(
        None, "--types", "-t", help="Comma-separated DNS record types (A,AAAA,MX,TXT,NS)"
    ),
):
    """Resolves DNS records using DNS-over-HTTPS (DoH)."""
    try:
        req_types = [t.strip().upper() for t in types.split(",")] if types else None
        res_data = dns_mod.resolve_domain(domain, record_types=req_types)
        res = Result(raw_output=res_data)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("whois")
def cmd_whois(
    domain: str = typer.Argument(..., help="Target domain (e.g. example.com)"),
    timeout: float = typer.Option(5.0, "--timeout", "-t", help="WHOIS query timeout"),
):
    """Queries WHOIS registry information via direct socket port 43."""
    try:
        info = whois_mod.lookup_whois(domain, timeout=timeout)
        res = Result(raw_output=info)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("subdomains")
def cmd_subdomains(
    domain: str = typer.Argument(..., help="Target domain (e.g. example.com)"),
    crt: bool = typer.Option(
        True, "--crt/--no-crt", help="Query crt.sh Certificate Transparency logs"
    ),
    wordlist: str | None = typer.Option(
        None, "--wordlist", "-w", help="Path to dictionary wordlist for brute-forcing"
    ),
    workers: int = typer.Option(20, "--workers", help="Concurrent threads"),
):
    """Discovers subdomains through Certificate Transparency logs and brute-forcing."""
    try:
        w_list = None
        if wordlist:
            w_path = Path(wordlist)
            if w_path.exists():
                w_list = [
                    line.strip()
                    for line in w_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                    if line.strip()
                ]

        found = subdomains_mod.enumerate_subdomains(
            domain, wordlist=w_list, use_crt=crt, max_workers=workers
        )
        res = Result(raw_output={"domain": domain, "count": len(found), "subdomains": found})
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))
