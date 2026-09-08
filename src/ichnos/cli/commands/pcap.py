"""Packet capture analysis sub-app."""

from __future__ import annotations

import typer

import ichnos.pcap.credentials as creds_mod
import ichnos.pcap.dns as dns_mod
import ichnos.pcap.flows as flows_mod
import ichnos.pcap.http as http_mod
import ichnos.pcap.parser as parser_mod
from ichnos.cli.state import state
from ichnos.core.input import read_input
from ichnos.core.models import Result
from ichnos.core.output import print_error, render

app = typer.Typer(no_args_is_help=True)


@app.command("summary")
def cmd_summary(file: str | None = typer.Argument(None)):
    """Provides high-level capture statistics: packet counts, protocols, time span."""
    try:
        inp = read_input(file)
        packets = parser_mod.read_pcap(inp.data)

        if not packets:
            render(Result(raw_output={"packets": 0}), state.json_mode)
            return

        protocols: dict[str, int] = {}
        ip_endpoints: set[str] = set()
        total_bytes = sum(p.length for p in packets)
        start_t = min(p.timestamp for p in packets)
        end_t = max(p.timestamp for p in packets)

        for p in packets:
            proto = p.protocol or "Unknown"
            protocols[proto] = protocols.get(proto, 0) + 1
            if p.ip_src:
                ip_endpoints.add(p.ip_src)
            if p.ip_dst:
                ip_endpoints.add(p.ip_dst)

        summary = {
            "packet_count": len(packets),
            "total_bytes": total_bytes,
            "duration_seconds": round(end_t - start_t, 4),
            "start_time": start_t,
            "end_time": end_t,
            "protocols": protocols,
            "unique_ip_endpoints": len(ip_endpoints),
        }
        res = Result(raw_output=summary)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("flows")
def cmd_flows(file: str | None = typer.Argument(None)):
    """Extracts bidirectional communication flows, conversations, and volume metrics."""
    try:
        inp = read_input(file)
        packets = parser_mod.read_pcap(inp.data)
        flows = flows_mod.extract_flows(packets)
        res = Result(raw_output=flows)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("dns")
def cmd_dns(file: str | None = typer.Argument(None)):
    """Extracts DNS query records and hostname lookups."""
    try:
        inp = read_input(file)
        packets = parser_mod.read_pcap(inp.data)
        queries = dns_mod.extract_dns_queries(packets)
        res = Result(raw_output=queries)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("credentials")
def cmd_credentials(file: str | None = typer.Argument(None)):
    """Extracts plaintext credentials (HTTP Basic, FTP, form POST parameters)."""
    try:
        inp = read_input(file)
        packets = parser_mod.read_pcap(inp.data)
        creds = creds_mod.extract_credentials(packets)
        res = Result(raw_output=creds)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("http")
def cmd_http(file: str | None = typer.Argument(None)):
    """Reconstructs plaintext HTTP requests and responses."""
    try:
        inp = read_input(file)
        packets = parser_mod.read_pcap(inp.data)
        messages = http_mod.reconstruct_http(packets)
        res = Result(raw_output=messages)
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))
