"""Wordlist management and retrieval sub-app."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from ichnos.cli.state import state
from ichnos.core.models import Result
from ichnos.core.output import print_error, print_info, print_success, render
from ichnos.password.wordlists import (
    WORDLIST_BUNDLES,
    WORDLIST_REGISTRY,
    fetch_bundle,
    fetch_wordlist,
    list_wordlists,
    resolve_wordlist,
)

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("list")
def cmd_list():
    """Lists available, installed, and system wordlists."""
    items = list_wordlists()
    if state.json_mode:
        render(Result(raw_output=items), json_mode=True)
        return

    table = Table(title="Ichnos Wordlists Repository", header_style="bold cyan")
    table.add_column("Key", style="bold green", no_wrap=True)
    table.add_column("Category", style="magenta")
    table.add_column("Size", style="yellow")
    table.add_column("Status", style="bold")
    table.add_column("Resolved Path", style="dim")

    for item in items:
        status = "[green]Installed[/green]" if item["installed"] else (
            "[cyan]System[/cyan]" if item["path"] else "[red]Available (remote)[/red]"
        )
        resolved = item["path"] or f"run: ichnos wordlists fetch {item['key']}"
        table.add_row(item["key"], item["category"], item["size"], status, resolved)

    console.print(table)
    console.print(
        "\n[bold yellow]Tip:[/bold yellow] Download common CTF wordlists via: "
        "[bold cyan]ichnos wordlists fetch ctf-starter[/bold cyan]"
    )


@app.command("fetch")
def cmd_fetch(
    name: str = typer.Argument(
        ...,
        help="Wordlist key (e.g. rockyou, raft-large) or bundle name (ctf-starter, all)",
    ),
):
    """Downloads and extracts a wordlist or curated bundle into the user config directory."""
    try:
        if name in WORDLIST_BUNDLES:
            print_info(f"Fetching bundle '{name}' ({len(WORDLIST_BUNDLES[name])} wordlists)...")
            paths = fetch_bundle(name)
            print_success(f"Successfully fetched bundle '{name}':")
            for p in paths:
                console.print(f"  • {p}")
            if state.json_mode:
                render(Result(raw_output={"bundle": name, "paths": [str(p) for p in paths]}), True)
        elif name in WORDLIST_REGISTRY:
            print_info(f"Fetching wordlist '{name}'...")
            path = fetch_wordlist(name)
            print_success(f"Successfully downloaded '{name}' to: {path}")
            if state.json_mode:
                render(Result(raw_output={"key": name, "path": str(path)}), True)
        else:
            available = list(WORDLIST_REGISTRY.keys()) + list(WORDLIST_BUNDLES.keys())
            print_error(f"Unknown wordlist or bundle '{name}'. Available options: {', '.join(available)}")
    except Exception as e:
        print_error(f"Download failed: {e}")


@app.command("path")
def cmd_path(
    name: str = typer.Argument(
        "rockyou.txt",
        help="Wordlist filename or key to resolve",
    ),
):
    """Resolves and prints the filesystem path to a wordlist."""
    # Check if name is a registry key
    if name in WORDLIST_REGISTRY:
        filename = WORDLIST_REGISTRY[name].filename
    else:
        filename = name

    path = resolve_wordlist(preferred_name=filename)
    if path:
        if state.json_mode:
            render(Result(raw_output={"target": name, "path": str(path)}), True)
        else:
            console.print(str(path))
    else:
        print_error(f"Wordlist '{name}' could not be found locally or on the system.")
        console.print(f"To download it, run: ichnos wordlists fetch {name}")
