"""Root CLI application."""

import typer

from ichnos import __version__

app = typer.Typer(
    name="ichnos",
    help="Ichnos — A modular CLI security/CTF toolkit.",
    no_args_is_help=False,
    rich_markup_mode="rich",
)

from ichnos.cli.state import state


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Show version and exit."),
    json_output: bool = typer.Option(
        False, "--json", help="Output as JSON instead of human-readable format."
    ),
    theme: str | None = typer.Option(
        None, "--theme", "-t", help="Theme to use for the interactive TUI."
    ),
):
    if version:
        typer.echo(f"ichnos {__version__}")
        raise typer.Exit()
    state.json_mode = json_output

    if ctx.invoked_subcommand is None:
        from ichnos.ui.app import IchnosApp

        app_instance = IchnosApp()
        if theme:
            app_instance.theme = theme
        app_instance.run()
        raise typer.Exit()


# Import commands
from ichnos.cli.commands.analyze import app as analyze_app
from ichnos.cli.commands.binary import app as binary_app
from ichnos.cli.commands.crypto import app as crypto_app
from ichnos.cli.commands.encoding import app as encoding_app
from ichnos.cli.commands.forensic import app as forensic_app
from ichnos.cli.commands.network import app as network_app
from ichnos.cli.commands.osint import app as osint_app
from ichnos.cli.commands.password import app as password_app
from ichnos.cli.commands.pcap import app as pcap_app
from ichnos.cli.commands.reverse import app as reverse_app
from ichnos.cli.commands.solve import app as solve_app
from ichnos.cli.commands.stego import app as stego_app
from ichnos.cli.commands.web import app as web_app

# Register sub-apps
app.add_typer(
    solve_app,
    name="solve",
    help="Autonomously solve CTF challenges across crypto, forensics, and encoding.",
)
app.add_typer(analyze_app, name="analyze", help="Analyze input automatically.")
app.add_typer(crypto_app, name="crypto", help="Cryptography tools.")
app.add_typer(encoding_app, name="encoding", help="Encoding and decoding tools.")
app.add_typer(stego_app, name="stego", help="Steganography tools.")
app.add_typer(binary_app, name="binary", help="Binary analysis tools.")
app.add_typer(forensic_app, name="forensic", help="Forensics tools.")
app.add_typer(reverse_app, name="reverse", help="Reverse engineering tools.")
app.add_typer(pcap_app, name="pcap", help="Packet capture analysis tools.")
app.add_typer(network_app, name="network", help="Network reconnaissance tools.")
app.add_typer(web_app, name="web", help="Web application reconnaissance tools.")
app.add_typer(osint_app, name="osint", help="Open-source intelligence tools.")
app.add_typer(password_app, name="password", help="Password cracking and wordlist tools.")

# Import analyzers to trigger registry


def app_entry():
    app()
