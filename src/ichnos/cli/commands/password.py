"""Password cracking and wordlist sub-app."""

from __future__ import annotations

from pathlib import Path

import typer

import ichnos.password.crack as crack_mod
import ichnos.password.mutator as mutator_mod
import ichnos.password.wordlist as wordlist_mod
from ichnos.cli.state import state
from ichnos.core.models import Result
from ichnos.core.output import print_error, print_success, render

app = typer.Typer(no_args_is_help=True)


@app.command("mutate")
def cmd_mutate(
    word: str = typer.Argument(..., help="Base password to mutate"),
    leet: bool = typer.Option(True, "--leet/--no-leet", help="Apply leetspeak rules"),
    casing: bool = typer.Option(True, "--casing/--no-casing", help="Apply casing permutations"),
    affixes: bool = typer.Option(
        True, "--affixes/--no-affixes", help="Apply prefix/suffix additions"
    ),
):
    """Generates rule-based mutations of a password (Hashcat/John-style)."""
    try:
        mutations = mutator_mod.mutate_word(
            word, include_leet=leet, include_casing=casing, include_affixes=affixes
        )
        res = Result(raw_output={"base": word, "count": len(mutations), "mutations": mutations})
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("generate")
def cmd_generate(
    words: str = typer.Option(..., "--words", "-W", help="Comma-separated base words"),
    suffixes: str = typer.Option("!,123,2024", "--suffixes", "-s", help="Comma-separated suffixes"),
    delimiter: str = typer.Option(
        "", "--delimiter", "-d", help="Delimiter between combined elements"
    ),
):
    """Generates combined candidate wordlist from base words and suffixes."""
    try:
        w_list = [w.strip() for w in words.split(",") if w.strip()]
        s_list = [s.strip() for s in suffixes.split(",") if s.strip()]
        combined = wordlist_mod.combine_lists([w_list, s_list], delimiter=delimiter)
        res = Result(raw_output={"count": len(combined), "wordlist": combined})
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))


@app.command("crack")
def cmd_crack(
    target_hash: str = typer.Argument(..., help="Hash to crack"),
    wordlist: str = typer.Option(..., "--wordlist", "-w", help="Path to dictionary wordlist"),
    algo: str = typer.Option(
        "auto", "--algo", "-a", help="Algorithm: auto, md5, sha1, sha256, sha512, ntlm"
    ),
    mutate: bool = typer.Option(
        False, "--mutate", "-m", help="Apply rule mutations to wordlist candidates"
    ),
):
    """Cracks password hashes (MD5, SHA1, SHA256, SHA512, NTLM) using dictionary and rules."""
    try:
        w_path = Path(wordlist)
        if not w_path.exists():
            raise FileNotFoundError(f"Wordlist '{wordlist}' not found")

        words = [
            line.strip()
            for line in w_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.strip()
        ]
        cracked = crack_mod.crack_hash(target_hash, words, algorithm=algo, apply_rules=mutate)

        if cracked:
            print_success(f"Hash cracked: {cracked}")
            res = Result(raw_output={"hash": target_hash, "cracked": True, "plaintext": cracked})
        else:
            res = Result(raw_output={"hash": target_hash, "cracked": False, "plaintext": None})
        render(res, state.json_mode)
    except Exception as e:
        print_error(str(e))
