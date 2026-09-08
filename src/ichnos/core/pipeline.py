"""Pipeline utilities — stdin/stdout piping contract between commands."""

from __future__ import annotations

import sys


def is_stdin_piped() -> bool:
    """Check if stdin has piped data (not a TTY)."""
    return not sys.stdin.isatty()


def is_stdout_piped() -> bool:
    """Check if stdout is being piped to another command."""
    return not sys.stdout.isatty()


def pipe_input() -> bytes | None:
    """Read all available stdin data if piped, otherwise return None."""
    if is_stdin_piped():
        return sys.stdin.buffer.read()
    return None


def pipe_output(data: str | bytes) -> None:
    """Write data to stdout for piping to the next command."""
    if isinstance(data, bytes):
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    else:
        sys.stdout.write(data)
        sys.stdout.flush()
