"""Input abstraction — accepts file path, stdin, or raw bytes and normalizes to an Input object."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from ichnos.core.detection import detect_file_type
from ichnos.core.models import Input, SourceType
from ichnos.core.security import DEFAULT_MAX_FILE_READ_SIZE


def _extract_payload_if_json_result(data: bytes) -> bytes:
    """If data is an Ichnos JSON Result, extract its meaningful payload for pipeline chaining."""
    stripped = data.lstrip()
    if not (stripped.startswith(b"{") and stripped.rstrip().endswith(b"}")):
        return data

    try:
        parsed = json.loads(data.decode("utf-8"))
        if not isinstance(parsed, dict):
            return data

        if any(k in parsed for k in ("candidates", "raw_output", "findings")):
            if "raw_output" in parsed and parsed["raw_output"] is not None:
                raw_val = parsed["raw_output"]
                if isinstance(raw_val, str):
                    return raw_val.encode("utf-8")
                elif isinstance(raw_val, (bytes, bytearray)):
                    return bytes(raw_val)
                elif isinstance(raw_val, (int, float, bool)):
                    return str(raw_val).encode("utf-8")
                elif isinstance(raw_val, (list, dict)):
                    return json.dumps(raw_val).encode("utf-8")

            if "candidates" in parsed and parsed["candidates"]:
                top = parsed["candidates"][0]
                if isinstance(top, dict) and "decoded" in top:
                    dec = top["decoded"]
                    if isinstance(dec, str):
                        return dec.encode("utf-8")
                    elif isinstance(dec, (bytes, bytearray)):
                        return bytes(dec)
    except Exception:
        pass

    return data


def read_input(source: str | None = None) -> Input:
    """Read input from a file path, stdin ('-'), or treat as raw text.

    Priority:
    1. If source is a valid file path → read file
    2. If source is '-' or None and stdin is not a TTY → read stdin
    3. Otherwise → treat source string as raw data
    """
    if source is not None and source != "-":
        try:
            path = Path(source).expanduser()
        except Exception:
            path = Path(source)

        if path.is_file():
            with open(path, "rb") as f:
                data = f.read(DEFAULT_MAX_FILE_READ_SIZE + 1)
                if len(data) > DEFAULT_MAX_FILE_READ_SIZE:
                    raise ValueError(
                        f"File exceeds maximum allowed read size of {DEFAULT_MAX_FILE_READ_SIZE // (1024 * 1024)}MB"
                    )
            return Input(
                data=data,
                source_type=SourceType.FILE,
                detected_type=detect_file_type(data),
                path=path,
                filename=path.name,
            )
        elif path.is_dir():
            files = [
                p
                for p in path.rglob("*")
                if p.is_file() and not any(part.startswith(".") for part in p.parts)
            ]
            return Input(
                data=f"Directory '{path.name}' with {len(files)} file(s)".encode("utf-8"),
                source_type=SourceType.DIRECTORY,
                detected_type="directory",
                path=path,
                filename=path.name,
            )

    # stdin mode
    if source == "-" or (source is None and not sys.stdin.isatty()):
        data = sys.stdin.buffer.read(DEFAULT_MAX_FILE_READ_SIZE + 1)
        if len(data) > DEFAULT_MAX_FILE_READ_SIZE:
            raise ValueError(
                f"Stdin stream exceeds maximum allowed read size of {DEFAULT_MAX_FILE_READ_SIZE // (1024 * 1024)}MB"
            )
        data = _extract_payload_if_json_result(data)
        return Input(
            data=data,
            source_type=SourceType.STDIN,
            detected_type=detect_file_type(data),
        )

    # raw string mode
    if source is not None:
        data = source.encode("utf-8")
        return Input(
            data=data,
            source_type=SourceType.RAW,
            detected_type=detect_file_type(data),
        )

    # No input at all
    raise SystemExit("Error: No input provided. Pass a file path, '-' for stdin, or a string.")


def read_input_bytes(source: str | None = None) -> bytes:
    """Convenience: read input and return just the raw bytes."""
    return read_input(source).data


def read_input_text(source: str | None = None) -> str:
    """Convenience: read input and return as UTF-8 text."""
    return read_input(source).text
