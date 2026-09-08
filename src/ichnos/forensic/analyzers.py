"""Forensic analyzers."""

from __future__ import annotations

from ichnos.core.registry import registry


@registry.analyzer(module="forensic", name="forensic")
class ForensicAnalyzer:
    module = "forensic"
    name = "forensic"

    def can_handle(self, inp) -> float:
        if (
            inp.data.startswith(b"PK\x03\x04")
            or inp.data.startswith(b"Rar!")
            or inp.data.startswith(b"7z\xbc\xaf\x27\x1c")
        ):
            return 1.0
        return 0.0

    def suggest(self, inp) -> list[str]:
        return ["zip inspect", "zip comments"]
