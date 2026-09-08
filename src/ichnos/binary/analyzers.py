"""Binary analyzers."""

from __future__ import annotations

from ichnos.binary.identify import identify
from ichnos.core.registry import registry


@registry.analyzer(module="binary", name="binary")
class BinaryAnalyzer:
    module = "binary"
    name = "binary"

    def can_handle(self, inp) -> float:
        res = identify(inp.data)
        if res.get("type") != "Unknown":
            return 1.0
        return 0.0

    def suggest(self, inp) -> list[str]:
        return ["identify", "strings", "entropy", "elf"]
