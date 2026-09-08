from __future__ import annotations

from ichnos.core.detection import english_score, printable_ratio
from ichnos.core.registry import registry
from ichnos.crypto.hashing.identify import identify_hash


@registry.analyzer(module="crypto", name="classical-cipher")
class ClassicalCipherAnalyzer:
    module = "crypto"
    name = "classical-cipher"

    def can_handle(self, inp) -> float:
        if isinstance(inp.data, bytes):
            pr = printable_ratio(inp.data)
            try:
                text = inp.data.decode("ascii")
                score = english_score(text)
                return max(0.0, pr * 0.5 + (1.0 - score) * 0.5)
            except Exception:
                return 0.0
        return 0.0

    def suggest(self, inp) -> list[str]:
        return ["caesar", "vigenere", "substitution"]


@registry.analyzer(module="crypto", name="xor")
class XORAnalyzer:
    module = "crypto"
    name = "xor"

    def can_handle(self, inp) -> float:
        if isinstance(inp.data, bytes):
            # XOR often produces unprintable data or looks slightly structured
            return 0.5
        return 0.0

    def suggest(self, inp) -> list[str]:
        return ["xor-single", "xor-repeating"]


@registry.analyzer(module="crypto", name="hash")
class HashAnalyzer:
    module = "crypto"
    name = "hash"

    def can_handle(self, inp) -> float:
        if isinstance(inp.data, bytes):
            try:
                text = inp.data.decode("ascii").strip()
                findings = identify_hash(text)
                if findings:
                    return findings[0].confidence
            except Exception:
                pass
        return 0.0

    def suggest(self, inp) -> list[str]:
        return ["hash-identify"]
