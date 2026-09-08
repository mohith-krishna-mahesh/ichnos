"""Analyzers for encoding module."""

from ichnos.core.models import Finding, Input
from ichnos.core.registry import registry
from ichnos.encoding.layered import detect_encoding


@registry.analyzer(module="encoding", name="encoding")
class EncodingAnalyzer:
    """Analyzer for encoded text."""

    module = "encoding"
    name = "encoding"

    def can_handle(self, inp: Input) -> float:
        """Check if input looks like encoded text."""
        # Simple heuristic: if it's textual, we can analyze it for encoding
        try:
            if inp.text:
                return 0.8
        except UnicodeDecodeError:
            pass
        return 0.0

    def analyze(self, inp: Input) -> list[Finding]:
        """Analyze the input to find encodings."""
        try:
            text = inp.text
            if not text:
                return []
            return detect_encoding(text)
        except Exception:
            return []

    def suggest(self, inp: Input) -> list[str]:
        """Suggest decode commands."""
        findings = self.analyze(inp)
        return [f.command_hint for f in findings if f.command_hint]
