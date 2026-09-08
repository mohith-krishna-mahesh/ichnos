"""
Register stego analyzers.
"""

from __future__ import annotations

from ichnos.core.models import Input
from ichnos.core.registry import registry


@registry.analyzer(module="stego", name="image-stego")
class ImageStegoAnalyzer:
    module = "stego"
    name = "image-stego"

    def can_handle(self, inp: Input) -> float:
        if inp.detected_type.startswith("image/"):
            return 1.0
        return 0.0

    def suggest(self, inp: Input) -> list[str]:
        return ["png", "lsb"]


@registry.analyzer(module="stego", name="audio-stego")
class AudioStegoAnalyzer:
    module = "stego"
    name = "audio-stego"

    def can_handle(self, inp: Input) -> float:
        if inp.detected_type.startswith("audio/"):
            return 1.0
        return 0.0

    def suggest(self, inp: Input) -> list[str]:
        return ["audio morse", "audio info"]


@registry.analyzer(module="stego", name="text-stego")
class TextStegoAnalyzer:
    module = "stego"
    name = "text-stego"

    def can_handle(self, inp: Input) -> float:
        if inp.detected_type.startswith("text/"):
            return 1.0
        return 0.0

    def suggest(self, inp: Input) -> list[str]:
        return ["text null", "text acrostic"]
