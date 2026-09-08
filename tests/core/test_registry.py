from ichnos.core.models import Input, SourceType
from ichnos.core.registry import Registry


class MockAnalyzer1:
    module = "test"
    name = "mock1"

    def can_handle(self, inp: Input) -> float:
        return 0.9

    def suggest(self, inp: Input) -> list[str]:
        return ["ichnos test mock1"]


class MockAnalyzer2:
    module = "test"
    name = "mock2"

    def can_handle(self, inp: Input) -> float:
        return 0.4

    def suggest(self, inp: Input) -> list[str]:
        return ["ichnos test mock2"]


def test_register_analyzer():
    reg = Registry()

    @reg.analyzer(module="test", name="mock")
    class DummyAnalyzer:
        module = "test"
        name = "mock"

        def can_handle(self, inp):
            return 1.0

        def suggest(self, inp):
            return []

    assert "test" in reg.registered_modules
    assert len(reg._analyzers) == 1
    assert reg._analyzers[0].name == "mock"


def test_query_all():
    reg = Registry()

    # Register manually using the decorator logic to create instances
    reg.analyzer(module="test", name="mock1")(MockAnalyzer1)
    reg.analyzer(module="test", name="mock2")(MockAnalyzer2)

    inp = Input(data=b"test data", source_type=SourceType.RAW)

    findings = reg.query_all(inp)

    assert len(findings) == 2
    # Ensure they are sorted by confidence descending
    assert findings[0].confidence == 0.9
    assert findings[0].command_hint == "ichnos test mock1"

    assert findings[1].confidence == 0.4
    assert findings[1].command_hint == "ichnos test mock2"
