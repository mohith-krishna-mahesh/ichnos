from ichnos.core.models import Candidate, Finding, Input, Result, SourceType


def test_input_creation_bytes():
    raw_data = b"Hello, world!"
    inp = Input(data=raw_data, source_type=SourceType.RAW)
    assert inp.data == raw_data
    assert inp.text == "Hello, world!"
    assert inp.size == 13


def test_finding_ordering():
    f1 = Finding(label="A", confidence=0.5)
    f2 = Finding(label="B", confidence=0.8)
    f3 = Finding(label="C", confidence=0.2)

    # Test __lt__
    assert f3 < f1 < f2


def test_candidate_decoded_str():
    c1 = Candidate(decoded=b"bytes string")
    assert c1.decoded_str == "bytes string"

    c2 = Candidate(decoded="text string")
    assert c2.decoded_str == "text string"


def test_result_sorted_findings():
    f1 = Finding(label="A", confidence=0.5)
    f2 = Finding(label="B", confidence=0.8)
    f3 = Finding(label="C", confidence=0.2)

    res = Result(findings=[f1, f2, f3])

    assert res.top_finding == f2
    sorted_f = res.sorted_findings()
    assert sorted_f == [f2, f1, f3]
