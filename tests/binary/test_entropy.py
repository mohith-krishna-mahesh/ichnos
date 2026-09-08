import os

from ichnos.binary.entropy import entropy_summary, sliding_window_entropy, whole_file_entropy


def test_whole_file_entropy_random():
    data = os.urandom(1000)
    ent = whole_file_entropy(data)
    assert ent > 7.5


def test_whole_file_entropy_zeros():
    data = b"\x00" * 1000
    ent = whole_file_entropy(data)
    assert ent == 0.0


def test_sliding_window():
    data = b"\x00" * 100 + os.urandom(100) + b"\x00" * 100
    res = sliding_window_entropy(data, window_size=50)
    assert len(res) > 0
    assert res[0][1] == 0.0
    # middle chunks should be high (max entropy for 50 bytes is log2(50) ≈ 5.64)
    assert any(ent > 5.0 for off, ent in res)


def test_entropy_summary():
    data = os.urandom(1000)
    summary = entropy_summary(data)
    assert "overall_entropy" in summary
    assert summary["overall_entropy"] > 7.5
