import struct

import pytest

from ichnos.stego.audio.morse import detect_morse
from ichnos.stego.audio.wav import get_samples, parse_wav


@pytest.fixture
def sos_wav():
    sample_rate = 8000
    # Create simple WAV header
    # 44 bytes header + data
    # Just a valid WAV structure with dummy data
    data_size = 1000
    header = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF",
        36 + data_size,
        b"WAVE",
        b"fmt ",
        16,
        1,
        1,
        sample_rate,
        sample_rate * 2,
        2,
        16,
        b"data",
        data_size,
    )
    samples = b"\x00\x00" * (data_size // 2)
    return header + samples


def test_parse_wav(sos_wav):
    header = parse_wav(sos_wav)
    assert header["sample_rate"] == 8000
    assert header["num_channels"] == 1
    assert header["bits_per_sample"] == 16


def test_get_samples(sos_wav):
    samples = get_samples(sos_wav)
    assert len(samples) > 0


def test_detect_morse_smoke(sos_wav):
    # Just checking it doesn't crash
    result = detect_morse(sos_wav)
    assert isinstance(result, str)
