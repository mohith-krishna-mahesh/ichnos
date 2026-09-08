"""
WAV parser module for Ichnos stego toolkit.
"""

from __future__ import annotations

import struct
from typing import Any

MAX_SAMPLES = 2_000_000


def parse_wav(data: bytes) -> dict[str, Any]:
    """Parse WAV/RIFF header."""
    if len(data) < 44 or not data.startswith(b"RIFF") or data[8:12] != b"WAVE":
        raise ValueError("Invalid WAV format")

    fmt_offset = data.find(b"fmt ")
    if fmt_offset == -1 or fmt_offset + 24 > len(data):
        raise ValueError("fmt chunk not found or truncated")

    try:
        audio_format, num_channels, sample_rate, _byte_rate, _block_align, bits_per_sample = (
            struct.unpack("<HHIIHH", data[fmt_offset + 8 : fmt_offset + 24])
        )
    except struct.error as e:
        raise ValueError(f"Malformed fmt chunk: {e}") from e

    data_offset = data.find(b"data")
    if data_offset == -1 or data_offset + 8 > len(data):
        raise ValueError("data chunk not found or truncated")

    try:
        data_size = struct.unpack("<I", data[data_offset + 4 : data_offset + 8])[0]
    except struct.error as e:
        raise ValueError(f"Malformed data chunk: {e}") from e

    if num_channels == 0 or bits_per_sample == 0:
        raise ValueError("Invalid audio parameters: zero channels or zero bits per sample")

    bytes_per_sample = bits_per_sample // 8
    if bytes_per_sample == 0:
        raise ValueError(f"Unsupported bits per sample: {bits_per_sample}")

    num_samples = data_size // (num_channels * bytes_per_sample) if bytes_per_sample > 0 else 0
    duration = num_samples / sample_rate if sample_rate > 0 else 0.0

    return {
        "format": audio_format,
        "channels": num_channels,
        "num_channels": num_channels,
        "sample_rate": sample_rate,
        "bits_per_sample": bits_per_sample,
        "data_size": data_size,
        "num_samples": num_samples,
        "duration": duration,
        "data_offset": data_offset + 8,
    }


def get_samples(data: bytes) -> list[int]:
    """Extract raw sample values as integers."""
    try:
        header = parse_wav(data)
    except ValueError:
        return []

    offset = header["data_offset"]
    size = header["data_size"]
    bits = header["bits_per_sample"]
    channels = header["channels"]

    if offset > len(data):
        return []

    sample_data = data[offset : min(offset + size, len(data))]
    bytes_per_sample = bits // 8
    if bytes_per_sample == 0:
        return []

    num_samples = min(len(sample_data) // bytes_per_sample, MAX_SAMPLES)
    if num_samples <= 0:
        return []

    try:
        if bits == 8:
            fmt = f"<{num_samples}B"
            raw_samples = struct.unpack(fmt, sample_data[: num_samples * 1])
            # 8-bit PCM is unsigned, center at 128
            samples = [s - 128 for s in raw_samples]
        elif bits == 16:
            fmt = f"<{num_samples}h"
            samples = list(struct.unpack(fmt, sample_data[: num_samples * 2]))
        else:
            # Not supported
            return []
    except struct.error:
        return []

    # If stereo, just mix down to mono for simplicity
    if channels > 1:
        mono = []
        for i in range(0, len(samples), channels):
            mono.append(sum(samples[i : i + channels]) // channels)
        return mono

    return samples


def get_metadata(data: bytes) -> dict[str, str]:
    """Extract LIST/INFO chunks."""
    metadata = {}
    list_offset = data.find(b"LIST")
    if list_offset != -1 and list_offset + 8 <= len(data):
        try:
            size = struct.unpack("<I", data[list_offset + 4 : list_offset + 8])[0]
        except struct.error:
            return metadata
        list_data = data[list_offset + 8 : min(list_offset + 8 + size, len(data))]
        if list_data.startswith(b"INFO"):
            info_data = list_data[4:]
            i = 0
            while i < len(info_data) - 8:
                try:
                    tag = info_data[i : i + 4].decode(errors="ignore")
                    tag_size = struct.unpack("<I", info_data[i + 4 : i + 8])[0]
                except struct.error:
                    break
                if tag_size < 0 or i + 8 + tag_size > len(info_data):
                    break
                val = info_data[i + 8 : i + 8 + tag_size].decode(errors="ignore").strip("\x00")
                metadata[tag] = val
                i += 8 + tag_size + (tag_size % 2)  # pad byte
    return metadata
