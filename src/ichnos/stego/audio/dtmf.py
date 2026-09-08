"""
DTMF (Dual-Tone Multi-Frequency) telephone keypad tone decoder.

Uses the Goertzel algorithm to efficiently detect specific frequency
components in audio frames, mapping detected frequency pairs to
telephone keypad characters.  Common in CTF challenges where flags
are encoded as DTMF tones in WAV files.
"""

from __future__ import annotations

import math
import struct

# DTMF frequency definitions
_ROW_FREQS = (697, 770, 852, 941)
_COL_FREQS = (1209, 1336, 1477, 1633)

# Keypad grid indexed by (row_index, col_index)
_DTMF_GRID: dict[tuple[int, int], str] = {
    (0, 0): "1", (0, 1): "2", (0, 2): "3", (0, 3): "A",
    (1, 0): "4", (1, 1): "5", (1, 2): "6", (1, 3): "B",
    (2, 0): "7", (2, 1): "8", (2, 2): "9", (2, 3): "C",
    (3, 0): "*", (3, 1): "0", (3, 2): "#", (3, 3): "D",
}


def goertzel(samples: list[float], target_freq: float, sample_rate: int) -> float:
    """Compute the magnitude of a single DFT bin using the Goertzel algorithm.

    Much more efficient than a full FFT when only a small number of
    frequency bins need to be evaluated.

    Args:
        samples: Audio sample values (typically normalised to [-1.0, 1.0]).
        target_freq: The frequency (Hz) to detect.
        sample_rate: The sampling rate of the audio (Hz).

    Returns:
        The magnitude (power) of the target frequency component.
    """
    n = len(samples)
    if n == 0:
        return 0.0

    k = int(0.5 + n * target_freq / sample_rate)
    omega = 2.0 * math.pi * k / n
    coeff = 2.0 * math.cos(omega)

    s0 = 0.0
    s1 = 0.0
    s2 = 0.0

    for sample in samples:
        s0 = sample + coeff * s1 - s2
        s2 = s1
        s1 = s0

    magnitude = s1 * s1 + s2 * s2 - coeff * s1 * s2
    return magnitude


def detect_dtmf_tones(
    samples: list[float],
    sample_rate: int,
    frame_ms: int = 40,
    threshold: float = 0.1,
) -> str:
    """Detect DTMF tones in audio samples and decode to keypad characters.

    Splits the audio into non-overlapping frames of *frame_ms* milliseconds.
    For each frame the Goertzel algorithm is run on all 8 DTMF frequencies;
    the strongest row and column frequencies are selected and, if both
    exceed *threshold*, mapped to the corresponding keypad character.
    Consecutive duplicate characters are collapsed.

    Args:
        samples: Audio sample values (float, ideally in [-1.0, 1.0]).
        sample_rate: Sampling rate in Hz.
        frame_ms: Frame length in milliseconds.
        threshold: Minimum Goertzel magnitude to consider a tone present.

    Returns:
        The decoded keypad string with consecutive duplicates collapsed.
    """
    frame_size = int(sample_rate * frame_ms / 1000)
    if frame_size <= 0:
        return ""

    result_chars: list[str] = []
    total_samples = len(samples)

    for start in range(0, total_samples, frame_size):
        frame = samples[start : start + frame_size]
        if len(frame) < frame_size // 2:
            break  # skip very short trailing frames

        # Evaluate all DTMF frequencies
        row_mags = [goertzel(frame, f, sample_rate) for f in _ROW_FREQS]
        col_mags = [goertzel(frame, f, sample_rate) for f in _COL_FREQS]

        best_row_idx = max(range(len(row_mags)), key=lambda i: row_mags[i])
        best_col_idx = max(range(len(col_mags)), key=lambda i: col_mags[i])

        best_row_mag = row_mags[best_row_idx]
        best_col_mag = col_mags[best_col_idx]

        if best_row_mag < threshold or best_col_mag < threshold:
            # Silence or noise — acts as a separator for duplicate detection
            if result_chars and result_chars[-1] is not None:
                result_chars.append(None)  # type: ignore[arg-type]
            continue

        char = _DTMF_GRID.get((best_row_idx, best_col_idx))
        if char is None:
            continue

        # Collapse consecutive duplicates (ignoring None separators)
        if not result_chars or result_chars[-1] != char:
            result_chars.append(char)

    return "".join(c for c in result_chars if c is not None)


def decode_wav_dtmf(wav_data: bytes) -> str:
    """Parse a WAV file and decode DTMF tones from the PCM audio data.

    Supports:
        - 8-bit unsigned and 16-bit signed PCM
        - Mono and stereo (stereo channels are averaged)

    Args:
        wav_data: Raw bytes of a WAV file.

    Returns:
        The decoded DTMF keypad string.

    Raises:
        ValueError: If the WAV data is invalid or uses an unsupported format.
    """
    # --- RIFF / WAV header validation ---
    if len(wav_data) < 12:
        raise ValueError("WAV data too short")
    if wav_data[:4] != b"RIFF" or wav_data[8:12] != b"WAVE":
        raise ValueError("Invalid WAV/RIFF header")

    # --- Locate 'fmt ' sub-chunk ---
    fmt_offset = _find_subchunk(wav_data, b"fmt ")
    if fmt_offset is None:
        raise ValueError("'fmt ' chunk not found")

    fmt_size = struct.unpack_from("<I", wav_data, fmt_offset + 4)[0]
    if fmt_offset + 8 + fmt_size > len(wav_data) or fmt_size < 16:
        raise ValueError("Malformed 'fmt ' chunk")

    (
        audio_format,
        num_channels,
        sample_rate,
        _byte_rate,
        _block_align,
        bits_per_sample,
    ) = struct.unpack_from("<HHIIHH", wav_data, fmt_offset + 8)

    if audio_format != 1:
        raise ValueError(f"Unsupported audio format: {audio_format} (only PCM/1 supported)")
    if bits_per_sample not in (8, 16):
        raise ValueError(f"Unsupported bits per sample: {bits_per_sample}")
    if num_channels < 1:
        raise ValueError(f"Invalid channel count: {num_channels}")

    # --- Locate 'data' sub-chunk ---
    data_offset = _find_subchunk(wav_data, b"data")
    if data_offset is None:
        raise ValueError("'data' chunk not found")

    data_size = struct.unpack_from("<I", wav_data, data_offset + 4)[0]
    pcm_start = data_offset + 8
    pcm_end = min(pcm_start + data_size, len(wav_data))
    pcm_bytes = wav_data[pcm_start:pcm_end]

    # --- Convert PCM to float samples ---
    samples = _pcm_to_float(pcm_bytes, bits_per_sample, num_channels)

    return detect_dtmf_tones(samples, sample_rate)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _find_subchunk(wav_data: bytes, chunk_id: bytes) -> int | None:
    """Find the byte offset of a RIFF sub-chunk by its 4-byte ID.

    Walks the chunk list starting after the RIFF header (offset 12).
    """
    offset = 12  # first sub-chunk starts right after RIFF header
    while offset + 8 <= len(wav_data):
        cid = wav_data[offset : offset + 4]
        size = struct.unpack_from("<I", wav_data, offset + 4)[0]
        if cid == chunk_id:
            return offset
        offset += 8 + size
        # Chunks are word-aligned in RIFF
        if offset % 2 != 0:
            offset += 1
    return None


def _pcm_to_float(
    pcm_bytes: bytes, bits_per_sample: int, num_channels: int
) -> list[float]:
    """Convert raw PCM bytes to a mono list of floats in [-1.0, 1.0].

    For stereo (or multi-channel) audio the channels are averaged.
    """
    samples: list[float] = []

    if bits_per_sample == 8:
        # 8-bit PCM is unsigned: 0..255, silence at 128
        bytes_per_sample = 1
        raw_samples = list(pcm_bytes)
        for i in range(0, len(raw_samples), num_channels):
            channel_vals = raw_samples[i : i + num_channels]
            if not channel_vals:
                break
            avg = sum(channel_vals) / len(channel_vals)
            samples.append((avg - 128.0) / 128.0)

    elif bits_per_sample == 16:
        # 16-bit PCM is signed little-endian: -32768..32767
        bytes_per_sample = 2
        total_frame_bytes = bytes_per_sample * num_channels
        num_frames = len(pcm_bytes) // total_frame_bytes

        for frame_idx in range(num_frames):
            base = frame_idx * total_frame_bytes
            channel_sum = 0.0
            for ch in range(num_channels):
                offset = base + ch * bytes_per_sample
                value = struct.unpack_from("<h", pcm_bytes, offset)[0]
                channel_sum += value
            samples.append((channel_sum / num_channels) / 32768.0)

    return samples
