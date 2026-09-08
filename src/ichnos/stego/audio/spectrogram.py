"""Pure-Python audio spectrogram generation and frequency-domain analysis.

Provides Cooley-Tukey FFT, Short-Time Fourier Transform (STFT),
spectral peak detection, and terminal ASCII spectrogram rendering without external dependencies.
"""

from __future__ import annotations

import cmath
import math
from typing import Any

from ichnos.stego.audio.wav import get_samples, parse_wav


def fft(x: list[complex]) -> list[complex]:
    """Computes the 1D Cooley-Tukey Fast Fourier Transform (FFT).

    Requires len(x) to be a power of 2.
    """
    n = len(x)
    if n <= 1:
        return x
    even = fft(x[0::2])
    odd = fft(x[1::2])
    t = [cmath.exp(-2j * cmath.pi * k / n) * odd[k] for k in range(n // 2)]
    return [even[k] + t[k] for k in range(n // 2)] + [even[k] - t[k] for k in range(n // 2)]


def _hann_window(size: int) -> list[float]:
    """Generates a Hann window of the specified size."""
    return [0.5 * (1.0 - math.cos(2.0 * math.pi * i / (size - 1))) for i in range(size)]


def compute_spectrogram(
    samples: list[int] | list[float],
    sample_rate: int = 8000,
    window_size: int = 256,
    hop_size: int = 128,
) -> list[list[float]]:
    """Computes the Short-Time Fourier Transform (STFT) magnitude matrix.

    Returns a 2D list: `spectrogram[time_frame][freq_bin]`.
    """
    if len(samples) < window_size:
        # Pad with zeros
        samples = list(samples) + [0] * (window_size - len(samples))

    window = _hann_window(window_size)
    time_frames: list[list[float]] = []

    for start in range(0, len(samples) - window_size + 1, hop_size):
        frame = [complex(samples[start + i] * window[i]) for i in range(window_size)]
        transformed = fft(frame)
        # Take positive frequency magnitudes (first N/2 bins)
        mags = [abs(val) for val in transformed[: window_size // 2]]
        time_frames.append(mags)

    return time_frames


def render_ascii_spectrogram(
    spectrogram: list[list[float]],
    width: int = 60,
    height: int = 20,
) -> str:
    """Renders a 2D spectrogram matrix into a terminal ASCII heatmap string."""
    if not spectrogram or not spectrogram[0]:
        return "Empty spectrogram"

    num_times = len(spectrogram)
    num_freqs = len(spectrogram[0])

    # Find max magnitude for normalization
    max_val = max(max(frame) for frame in spectrogram) or 1.0

    chars = " .:-=+*#%@"
    num_chars = len(chars)

    lines: list[str] = []

    # Frequency on Y axis (high to low), Time on X axis
    for row in range(height - 1, -1, -1):
        freq_idx = int(row * (num_freqs - 1) / (height - 1))
        row_chars = []
        for col in range(width):
            time_idx = int(col * (num_times - 1) / (width - 1))
            val = spectrogram[time_idx][freq_idx] / max_val
            # Logarithmic dynamic range mapping
            log_norm = math.log10(1 + 9 * val)
            char_idx = min(int(log_norm * (num_chars - 1)), num_chars - 1)
            row_chars.append(chars[char_idx])
        lines.append("".join(row_chars))

    return "\n".join(lines)


def detect_spectral_peaks(
    spectrogram: list[list[float]],
    sample_rate: int,
    window_size: int = 256,
    top_k: int = 5,
) -> list[dict[str, Any]]:
    """Detects the most prominent frequency components across all time frames."""
    if not spectrogram or not spectrogram[0]:
        return []

    num_bins = len(spectrogram[0])
    bin_width = sample_rate / window_size

    # Accumulate energy per bin across time
    bin_energies = [0.0] * num_bins
    for frame in spectrogram:
        for b_idx, mag in enumerate(frame):
            bin_energies[b_idx] += mag

    # Rank bins
    ranked = sorted(enumerate(bin_energies), key=lambda x: x[1], reverse=True)
    peaks = []
    for b_idx, energy in ranked[:top_k]:
        freq = b_idx * bin_width
        peaks.append(
            {
                "frequency_hz": round(freq, 1),
                "bin": b_idx,
                "relative_energy": round(energy, 2),
            }
        )

    return peaks


def spectrogram_from_wav(wav_bytes: bytes, window_size: int = 256) -> tuple[list[list[float]], int]:
    """Parses WAV bytes, computes STFT spectrogram, and returns (spectrogram, sample_rate)."""
    meta = parse_wav(wav_bytes)
    samples = get_samples(wav_bytes)
    sample_rate = meta.get("sample_rate", 8000)
    spec = compute_spectrogram(samples, sample_rate=sample_rate, window_size=window_size)
    return spec, sample_rate
