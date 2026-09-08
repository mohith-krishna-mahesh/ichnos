"""
Morse-in-audio detection for Ichnos.
"""

from __future__ import annotations

from ichnos.stego.audio.wav import get_samples, parse_wav

# Simplified morse map for stego detection if decoding isn't available elsewhere
REVERSE_MORSE = {
    ".-": "A",
    "-...": "B",
    "-.-.": "C",
    "-..": "D",
    ".": "E",
    "..-.": "F",
    "--.": "G",
    "....": "H",
    "..": "I",
    ".---": "J",
    "-.-": "K",
    ".-..": "L",
    "--": "M",
    "-.": "N",
    "---": "O",
    ".--.": "P",
    "--.-": "Q",
    ".-.": "R",
    "...": "S",
    "-": "T",
    "..-": "U",
    "...-": "V",
    ".--": "W",
    "-..-": "X",
    "-.--": "Y",
    "--..": "Z",
    ".----": "1",
    "..---": "2",
    "...--": "3",
    "....-": "4",
    ".....": "5",
    "-....": "6",
    "--...": "7",
    "---..": "8",
    "----.": "9",
    "-----": "0",
}


def detect_tones(samples: list[int], sample_rate: int, threshold: float) -> list[tuple[int, int]]:
    """Return list of (start_sample, duration_samples) for each detected tone."""
    tones = []
    in_tone = False
    start = 0

    # windowed smoothing
    window_size = sample_rate // 100  # 10ms window
    if window_size == 0:
        window_size = 1

    for i in range(0, len(samples), window_size):
        chunk = samples[i : i + window_size]
        avg_amp = sum(abs(s) for s in chunk) / len(chunk)

        if avg_amp > threshold:
            if not in_tone:
                in_tone = True
                start = i
        else:
            if in_tone:
                in_tone = False
                tones.append((start, i - start))

    if in_tone:
        tones.append((start, len(samples) - start))

    return tones


def detect_morse(wav_data: bytes, threshold: float | None = None) -> str:
    """Detect and decode morse code in audio."""
    try:
        header = parse_wav(wav_data)
        samples = get_samples(wav_data)
    except Exception:
        return ""

    if not samples:
        return ""

    if threshold is None:
        max_amp = max(abs(s) for s in samples)
        threshold = max_amp * 0.2

    tones = detect_tones(samples, header["sample_rate"], threshold)
    if not tones:
        return ""

    # Analyze durations
    on_durations = [t[1] for t in tones]
    off_durations = []
    for i in range(len(tones) - 1):
        off_durations.append(tones[i + 1][0] - (tones[i][0] + tones[i][1]))

    if not on_durations:
        return ""

    avg_dot = min(on_durations)
    avg_dash = max(on_durations)
    dot_threshold = (avg_dot + avg_dash) / 2

    avg_inter_char = sorted(off_durations)[len(off_durations) // 2] if off_durations else 0
    avg_word = max(off_durations) if off_durations else 0
    gap_threshold = (avg_inter_char + avg_word) / 2

    result = []
    current_char = ""

    for i, tone in enumerate(tones):
        if tone[1] > dot_threshold:
            current_char += "-"
        else:
            current_char += "."

        if i < len(off_durations):
            gap = off_durations[i]
            if gap > gap_threshold:
                if current_char:
                    result.append(REVERSE_MORSE.get(current_char, "?"))
                    current_char = ""
                result.append(" ")
            elif gap > (avg_inter_char * 0.5):  # Intra-char gap is small, inter-char is medium
                if current_char:
                    result.append(REVERSE_MORSE.get(current_char, "?"))
                    current_char = ""

    if current_char:
        result.append(REVERSE_MORSE.get(current_char, "?"))

    return "".join(result)
