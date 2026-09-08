"""Morse code encoding and decoding."""

import re

MORSE_TABLE = {
    "A": ".-",
    "B": "-...",
    "C": "-.-.",
    "D": "-..",
    "E": ".",
    "F": "..-.",
    "G": "--.",
    "H": "....",
    "I": "..",
    "J": ".---",
    "K": "-.-",
    "L": ".-..",
    "M": "--",
    "N": "-.",
    "O": "---",
    "P": ".--.",
    "Q": "--.-",
    "R": ".-.",
    "S": "...",
    "T": "-",
    "U": "..-",
    "V": "...-",
    "W": ".--",
    "X": "-..-",
    "Y": "-.--",
    "Z": "--..",
    "0": "-----",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
    ".": ".-.-.-",
    ",": "--..--",
    "?": "..--..",
    "'": ".----.",
    "!": "-.-.--",
    "/": "-..-.",
    "(": "-.--.",
    ")": "-.--.-",
    "&": ".-...",
    ":": "---...",
    ";": "-.-.-.",
    "=": "-...-",
    "+": ".-.-.",
    "-": "-....-",
    "_": "..--.-",
    '"': ".-..-.",
    "@": ".--.-.",
}

REVERSE_MORSE = {v: k for k, v in MORSE_TABLE.items()}


def encode(text: str) -> str:
    """Encode text to Morse code."""
    result = []
    for word in text.upper().split():
        word_morse = []
        for char in word:
            if char in MORSE_TABLE:
                word_morse.append(MORSE_TABLE[char])
        if word_morse:
            result.append(" ".join(word_morse))
    return " / ".join(result)


def decode(morse: str) -> str:
    """Decode Morse code to text."""
    # Normalize separators
    morse = morse.strip()

    # Try to find word separators: / or | or multiple spaces
    if "/" in morse:
        words = morse.split("/")
    elif "|" in morse:
        words = morse.split("|")
    else:
        words = re.split(r"\s{2,}", morse)

    decoded_words = []
    for word in words:
        chars = word.strip().split()
        decoded_chars = []
        for char in chars:
            if char in REVERSE_MORSE:
                decoded_chars.append(REVERSE_MORSE[char])
            else:
                decoded_chars.append("?")  # Unknown character
        if decoded_chars:
            decoded_words.append("".join(decoded_chars))

    return " ".join(decoded_words)
