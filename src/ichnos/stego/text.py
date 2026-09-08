"""
Text steganography module for Ichnos.
"""

from __future__ import annotations

from ichnos.core.models import Candidate


def null_cipher_first_letter(text: str) -> str:
    """Extract first letter of each word."""
    words = text.split()
    return "".join(word[0] for word in words if word)


def null_cipher_nth_letter(text: str, n: int) -> str:
    """Extract every Nth letter from the text, ignoring spaces/punctuation for counting."""
    cleaned = "".join(c for c in text if c.isalpha())
    if n <= 0 or not cleaned:
        return ""
    return cleaned[n - 1 :: n]


def nth_letter(text: str, n: int) -> str:
    """Extract every Nth character from the text (stepping by n)."""
    if n <= 0:
        return ""
    return text[::n]


def null_cipher_first_sentence(text: str) -> str:
    """Extract first letter of each sentence."""
    sentences = [
        s.strip() for s in text.replace("!", ".").replace("?", ".").split(".") if s.strip()
    ]
    return "".join(s[0] for s in sentences if s)


def acrostic(text: str) -> str:
    """Extract first character of each line."""
    lines = text.splitlines()
    return "".join(line[0] for line in lines if line)


def cardan_grille(text: str, positions: list[int]) -> str:
    """Extract characters at given 0-indexed positions."""
    res = []
    for p in positions:
        if 0 <= p < len(text):
            res.append(text[p])
    return "".join(res)


def reverse_text(text: str) -> str:
    """Reverse the entire string."""
    return text[::-1]


def mirror_text(text: str) -> str:
    """Reverse each line."""
    return "\n".join(line[::-1] for line in text.splitlines())


COMMON_WORDS = {
    "the",
    "be",
    "to",
    "of",
    "and",
    "a",
    "in",
    "that",
    "have",
    "i",
    "it",
    "for",
    "not",
    "on",
    "with",
    "he",
    "as",
    "you",
    "do",
    "at",
    "this",
    "but",
    "his",
    "by",
    "from",
    "they",
    "we",
    "say",
    "her",
    "she",
    "or",
    "an",
    "will",
    "my",
    "one",
    "all",
    "would",
    "there",
    "their",
    "what",
    "so",
    "up",
    "out",
    "if",
    "about",
    "who",
    "get",
    "which",
    "go",
    "me",
    "when",
    "make",
    "can",
    "like",
    "time",
    "no",
    "just",
    "him",
    "know",
    "take",
    "is",
    "are",
    "was",
    "were",
    "test",
    "secret",
    "flag",
    "message",
    "hidden",
}


def detect_reverse(text: str) -> Candidate | None:
    """Check if reversing produces more English-like text."""
    rev = reverse_text(text)
    words_orig = [w.strip(".,!?;:\"'()[]{}").lower() for w in text.split()]
    words_rev = [w.strip(".,!?;:\"'()[]{}").lower() for w in rev.split()]
    if not words_rev:
        return None

    orig_matches = sum(1 for w in words_orig if w in COMMON_WORDS)
    rev_matches = sum(1 for w in words_rev if w in COMMON_WORDS)

    if rev_matches > orig_matches:
        conf = min(1.0, max(0.5, rev_matches / len(words_rev)))
        return Candidate(
            decoded=rev, method="reverse_text", confidence=conf, layers=["stego.text.reverse"]
        )
    return None


UPSIDE_DOWN_MAP = {
    "ɐ": "a",
    "q": "b",
    "ɔ": "c",
    "p": "d",
    "ǝ": "e",
    "ɟ": "f",
    "ƃ": "g",
    "ɥ": "h",
    "ᴉ": "i",
    "ɾ": "j",
    "ʞ": "k",
    "l": "l",
    "ɯ": "m",
    "u": "n",
    "o": "o",
    "d": "p",
    "b": "q",
    "ɹ": "r",
    "s": "s",
    "ʇ": "t",
    "ʌ": "v",
    "ʍ": "w",
    "x": "x",
    "ʎ": "y",
    "z": "z",
    "∀": "A",
    "ᗺ": "B",
    "Ɔ": "C",
    "ᗡ": "D",
    "Ǝ": "E",
    "Ⅎ": "F",
    "פ": "G",
    "H": "H",
    "I": "I",
    "ſ": "J",
    "˥": "L",
    "W": "M",
    "N": "N",
    "O": "O",
    "Ԁ": "P",
    "Q": "Q",
    "R": "R",
    "S": "S",
    "┴": "T",
    "∩": "U",
    "Λ": "V",
    "M": "W",
    "X": "X",
    "⅄": "Y",
    "Z": "Z",
    "0": "0",
    "Ɩ": "1",
    "ᄅ": "2",
    "Ɛ": "3",
    "ㄣ": "4",
    "ϛ": "5",
    "9": "6",
    "ㄥ": "7",
    "8": "8",
    "6": "9",
    "˙": ".",
    ",": "'",
    "'": ",",
    '"': ",,",
    "¡": "!",
    "¿": "?",
    "‾": "_",
    ")": "(",
    "(": ")",
    "}": "{",
    "{": "}",
    "]": "[",
    "[": "]",
    "<": ">",
    ">": "<",
}


def upside_down_decode(text: str) -> str:
    """Map upside-down Unicode chars back to normal and reverse."""
    mapped = []
    for char in text:
        mapped.append(UPSIDE_DOWN_MAP.get(char, char))
    return "".join(mapped)[::-1]
