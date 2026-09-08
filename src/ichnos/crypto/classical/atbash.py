from __future__ import annotations


def encode(text: str) -> str:
    """Encode text using Atbash cipher."""
    result = []
    for c in text:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            result.append(chr(base + 25 - (ord(c) - base)))
        else:
            result.append(c)
    return "".join(result)


def decode(text: str) -> str:
    """Decode text using Atbash cipher."""
    return encode(text)
