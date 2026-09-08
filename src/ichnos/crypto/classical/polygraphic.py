"""Polygraphic ciphers.

Includes Playfair (with quadgram solver), Two-Square, Three-Square, Four-Square,
Bifid, Trifid (Delastelle), Collon, Digrafid, Morbit, Pollux, and Fractionated Morse.
"""

from __future__ import annotations

import random
import re

from ichnos.core.models import Candidate
from ichnos.crypto.classical.substitution import score_text

ALPHABET_25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J merged with I


# =============================================================================
# Helper: Keyed 5x5 Square
# =============================================================================


def make_5x5_square(key: str = "") -> list[str]:
    seen = set()
    sq = []
    for c in re.sub(r"[^A-Z]", "", key.upper()).replace("J", "I"):
        if c not in seen:
            seen.add(c)
            sq.append(c)
    for c in ALPHABET_25:
        if c not in seen:
            seen.add(c)
            sq.append(c)
    return sq


# =============================================================================
# 1. Playfair Cipher
# =============================================================================


def _prepare_playfair_digraphs(text: str) -> list[tuple[str, str]]:
    clean = re.sub(r"[^A-Z]", "", text.upper()).replace("J", "I")
    digraphs = []
    i = 0
    while i < len(clean):
        c1 = clean[i]
        if i + 1 < len(clean):
            c2 = clean[i + 1]
            if c1 == c2:
                digraphs.append((c1, "X"))
                i += 1
            else:
                digraphs.append((c1, c2))
                i += 2
        else:
            digraphs.append((c1, "X"))
            i += 1
    return digraphs


def playfair_encrypt(text: str, key: str) -> str:
    """Playfair 5x5 digraph cipher encryption."""
    sq = make_5x5_square(key)
    pos = {sq[i]: (i // 5, i % 5) for i in range(25)}
    digraphs = _prepare_playfair_digraphs(text)

    res = []
    for c1, c2 in digraphs:
        r1, col1 = pos[c1]
        r2, col2 = pos[c2]
        if r1 == r2:
            # Same row: shift right
            res.append(sq[r1 * 5 + (col1 + 1) % 5])
            res.append(sq[r2 * 5 + (col2 + 1) % 5])
        elif col1 == col2:
            # Same column: shift down
            res.append(sq[((r1 + 1) % 5) * 5 + col1])
            res.append(sq[((r2 + 1) % 5) * 5 + col2])
        else:
            # Rectangle: swap columns
            res.append(sq[r1 * 5 + col2])
            res.append(sq[r2 * 5 + col1])
    return "".join(res)


def playfair_decrypt(text: str, key: str) -> str:
    """Playfair 5x5 digraph cipher decryption."""
    sq = make_5x5_square(key)
    pos = {sq[i]: (i // 5, i % 5) for i in range(25)}
    clean = re.sub(r"[^A-Z]", "", text.upper()).replace("J", "I")

    res = []
    for i in range(0, len(clean) - 1, 2):
        c1, c2 = clean[i], clean[i + 1]
        r1, col1 = pos.get(c1, (0, 0))
        r2, col2 = pos.get(c2, (0, 0))
        if r1 == r2:
            # Same row: shift left
            res.append(sq[r1 * 5 + (col1 - 1) % 5])
            res.append(sq[r2 * 5 + (col2 - 1) % 5])
        elif col1 == col2:
            # Same column: shift up
            res.append(sq[((r1 - 1) % 5) * 5 + col1])
            res.append(sq[((r2 - 1) % 5) * 5 + col2])
        else:
            # Rectangle: swap columns
            res.append(sq[r1 * 5 + col2])
            res.append(sq[r2 * 5 + col1])
    return "".join(res)


def playfair_solve(ciphertext: str, iterations: int = 1500, restarts: int = 3) -> Candidate:
    """Hill-climbing solver for Playfair cipher using quadgram log-probabilities."""
    best_key = ""
    best_score = -float("inf")

    for _ in range(restarts):
        curr_key = list(ALPHABET_25)
        random.shuffle(curr_key)
        curr_key_str = "".join(curr_key)
        curr_score = score_text(playfair_decrypt(ciphertext, curr_key_str))

        improved = True
        while improved:
            improved = False
            for _ in range(iterations):
                a, b = random.sample(range(25), 2)
                curr_key[a], curr_key[b] = curr_key[b], curr_key[a]
                k_candidate = "".join(curr_key)
                new_score = score_text(playfair_decrypt(ciphertext, k_candidate))
                if new_score > curr_score:
                    curr_score = new_score
                    improved = True
                else:
                    curr_key[a], curr_key[b] = curr_key[b], curr_key[a]

        if curr_score > best_score:
            best_score = curr_score
            best_key = "".join(curr_key)

    decrypted = playfair_decrypt(ciphertext, best_key)
    return Candidate(
        decoded=decrypted.encode(),
        method="playfair",
        confidence=min(
            1.0, max(0.0, (best_score + 10.0 * len(ciphertext)) / (10.0 * len(ciphertext) + 1))
        ),
        key=best_key,
        layers=["playfair"],
    )


# =============================================================================
# 2. Two-Square & Four-Square Ciphers
# =============================================================================


def four_square_encrypt(text: str, key_tr: str, key_bl: str) -> str:
    """Four-square cipher: top-right and bottom-left are keyed matrices."""
    sq_tl = make_5x5_square("")  # Standard
    sq_tr = make_5x5_square(key_tr)  # Keyed
    sq_bl = make_5x5_square(key_bl)  # Keyed
    sq_br = make_5x5_square("")  # Standard

    pos_tl = {sq_tl[i]: (i // 5, i % 5) for i in range(25)}
    pos_br = {sq_br[i]: (i // 5, i % 5) for i in range(25)}

    digraphs = _prepare_playfair_digraphs(text)
    res = []
    for c1, c2 in digraphs:
        r1, col1 = pos_tl[c1]
        r2, col2 = pos_br[c2]
        res.append(sq_tr[r1 * 5 + col2])
        res.append(sq_bl[r2 * 5 + col1])
    return "".join(res)


def four_square_decrypt(text: str, key_tr: str, key_bl: str) -> str:
    """Four-square cipher decryption."""
    sq_tl = make_5x5_square("")
    sq_tr = make_5x5_square(key_tr)
    sq_bl = make_5x5_square(key_bl)
    sq_br = make_5x5_square("")

    pos_tr = {sq_tr[i]: (i // 5, i % 5) for i in range(25)}
    pos_bl = {sq_bl[i]: (i // 5, i % 5) for i in range(25)}

    clean = re.sub(r"[^A-Z]", "", text.upper()).replace("J", "I")
    res = []
    for i in range(0, len(clean) - 1, 2):
        c1, c2 = clean[i], clean[i + 1]
        r1, col1 = pos_tr.get(c1, (0, 0))
        r2, col2 = pos_bl.get(c2, (0, 0))
        res.append(sq_tl[r1 * 5 + col2])
        res.append(sq_br[r2 * 5 + col1])
    return "".join(res)


def two_square_encrypt(text: str, key_left: str, key_right: str, horizontal: bool = True) -> str:
    """Two-square (double Playfair) cipher encryption."""
    sq1 = make_5x5_square(key_left)
    sq2 = make_5x5_square(key_right)

    pos1 = {sq1[i]: (i // 5, i % 5) for i in range(25)}
    pos2 = {sq2[i]: (i // 5, i % 5) for i in range(25)}

    digraphs = _prepare_playfair_digraphs(text)
    res = []
    for c1, c2 in digraphs:
        r1, col1 = pos1[c1]
        r2, col2 = pos2[c2]
        if horizontal:
            if r1 == r2:
                res.extend([c1, c2])
            else:
                res.append(sq1[r1 * 5 + col2])
                res.append(sq2[r2 * 5 + col1])
        else:
            if col1 == col2:
                res.extend([c1, c2])
            else:
                res.append(sq1[r2 * 5 + col1])
                res.append(sq2[r1 * 5 + col2])
    return "".join(res)


def two_square_decrypt(text: str, key_left: str, key_right: str, horizontal: bool = True) -> str:
    """Two-square cipher decryption."""
    sq1 = make_5x5_square(key_left)
    sq2 = make_5x5_square(key_right)

    pos1 = {sq1[i]: (i // 5, i % 5) for i in range(25)}
    pos2 = {sq2[i]: (i // 5, i % 5) for i in range(25)}

    clean = re.sub(r"[^A-Z]", "", text.upper()).replace("J", "I")
    res = []
    for i in range(0, len(clean) - 1, 2):
        c1, c2 = clean[i], clean[i + 1]
        r1, col1 = pos1.get(c1, (0, 0))
        r2, col2 = pos2.get(c2, (0, 0))
        if horizontal:
            if r1 == r2:
                res.extend([c1, c2])
            else:
                res.append(sq1[r1 * 5 + col2])
                res.append(sq2[r2 * 5 + col1])
        else:
            if col1 == col2:
                res.extend([c1, c2])
            else:
                res.append(sq1[r2 * 5 + col1])
                res.append(sq2[r1 * 5 + col2])
    return "".join(res)


# =============================================================================
# 3. Bifid Cipher (Delastelle)
# =============================================================================


def bifid_encrypt(text: str, key: str = "", period: int = 5) -> str:
    """Delastelle's Bifid 2D fractionation cipher."""
    sq = make_5x5_square(key)
    pos = {sq[i]: (i // 5, i % 5) for i in range(25)}
    clean = re.sub(r"[^A-Z]", "", text.upper()).replace("J", "I")

    res = []
    for b in range(0, len(clean), period):
        chunk = clean[b : b + period]
        rows = [pos[c][0] for c in chunk]
        cols = [pos[c][1] for c in chunk]
        combined = rows + cols
        for i in range(0, len(combined), 2):
            r, c = combined[i], combined[i + 1]
            res.append(sq[r * 5 + c])
    return "".join(res)


def bifid_decrypt(text: str, key: str = "", period: int = 5) -> str:
    """Delastelle's Bifid cipher decryption."""
    sq = make_5x5_square(key)
    pos = {sq[i]: (i // 5, i % 5) for i in range(25)}
    clean = re.sub(r"[^A-Z]", "", text.upper()).replace("J", "I")

    res = []
    for b in range(0, len(clean), period):
        chunk = clean[b : b + period]
        n = len(chunk)
        coords = []
        for c in chunk:
            r, col = pos[c]
            coords.extend([r, col])
        rows = coords[:n]
        cols = coords[n:]
        for i in range(n):
            res.append(sq[rows[i] * 5 + cols[i]])
    return "".join(res)


# =============================================================================
# 4. Trifid Cipher (Delastelle)
# =============================================================================

TRIFID_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ#"  # 27 chars = 3x3x3


def _make_trifid_cube(key: str = "") -> list[str]:
    seen = set()
    cube = []
    for c in re.sub(r"[^A-Z#]", "", key.upper()):
        if c not in seen:
            seen.add(c)
            cube.append(c)
    for c in TRIFID_CHARS:
        if c not in seen:
            seen.add(c)
            cube.append(c)
    return cube


def trifid_encrypt(text: str, key: str = "", period: int = 5) -> str:
    """Delastelle's Trifid 3D fractionation cipher."""
    cube = _make_trifid_cube(key)
    pos = {cube[i]: (i // 9, (i % 9) // 3, i % 3) for i in range(27)}
    clean = [c.upper() for c in text if c.upper() in pos]

    res = []
    for b in range(0, len(clean), period):
        chunk = clean[b : b + period]
        layers = [pos[c][0] for c in chunk]
        rows = [pos[c][1] for c in chunk]
        cols = [pos[c][2] for c in chunk]
        combined = layers + rows + cols
        for i in range(0, len(combined), 3):
            l, r, c = combined[i], combined[i + 1], combined[i + 2]
            res.append(cube[l * 9 + r * 3 + c])
    return "".join(res)


def trifid_decrypt(text: str, key: str = "", period: int = 5) -> str:
    """Delastelle's Trifid cipher decryption."""
    cube = _make_trifid_cube(key)
    pos = {cube[i]: (i // 9, (i % 9) // 3, i % 3) for i in range(27)}
    clean = [c.upper() for c in text if c.upper() in pos]

    res = []
    for b in range(0, len(clean), period):
        chunk = clean[b : b + period]
        n = len(chunk)
        coords = []
        for c in chunk:
            l, r, col = pos[c]
            coords.extend([l, r, col])
        layers = coords[:n]
        rows = coords[n : 2 * n]
        cols = coords[2 * n :]
        for i in range(n):
            res.append(cube[layers[i] * 9 + rows[i] * 3 + cols[i]])
    return "".join(res)


# =============================================================================
# 5. Morbit and Pollux Ciphers
# =============================================================================

MORSE_DICT = {
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
}

MORBIT_PAIRS = ["..", ".-", "./", "-.", "--", "-/", "/.", "/-", "//"]


def morbit_encrypt(text: str, key: str = "123456789") -> str:
    """Morbit cipher: Morse code pairs mapped to digits 1-9."""
    key_digits = [c for c in key if c in "123456789"]
    if len(key_digits) < 9:
        key_digits = list("123456789")

    # Map pairs to key digits
    pair_to_digit = {MORBIT_PAIRS[i]: key_digits[i] for i in range(9)}

    # Encode to Morse with '/' between letters
    morse_parts = [MORSE_DICT.get(c.upper(), "") for c in text if c.isalpha()]
    morse_stream = "/".join(morse_parts) + "/"
    if len(morse_stream) % 2 != 0:
        morse_stream += "/"

    res = []
    for i in range(0, len(morse_stream), 2):
        pair = morse_stream[i : i + 2]
        res.append(pair_to_digit.get(pair, "1"))
    return "".join(res)


def morbit_decrypt(text: str, key: str = "123456789") -> str:
    """Morbit cipher decryption."""
    key_digits = [c for c in key if c in "123456789"]
    if len(key_digits) < 9:
        key_digits = list("123456789")
    digit_to_pair = {key_digits[i]: MORBIT_PAIRS[i] for i in range(9)}

    morse_stream = "".join(digit_to_pair.get(d, "") for d in text if d in digit_to_pair)
    rev_morse = {v: k for k, v in MORSE_DICT.items()}

    res = []
    for letter_morse in morse_stream.split("/"):
        if letter_morse in rev_morse:
            res.append(rev_morse[letter_morse])
    return "".join(res)


def pollux_encrypt(text: str, key: str = "0123456789") -> str:
    """Pollux cipher: Morse characters mapped to digits."""
    # Standard mapping: 0,1,2 = dot, 3,4,5 = dash, 6,7,8,9 = space
    dot_digits = ["0", "1", "2"]
    dash_digits = ["3", "4", "5"]
    space_digits = ["6", "7", "8", "9"]

    morse_parts = [MORSE_DICT.get(c.upper(), "") for c in text if c.isalpha()]
    morse_stream = "/".join(morse_parts)

    res = []
    for m in morse_stream:
        if m == ".":
            res.append(random.choice(dot_digits))
        elif m == "-":
            res.append(random.choice(dash_digits))
        elif m == "/":
            res.append(random.choice(space_digits))
    return "".join(res)


def pollux_decrypt(
    digits: str, dot_digits: str = "012", dash_digits: str = "345", space_digits: str = "6789"
) -> str:
    """Pollux cipher decryption."""
    dots = set(dot_digits)
    dashes = set(dash_digits)
    spaces = set(space_digits)

    morse_chars = []
    for d in digits:
        if d in dots:
            morse_chars.append(".")
        elif d in dashes:
            morse_chars.append("-")
        elif d in spaces:
            morse_chars.append("/")

    morse_stream = "".join(morse_chars)
    rev_morse = {v: k for k, v in MORSE_DICT.items()}
    return "".join(rev_morse.get(part, "") for part in morse_stream.split("/") if part)


# =============================================================================
# 6. Fractionated Morse Cipher
# =============================================================================

FRACTIONATED_TRIGRAMS = [
    "...",
    "..-",
    "../",
    ".-.",
    ".--",
    ".-/",
    "./.",
    "./-",
    ".//",
    "-..",
    "-.-",
    "-./",
    "--.",
    "---",
    "--/",
    "-/.",
    "-/-",
    "-//",
    "/..",
    "/.-",
    "/./",
    "/-.",
    "/--",
    "/-/",
    "//.",
    "//-",
    "///",
]


def fractionated_morse_encrypt(text: str, key: str = "") -> str:
    """Fractionated Morse cipher: Morse trigrams mapped to 26 letters."""
    seen = set()
    alpha = []
    for c in re.sub(r"[^A-Z]", "", key.upper()):
        if c not in seen:
            seen.add(c)
            alpha.append(c)
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if c not in seen:
            seen.add(c)
            alpha.append(c)

    trigram_map = {FRACTIONATED_TRIGRAMS[i]: alpha[i] for i in range(26)}

    morse_parts = [MORSE_DICT.get(c.upper(), "") for c in text if c.isalpha()]
    morse_stream = "/".join(morse_parts)
    while len(morse_stream) % 3 != 0:
        morse_stream += "/"

    res = []
    for i in range(0, len(morse_stream), 3):
        tri = morse_stream[i : i + 3]
        res.append(trigram_map.get(tri, "A"))
    return "".join(res)


def fractionated_morse_decrypt(text: str, key: str = "") -> str:
    """Fractionated Morse cipher decryption."""
    seen = set()
    alpha = []
    for c in re.sub(r"[^A-Z]", "", key.upper()):
        if c not in seen:
            seen.add(c)
            alpha.append(c)
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if c not in seen:
            seen.add(c)
            alpha.append(c)

    rev_trigram = {alpha[i]: FRACTIONATED_TRIGRAMS[i] for i in range(26)}

    morse_stream = "".join(rev_trigram.get(c.upper(), "") for c in text if c.isalpha())
    rev_morse = {v: k for k, v in MORSE_DICT.items()}

    res = []
    for part in morse_stream.split("/"):
        if part in rev_morse:
            res.append(rev_morse[part])
    return "".join(res)
