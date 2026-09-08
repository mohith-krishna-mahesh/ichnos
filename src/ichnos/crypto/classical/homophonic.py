"""Homophonic and Nomenclator ciphers.

Includes Homophonic Substitution, Nomenclator, Grandpré, Arnold Book Cipher,
Modulo Cipher, and Mexican Army Cipher Wheel.
"""

from __future__ import annotations

import random
import re

# Standard English letter distribution for 100-number homophonic table (00-99)
HOMOPHONIC_DEFAULT_ALLOCATION = {
    "A": [9, 12, 33, 47, 53, 67, 78, 92],
    "B": [48, 81],
    "C": [13, 41, 62],
    "D": [1, 14, 25, 40],
    "E": [15, 22, 36, 44, 50, 61, 69, 74, 85, 88, 96, 98],
    "F": [10, 31],
    "G": [6, 20],
    "H": [16, 29, 52, 70, 89, 95],
    "I": [3, 24, 39, 75, 84, 93],
    "J": [27],
    "K": [37],
    "L": [18, 38, 59, 71],
    "M": [23, 58],
    "N": [4, 19, 51, 72, 79, 90],
    "O": [5, 28, 43, 63, 73, 86, 94],
    "P": [7, 60],
    "Q": [77],
    "R": [11, 35, 54, 68, 87, 99],
    "S": [8, 26, 42, 65, 82, 97],
    "T": [17, 34, 46, 55, 64, 76, 83, 91, 100],
    "U": [2, 30, 66],
    "V": [21],
    "W": [32, 57],
    "X": [49],
    "Y": [56, 80],
    "Z": [45],
}


# =============================================================================
# 1. Homophonic Cipher
# =============================================================================


def homophonic_encrypt(text: str, allocation: dict[str, list[int]] | None = None) -> list[int]:
    """Homophonic substitution encryption (frequency-balanced numbers)."""
    table = allocation or HOMOPHONIC_DEFAULT_ALLOCATION
    res = []
    for char in text:
        cu = char.upper()
        if cu in table:
            res.append(random.choice(table[cu]))
    return res


def homophonic_decrypt(
    numbers: list[int] | str, allocation: dict[str, list[int]] | None = None
) -> str:
    """Homophonic substitution decryption."""
    table = allocation or HOMOPHONIC_DEFAULT_ALLOCATION
    rev_map: dict[int, str] = {}
    for letter, nums in table.items():
        for n in nums:
            rev_map[n] = letter

    if isinstance(numbers, str):
        num_list = [int(x) for x in re.findall(r"\d+", numbers)]
    else:
        num_list = list(numbers)

    return "".join(rev_map.get(n, "?") for n in num_list)


# =============================================================================
# 2. Nomenclator
# =============================================================================

NOMENCLATOR_DEFAULT_WORDS = {
    "THE": 901,
    "AND": 902,
    "THAT": 903,
    "HAVE": 904,
    "FOR": 905,
    "NOT": 906,
    "WITH": 907,
    "YOU": 908,
    "ATTACK": 909,
    "SECRET": 910,
    "FLAG": 911,
    "CONFIDENTIAL": 912,
    "ENEMY": 913,
    "TARGET": 914,
}


def nomenclator_encrypt(
    text: str,
    letter_alloc: dict[str, list[int]] | None = None,
    word_dict: dict[str, int] | None = None,
) -> list[int]:
    """Nomenclator: hybrid word-level codebook and letter substitution."""
    letters_table = letter_alloc or HOMOPHONIC_DEFAULT_ALLOCATION
    words_table = word_dict or NOMENCLATOR_DEFAULT_WORDS

    # Tokenize words vs punctuation
    tokens = re.findall(r"[A-Za-z]+|\S+", text)
    res = []
    for token in tokens:
        tu = token.upper()
        if tu in words_table:
            res.append(words_table[tu])
        else:
            for char in tu:
                if char in letters_table:
                    res.append(random.choice(letters_table[char]))
    return res


def nomenclator_decrypt(
    numbers: list[int] | str,
    letter_alloc: dict[str, list[int]] | None = None,
    word_dict: dict[str, int] | None = None,
) -> str:
    """Nomenclator decryption."""
    letters_table = letter_alloc or HOMOPHONIC_DEFAULT_ALLOCATION
    words_table = word_dict or NOMENCLATOR_DEFAULT_WORDS

    rev_words = {v: k for k, v in words_table.items()}
    rev_letters = {}
    for letter, nums in letters_table.items():
        for n in nums:
            rev_letters[n] = letter

    if isinstance(numbers, str):
        num_list = [int(x) for x in re.findall(r"\d+", numbers)]
    else:
        num_list = list(numbers)

    res = []
    for n in num_list:
        if n in rev_words:
            res.append(f" {rev_words[n]} ")
        elif n in rev_letters:
            res.append(rev_letters[n])
        else:
            res.append("?")
    return re.sub(r"\s+", " ", "".join(res)).strip()


# =============================================================================
# 3. Grandpré Cipher
# =============================================================================

# 8x8 Grandpré grid using 8-letter English words
GRANDPRE_DEFAULT_GRID = [
    "EQUIPMENTS",
    "JACKRABBIT",
    "WINDCHIMES",
    "COMPLEXITY",
    "APOLOGIZED",
    "VERTEBRATE",
    "BEAUTIFULL",
    "GARRISONSS",
    "AUTHORISED",
    "BLACKBOARD",
]


def grandpre_encrypt(text: str, grid: list[str] | None = None) -> list[str]:
    """Grandpré cipher: 8x8 or 10x10 pangram grid coordinates."""
    g = grid or GRANDPRE_DEFAULT_GRID
    char_coords: dict[str, list[str]] = {}
    for r in range(len(g)):
        for c in range(len(g[r])):
            char = g[r][c].upper()
            coord = f"{(r + 1) % 10}{(c + 1) % 10}" if len(g) == 10 else f"{r + 1}{c + 1}"
            char_coords.setdefault(char, []).append(coord)

    res = []
    for char in text.upper():
        if char in char_coords:
            res.append(random.choice(char_coords[char]))
    return res


def grandpre_decrypt(coordinates: list[str] | str, grid: list[str] | None = None) -> str:
    """Grandpré cipher decryption."""
    g = grid or GRANDPRE_DEFAULT_GRID
    if isinstance(coordinates, str):
        coords = re.findall(r"\d{2}", coordinates)
    else:
        coords = list(coordinates)

    res = []
    for coord in coords:
        if len(g) == 10:
            r = (int(coord[0]) - 1) % 10
            c = (int(coord[1]) - 1) % 10
        else:
            r = int(coord[0]) - 1
            c = int(coord[1]) - 1
        if 0 <= r < len(g) and 0 <= c < len(g[r]):
            res.append(g[r][c])
        else:
            res.append("?")
    return "".join(res)


# =============================================================================
# 4. Arnold Cipher (Book Cipher)
# =============================================================================


def arnold_encrypt(text: str, book_text: str) -> list[str]:
    """Arnold book cipher: maps words or letters to page/line/word coordinates."""
    words = re.findall(r"[A-Za-z]+", book_text.upper())
    word_to_indices: dict[str, list[int]] = {}
    for idx, w in enumerate(words):
        word_to_indices.setdefault(w, []).append(idx + 1)

    res = []
    for word in re.findall(r"[A-Za-z]+", text.upper()):
        if word in word_to_indices:
            res.append(str(random.choice(word_to_indices[word])))
        else:
            # Fallback: spell out letters
            for c in word:
                matching = [
                    idx for w, idxs in word_to_indices.items() if w.startswith(c) for idx in idxs
                ]
                res.append(str(random.choice(matching) if matching else 0))
    return res


def arnold_decrypt(tokens: list[str] | str, book_text: str) -> str:
    """Arnold book cipher decryption."""
    words = re.findall(r"[A-Za-z]+", book_text.upper())
    if isinstance(tokens, str):
        indices = [int(x) for x in re.findall(r"\d+", tokens)]
    else:
        indices = [int(x) for x in tokens]

    res = []
    for idx in indices:
        if 1 <= idx <= len(words):
            res.append(words[idx - 1])
        else:
            res.append("?")
    return " ".join(res)


# =============================================================================
# 5. Modulo Cipher
# =============================================================================


def modulo_encrypt(text: str, key_values: list[int] | int, mod: int = 26) -> list[int]:
    """Modulo cipher: converts letters to numbers, applies additive key mod N."""
    if isinstance(key_values, int):
        keys = [key_values]
    else:
        keys = key_values

    res = []
    k_idx = 0
    for char in text.upper():
        if char.isalpha():
            val = ord(char) - ord("A")
            k = keys[k_idx % len(keys)]
            res.append((val + k) % mod)
            k_idx += 1
    return res


def modulo_decrypt(numbers: list[int] | str, key_values: list[int] | int, mod: int = 26) -> str:
    """Modulo cipher decryption."""
    if isinstance(key_values, int):
        keys = [key_values]
    else:
        keys = key_values

    if isinstance(numbers, str):
        num_list = [int(x) for x in re.findall(r"\d+", numbers)]
    else:
        num_list = list(numbers)

    res = []
    for idx, num in enumerate(num_list):
        k = keys[idx % len(keys)]
        val = (num - k) % mod
        res.append(chr(val + ord("A")))
    return "".join(res)


# =============================================================================
# 6. Mexican Army Cipher Wheel
# =============================================================================


class MexicanArmyCipherWheel:
    """Mexican Army Cipher Wheel (5 concentric disks: 1 alphabet + 4 numbered)."""

    BASE_OFFSETS = [1, 27, 53, 79]

    def __init__(self, key_letters: str = "AAAA"):
        self.key_letters = key_letters.upper()[:4].ljust(4, "A")

    def encrypt(self, text: str) -> list[str]:
        res = []
        for char in text:
            cu = char.upper()
            if cu.isalpha():
                valid_disks = []
                for d in range(4):
                    off = (ord(cu) - ord(self.key_letters[d])) % 26
                    if d < 3 or off < 22:
                        valid_disks.append((d, off))
                d, off = random.choice(valid_disks)
                num = (self.BASE_OFFSETS[d] + off) % 100
                res.append(f"{num:02d}")
        return res

    def decrypt(self, tokens: list[str] | str) -> str:
        if isinstance(tokens, str):
            num_list = re.findall(r"\d{2}", tokens)
        else:
            num_list = list(tokens)

        res = []
        for num_str in num_list:
            n = int(num_str)
            if 1 <= n <= 26:
                d = 0
                base = 1
                off = n - base
            elif 27 <= n <= 52:
                d = 1
                base = 27
                off = n - base
            elif 53 <= n <= 78:
                d = 2
                base = 53
                off = n - base
            elif 79 <= n <= 99:
                d = 3
                base = 79
                off = n - base
            elif n == 0:
                d = 3
                base = 79
                off = 100 - base
            else:
                res.append("?")
                continue
            letter = chr(((ord(self.key_letters[d]) - ord("A") + off) % 26) + ord("A"))
            res.append(letter)
        return "".join(res)


def mexican_wheel_encrypt(text: str, key_letters: str = "AAAA") -> list[str]:
    return MexicanArmyCipherWheel(key_letters).encrypt(text)


def mexican_wheel_decrypt(tokens: list[str] | str, key_letters: str = "AAAA") -> str:
    return MexicanArmyCipherWheel(key_letters).decrypt(tokens)
