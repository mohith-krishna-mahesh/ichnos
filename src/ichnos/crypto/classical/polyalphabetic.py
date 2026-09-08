"""Polyalphabetic ciphers.

Includes Beaufort, Autokey, Gronsfeld, Porta, Trithemius (with Ave Maria variant),
Alberti, Bazeries, Bellaso, Chaocipher, Nihilist, Phillips, Ragbaby, Slidefair,
Keyword Shift, Jefferson Wheel, Solitaire (Pontifex), and Vernam / One-Time Pad.
"""

from __future__ import annotations

import re

from ichnos.core.detection import english_score
from ichnos.core.models import Candidate

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


# =============================================================================
# 1. Beaufort Cipher & Variant Beaufort
# =============================================================================


def beaufort_encrypt(text: str, key: str) -> str:
    """Beaufort cipher: C = (Key - Plaintext) mod 26. (Self-reciprocal)"""
    if not key:
        raise ValueError("Key must not be empty.")
    key = re.sub(r"[^A-Za-z]", "", key).upper()
    if not key:
        raise ValueError("Key must contain alphabetic characters.")

    res = []
    k_idx = 0
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            p_val = ord(char.upper()) - ord("A")
            k_val = ord(key[k_idx % len(key)]) - ord("A")
            c_val = (k_val - p_val) % 26
            c_char = chr(c_val + ord("A"))
            res.append(c_char if is_upper else c_char.lower())
            k_idx += 1
        else:
            res.append(char)
    return "".join(res)


def beaufort_decrypt(text: str, key: str) -> str:
    """Beaufort decrypt is identical to encrypt (self-reciprocal)."""
    return beaufort_encrypt(text, key)


def variant_beaufort_encrypt(text: str, key: str) -> str:
    """Variant Beaufort: C = (Plaintext - Key) mod 26."""
    key = re.sub(r"[^A-Za-z]", "", key).upper()
    if not key:
        raise ValueError("Key must contain alphabetic characters.")

    res = []
    k_idx = 0
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            p_val = ord(char.upper()) - ord("A")
            k_val = ord(key[k_idx % len(key)]) - ord("A")
            c_val = (p_val - k_val) % 26
            c_char = chr(c_val + ord("A"))
            res.append(c_char if is_upper else c_char.lower())
            k_idx += 1
        else:
            res.append(char)
    return "".join(res)


def variant_beaufort_decrypt(text: str, key: str) -> str:
    """Variant Beaufort decrypt: P = (Ciphertext + Key) mod 26."""
    key = re.sub(r"[^A-Za-z]", "", key).upper()
    if not key:
        raise ValueError("Key must contain alphabetic characters.")

    res = []
    k_idx = 0
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            c_val = ord(char.upper()) - ord("A")
            k_val = ord(key[k_idx % len(key)]) - ord("A")
            p_val = (c_val + k_val) % 26
            p_char = chr(p_val + ord("A"))
            res.append(p_char if is_upper else p_char.lower())
            k_idx += 1
        else:
            res.append(char)
    return "".join(res)


# =============================================================================
# 2. Autokey / Autoclave Cipher
# =============================================================================


def autokey_encrypt(text: str, key: str) -> str:
    """Plaintext Autokey cipher: keystream = key + plaintext."""
    key_clean = re.sub(r"[^A-Za-z]", "", key).upper()
    if not key_clean:
        raise ValueError("Key must contain alphabetic characters.")

    pt_letters = [c.upper() for c in text if c.isalpha()]
    keystream = key_clean + "".join(pt_letters)

    res = []
    k_idx = 0
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            p_val = ord(char.upper()) - ord("A")
            k_val = ord(keystream[k_idx]) - ord("A")
            c_val = (p_val + k_val) % 26
            c_char = chr(c_val + ord("A"))
            res.append(c_char if is_upper else c_char.lower())
            k_idx += 1
        else:
            res.append(char)
    return "".join(res)


def autokey_decrypt(text: str, key: str) -> str:
    """Plaintext Autokey decrypt: recovers plaintext character by character."""
    key_clean = re.sub(r"[^A-Za-z]", "", key).upper()
    if not key_clean:
        raise ValueError("Key must contain alphabetic characters.")

    keystream = list(key_clean)
    res = []
    k_idx = 0
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            c_val = ord(char.upper()) - ord("A")
            k_val = ord(keystream[k_idx]) - ord("A")
            p_val = (c_val - k_val) % 26
            p_char = chr(p_val + ord("A"))
            keystream.append(p_char)
            res.append(p_char if is_upper else p_char.lower())
            k_idx += 1
        else:
            res.append(char)
    return "".join(res)


# =============================================================================
# 3. Gronsfeld Cipher
# =============================================================================


def gronsfeld_encrypt(text: str, key: str | int) -> str:
    """Gronsfeld cipher: Vigenère with decimal digits key."""
    key_str = "".join(c for c in str(key) if c.isdigit())
    if not key_str:
        raise ValueError("Key must contain numeric digits.")

    res = []
    k_idx = 0
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            shift = int(key_str[k_idx % len(key_str)])
            base = ord("A") if is_upper else ord("a")
            res.append(chr((ord(char) - base + shift) % 26 + base))
            k_idx += 1
        else:
            res.append(char)
    return "".join(res)


def gronsfeld_decrypt(text: str, key: str | int) -> str:
    """Gronsfeld decrypt: inverse digit shifts."""
    key_str = "".join(c for c in str(key) if c.isdigit())
    if not key_str:
        raise ValueError("Key must contain numeric digits.")

    res = []
    k_idx = 0
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            shift = int(key_str[k_idx % len(key_str)])
            base = ord("A") if is_upper else ord("a")
            res.append(chr((ord(char) - base - shift) % 26 + base))
            k_idx += 1
        else:
            res.append(char)
    return "".join(res)


# =============================================================================
# 4. Porta Cipher
# =============================================================================

# Porta 13-alphabet tableau (reciprocal)
PORTA_TABLE = [
    ("NOPQRSTUVWXYZ", "ABCDEFGHIJKLM"),  # A, B: shift 0
    ("OPQRSTUVWXYZN", "BCDEFGHIJKLMA"),  # C, D: shift 1
    ("PQRSTUVWXYZNO", "CDEFGHIJKLMAB"),  # E, F: shift 2
    ("QRSTUVWXYZNOP", "DEFGHIJKLMABC"),  # G, H: shift 3
    ("RSTUVWXYZNOPQ", "EFGHIJKLMABCD"),  # I, J: shift 4
    ("STUVWXYZNOPQR", "FGHIJKLMABCDE"),  # K, L: shift 5
    ("TUVWXYZNOPQRS", "GHIJKLMABCDEF"),  # M, N: shift 6
    ("UVWXYZNOPQRST", "HIJKLMABCDEFG"),  # O, P: shift 7
    ("VWXYZNOPQRSTU", "IJKLMABCDEFGH"),  # Q, R: shift 8
    ("WXYZNOPQRSTUV", "JKLMABCDEFGHI"),  # S, T: shift 9
    ("XYZNOPQRSTUVW", "KLMABCDEFGHIJ"),  # U, V: shift 10
    ("YZNOPQRSTUVWX", "LMABCDEFGHIJK"),  # W, X: shift 11
    ("ZNOPQRSTUVWXY", "MABCDEFGHIJKL"),  # Y, Z: shift 12
]


def porta_encrypt(text: str, key: str) -> str:
    """Porta polyalphabetic cipher (self-reciprocal)."""
    key_clean = re.sub(r"[^A-Za-z]", "", key).upper()
    if not key_clean:
        raise ValueError("Key must contain alphabetic characters.")

    res = []
    k_idx = 0
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            cu = char.upper()
            k_char = key_clean[k_idx % len(key_clean)]
            table_idx = (ord(k_char) - ord("A")) // 2
            half2, _ = PORTA_TABLE[table_idx]

            # In Porta: if letter in A-M (0-12), it maps to half2[p_val]
            # if letter in N-Z (13-25), it maps to (half2.index(cu) + 'A')
            p_val = ord(cu) - ord("A")
            if p_val < 13:
                c_char = half2[p_val]
            else:
                c_char = chr(half2.index(cu) + ord("A"))

            res.append(c_char if is_upper else c_char.lower())
            k_idx += 1
        else:
            res.append(char)
    return "".join(res)


def porta_decrypt(text: str, key: str) -> str:
    """Porta decrypt is identical to encrypt (self-reciprocal)."""
    return porta_encrypt(text, key)


# =============================================================================
# 5. Trithemius Cipher & Ave Maria Variant
# =============================================================================


def trithemius_encrypt(text: str, start_shift: int = 0, step: int = 1) -> str:
    """Trithemius progressive shift cipher: shift increases with each letter."""
    res = []
    shift = start_shift
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            base = ord("A") if is_upper else ord("a")
            res.append(chr((ord(char) - base + shift) % 26 + base))
            shift = (shift + step) % 26
        else:
            res.append(char)
    return "".join(res)


def trithemius_decrypt(text: str, start_shift: int = 0, step: int = 1) -> str:
    """Trithemius decrypt."""
    res = []
    shift = start_shift
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            base = ord("A") if is_upper else ord("a")
            res.append(chr((ord(char) - base - shift) % 26 + base))
            shift = (shift + step) % 26
        else:
            res.append(char)
    return "".join(res)


# Trithemius Ave Maria Latin wordbook (table of 26 theological words per position)
AVE_MARIA_WORDS = [
    "Deus",
    "Creator",
    "Conditor",
    "Opifex",
    "Dominus",
    "Regnator",
    "Pater",
    "Filius",
    "Consolator",
    "Judex",
    "Salvator",
    "Redemptor",
    "Gubernator",
    "Princeps",
    "Pastor",
    "Moderator",
    "Monarcha",
    "Rex",
    "Imperator",
    "Dux",
    "Dominator",
    "Sponsus",
    "Lumen",
    "Veritas",
    "Vita",
    "Via",
]


def ave_maria_encrypt(text: str) -> str:
    """Trithemius Ave Maria theological word substitution."""
    words = []
    for char in text:
        if char.isalpha():
            idx = (ord(char.upper()) - ord("A")) % 26
            words.append(AVE_MARIA_WORDS[idx])
    return " ".join(words)


def ave_maria_decrypt(text: str) -> str:
    """Trithemius Ave Maria decrypt."""
    word_map = {w.upper(): chr(i + ord("A")) for i, w in enumerate(AVE_MARIA_WORDS)}
    res = []
    for token in text.split():
        clean = re.sub(r"[^A-Za-z]", "", token).upper()
        if clean in word_map:
            res.append(word_map[clean])
    return "".join(res)


# =============================================================================
# 6. Alberti Cipher Disk
# =============================================================================

ALBERTI_OUTER = "ABCDEFGILMNOPQRSTVXZ1234"
ALBERTI_INNER = "gklnprtvz&xysomqihfdbace"


def alberti_encrypt(text: str, index_key: str = "A", step: int = 0) -> str:
    """Alberti cipher disk encryption."""
    idx = ALBERTI_OUTER.find(index_key.upper())
    if idx == -1:
        idx = 0

    res = []
    curr_offset = idx
    for char in text:
        cu = char.upper()
        if cu in ALBERTI_OUTER:
            outer_pos = ALBERTI_OUTER.index(cu)
            inner_char = ALBERTI_INNER[(outer_pos - curr_offset) % len(ALBERTI_INNER)]
            res.append(inner_char)
            if step:
                curr_offset = (curr_offset + step) % len(ALBERTI_OUTER)
        else:
            res.append(char)
    return "".join(res)


def alberti_decrypt(text: str, index_key: str = "A", step: int = 0) -> str:
    """Alberti cipher disk decryption."""
    idx = ALBERTI_OUTER.find(index_key.upper())
    if idx == -1:
        idx = 0

    res = []
    curr_offset = idx
    for char in text:
        cl = char.lower()
        if cl in ALBERTI_INNER:
            inner_pos = ALBERTI_INNER.index(cl)
            outer_char = ALBERTI_OUTER[(inner_pos + curr_offset) % len(ALBERTI_OUTER)]
            res.append(outer_char)
            if step:
                curr_offset = (curr_offset + step) % len(ALBERTI_OUTER)
        else:
            res.append(char)
    return "".join(res)


# =============================================================================
# 7. Bazeries Cipher
# =============================================================================


def bazeries_encrypt(text: str, key_num: int) -> str:
    """Bazeries cipher: number-based transposition and substitution."""
    # Key digits define group reversal
    digits = [int(d) for d in str(key_num) if d in "123456789"]
    if not digits:
        digits = [2, 3, 4]

    letters = [c.upper() for c in text if c.isalpha()]
    # Group and reverse
    rearranged = []
    idx = 0
    d_idx = 0
    while idx < len(letters):
        size = digits[d_idx % len(digits)]
        chunk = letters[idx : idx + size]
        rearranged.extend(reversed(chunk))
        idx += size
        d_idx += 1

    return "".join(rearranged)


def bazeries_decrypt(text: str, key_num: int) -> str:
    """Bazeries cipher decryption (re-reversing matching block chunks)."""
    digits = [int(d) for d in str(key_num) if d in "123456789"]
    if not digits:
        digits = [2, 3, 4]

    letters = [c.upper() for c in text if c.isalpha()]
    restored = []
    idx = 0
    d_idx = 0
    while idx < len(letters):
        size = digits[d_idx % len(digits)]
        chunk = letters[idx : idx + size]
        restored.extend(reversed(chunk))
        idx += size
        d_idx += 1
    return "".join(restored)


# =============================================================================
# 8. Bellaso Cipher
# =============================================================================


def bellaso_encrypt(text: str, key: str) -> str:
    """Giovan Battista Bellaso cipher: reciprocal polyalphabetic with keyword."""
    return vigenere_polyalphabetic(text, key, decrypt=False)


def bellaso_decrypt(text: str, key: str) -> str:
    """Bellaso decrypt."""
    return vigenere_polyalphabetic(text, key, decrypt=True)


def vigenere_polyalphabetic(text: str, key: str, decrypt: bool = False) -> str:
    key_clean = re.sub(r"[^A-Za-z]", "", key).upper()
    if not key_clean:
        raise ValueError("Key must contain alphabetic characters.")
    res = []
    k_idx = 0
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            p_val = ord(char.upper()) - ord("A")
            k_val = ord(key_clean[k_idx % len(key_clean)]) - ord("A")
            if decrypt:
                c_val = (p_val - k_val) % 26
            else:
                c_val = (p_val + k_val) % 26
            c_char = chr(c_val + ord("A"))
            res.append(c_char if is_upper else c_char.lower())
            k_idx += 1
        else:
            res.append(char)
    return "".join(res)


# =============================================================================
# 9. Chaocipher
# =============================================================================


class Chaocipher:
    """John F. Byrne's 1918 Chaocipher with dual dynamic alphabet stepping."""

    def __init__(
        self,
        left_alphabet: str = "HXUCZVAMDSLKPEFJRIGTWOBNYQ",
        right_alphabet: str = "PTLNBQDEOYSFAVZKGJRIHWXUMC",
    ):
        self.left = list(left_alphabet)
        self.right = list(right_alphabet)

    def encrypt(self, text: str) -> str:
        left = list(self.left)
        right = list(self.right)
        res = []
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                cu = char.upper()
                if cu not in right:
                    res.append(char)
                    continue

                idx = right.index(cu)
                c_char = left[idx]
                res.append(c_char if is_upper else c_char.lower())

                # Permute left wheel: rotate idx to zenith (pos 0)
                left = left[idx:] + left[:idx]
                # Extract nadir+1 (pos 14), shift pos 2..13, insert at pos 13
                extracted = left.pop(14)
                left.insert(13, extracted)

                # Permute right wheel: rotate idx+1 to zenith
                right_rot = (idx + 1) % 26
                right = right[right_rot:] + right[:right_rot]
                # Extract nadir+2 (pos 14), shift pos 3..13, insert at pos 13
                extracted_r = right.pop(14)
                right.insert(13, extracted_r)
            else:
                res.append(char)
        return "".join(res)

    def decrypt(self, text: str) -> str:
        left = list(self.left)
        right = list(self.right)
        res = []
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                cu = char.upper()
                if cu not in left:
                    res.append(char)
                    continue

                idx = left.index(cu)
                p_char = right[idx]
                res.append(p_char if is_upper else p_char.lower())

                # Permute left
                left = left[idx:] + left[:idx]
                extracted = left.pop(14)
                left.insert(13, extracted)

                # Permute right
                right_rot = (idx + 1) % 26
                right = right[right_rot:] + right[:right_rot]
                extracted_r = right.pop(14)
                right.insert(13, extracted_r)
            else:
                res.append(char)
        return "".join(res)


def chaocipher_encrypt(
    text: str, left: str = "HXUCZVAMDSLKPEFJRIGTWOBNYQ", right: str = "PTLNBQDEOYSFAVZKGJRIHWXUMC"
) -> str:
    return Chaocipher(left, right).encrypt(text)


def chaocipher_decrypt(
    text: str, left: str = "HXUCZVAMDSLKPEFJRIGTWOBNYQ", right: str = "PTLNBQDEOYSFAVZKGJRIHWXUMC"
) -> str:
    return Chaocipher(left, right).decrypt(text)


# =============================================================================
# 10. Nihilist Cipher
# =============================================================================


def _generate_polybius_square(keyword: str = "") -> dict[str, str]:
    seen = set()
    sq = []
    clean_kw = re.sub(r"[^A-Z]", "", keyword.upper()).replace("J", "I")
    for c in clean_kw:
        if c not in seen:
            seen.add(c)
            sq.append(c)
    for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if c not in seen:
            seen.add(c)
            sq.append(c)

    coords = {}
    for r in range(5):
        for col in range(5):
            coords[sq[r * 5 + col]] = f"{r + 1}{col + 1}"
    return coords


def nihilist_encrypt(text: str, square_key: str, addition_key: str) -> list[int]:
    """Nihilist cipher: Polybius coordinates of text + Polybius coordinates of key."""
    coords = _generate_polybius_square(square_key)
    add_key_clean = re.sub(r"[^A-Z]", "", addition_key.upper()).replace("J", "I")
    if not add_key_clean:
        raise ValueError("Addition key must not be empty.")

    key_coords = [int(coords[c]) for c in add_key_clean if c in coords]
    if not key_coords:
        raise ValueError("Invalid addition key.")

    res = []
    k_idx = 0
    for char in text:
        cu = char.upper().replace("J", "I")
        if cu in coords:
            pt_coord = int(coords[cu])
            k_val = key_coords[k_idx % len(key_coords)]
            res.append(pt_coord + k_val)
            k_idx += 1
    return res


def nihilist_decrypt(numbers: list[int] | str, square_key: str, addition_key: str) -> str:
    """Nihilist cipher decryption."""
    coords = _generate_polybius_square(square_key)
    rev_coords = {int(v): k for k, v in coords.items()}
    add_key_clean = re.sub(r"[^A-Z]", "", addition_key.upper()).replace("J", "I")
    key_coords = [int(coords[c]) for c in add_key_clean if c in coords]

    if isinstance(numbers, str):
        num_list = [int(n) for n in re.findall(r"\d+", numbers)]
    else:
        num_list = list(numbers)

    res = []
    for i, num in enumerate(num_list):
        k_val = key_coords[i % len(key_coords)]
        pt_coord = num - k_val
        res.append(rev_coords.get(pt_coord, "?"))
    return "".join(res)


# =============================================================================
# 11. Phillips Cipher
# =============================================================================


def phillips_encrypt(text: str, keyword: str = "") -> str:
    """Phillips cipher using 5x5 Polybius square and row shifts."""
    coords = _generate_polybius_square(keyword)
    rev = {v: k for k, v in coords.items()}

    res = []
    clean_text = [c.upper().replace("J", "I") for c in text if c.isalpha()]
    for i, c in enumerate(clean_text):
        if c in coords:
            r, col = int(coords[c][0]), int(coords[c][1])
            # Shift row based on 5-block schedule
            shift = (i // 5) % 5
            new_r = ((r - 1 + shift) % 5) + 1
            res.append(rev.get(f"{new_r}{col}", c))
    return "".join(res)


def phillips_decrypt(text: str, keyword: str = "") -> str:
    """Phillips cipher decryption."""
    coords = _generate_polybius_square(keyword)
    rev = {v: k for k, v in coords.items()}

    res = []
    clean_text = [c.upper().replace("J", "I") for c in text if c.isalpha()]
    for i, c in enumerate(clean_text):
        if c in coords:
            r, col = int(coords[c][0]), int(coords[c][1])
            shift = (i // 5) % 5
            new_r = ((r - 1 - shift) % 5) + 1
            res.append(rev.get(f"{new_r}{col}", c))
    return "".join(res)


# =============================================================================
# 12. Ragbaby Cipher
# =============================================================================

RAGBABY_ALPHABET = "ABCDEFGHIKLMNOPQRSTUVWYZ"  # 24-char alphabet (excluding J, X)


def _make_ragbaby_alphabet(key: str = "") -> str:
    clean = re.sub(r"[^A-Z]", "", key.upper()).replace("J", "I").replace("X", "Z")
    seen = set()
    res = []
    for c in clean:
        if c in RAGBABY_ALPHABET and c not in seen:
            seen.add(c)
            res.append(c)
    for c in RAGBABY_ALPHABET:
        if c not in seen:
            seen.add(c)
            res.append(c)
    return "".join(res)


def ragbaby_encrypt(text: str, key: str = "") -> str:
    """Ragbaby cipher: word-length progressive shift with keyed alphabet."""
    alpha = _make_ragbaby_alphabet(key)
    n = len(alpha)
    words = text.split(" ")
    out_words = []

    for word in words:
        enc_word = []
        char_pos = 1
        for char in word:
            cu = char.upper().replace("J", "I").replace("X", "Z")
            if cu in alpha:
                is_upper = char.isupper()
                idx = (alpha.index(cu) + char_pos) % n
                c = alpha[idx]
                enc_word.append(c if is_upper else c.lower())
                char_pos += 1
            else:
                enc_word.append(char)
        out_words.append("".join(enc_word))

    return " ".join(out_words)


def ragbaby_decrypt(text: str, key: str = "") -> str:
    """Ragbaby cipher decryption."""
    alpha = _make_ragbaby_alphabet(key)
    n = len(alpha)
    words = text.split(" ")
    out_words = []

    for word in words:
        dec_word = []
        char_pos = 1
        for char in word:
            cu = char.upper().replace("J", "I").replace("X", "Z")
            if cu in alpha:
                is_upper = char.isupper()
                idx = (alpha.index(cu) - char_pos) % n
                c = alpha[idx]
                dec_word.append(c if is_upper else c.lower())
                char_pos += 1
            else:
                dec_word.append(char)
        out_words.append("".join(dec_word))

    return " ".join(out_words)


# =============================================================================
# 13. Slidefair Cipher
# =============================================================================


def slidefair_encrypt(text: str, key: str) -> str:
    """Slidefair digraph cipher using dual alphabet slide."""
    key_clean = re.sub(r"[^A-Z]", "", key.upper())
    if not key_clean:
        raise ValueError("Key must contain letters.")

    letters = [c.upper() for c in text if c.isalpha()]
    if len(letters) % 2 != 0:
        letters.append("X")

    res = []
    for i in range(0, len(letters), 2):
        p1, p2 = letters[i], letters[i + 1]
        k = key_clean[(i // 2) % len(key_clean)]
        k_val = ord(k) - ord("A")
        # Slide: swap column offsets
        c1 = chr(((ord(p1) - ord("A") + k_val) % 26) + ord("A"))
        c2 = chr(((ord(p2) - ord("A") - k_val) % 26) + ord("A"))
        res.extend([c1, c2])
    return "".join(res)


def slidefair_decrypt(text: str, key: str) -> str:
    """Slidefair digraph decryption."""
    key_clean = re.sub(r"[^A-Z]", "", key.upper())
    if not key_clean:
        raise ValueError("Key must contain letters.")

    letters = [c.upper() for c in text if c.isalpha()]
    res = []
    for i in range(0, len(letters), 2):
        c1, c2 = letters[i], letters[i + 1]
        k = key_clean[(i // 2) % len(key_clean)]
        k_val = ord(k) - ord("A")
        p1 = chr(((ord(c1) - ord("A") - k_val) % 26) + ord("A"))
        p2 = chr(((ord(c2) - ord("A") + k_val) % 26) + ord("A"))
        res.extend([p1, p2])
    return "".join(res)


# =============================================================================
# 14. Keyword Shift Cipher
# =============================================================================


def keyword_shift_encrypt(text: str, keyword: str, shift: int = 0) -> str:
    """Caesar cipher on a keyed alphabet."""
    seen = set()
    keyed = []
    for c in re.sub(r"[^A-Z]", "", keyword.upper()):
        if c not in seen:
            seen.add(c)
            keyed.append(c)
    for c in ALPHABET:
        if c not in seen:
            seen.add(c)
            keyed.append(c)

    keyed_alpha = "".join(keyed)
    shifted_alpha = keyed_alpha[shift % 26 :] + keyed_alpha[: shift % 26]

    res = []
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            idx = ord(char.upper()) - ord("A")
            c = shifted_alpha[idx]
            res.append(c if is_upper else c.lower())
        else:
            res.append(char)
    return "".join(res)


def keyword_shift_decrypt(text: str, keyword: str, shift: int = 0) -> str:
    """Keyword shift decrypt."""
    seen = set()
    keyed = []
    for c in re.sub(r"[^A-Z]", "", keyword.upper()):
        if c not in seen:
            seen.add(c)
            keyed.append(c)
    for c in ALPHABET:
        if c not in seen:
            seen.add(c)
            keyed.append(c)

    keyed_alpha = "".join(keyed)
    shifted_alpha = keyed_alpha[shift % 26 :] + keyed_alpha[: shift % 26]

    res = []
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            idx = shifted_alpha.index(char.upper())
            p = ALPHABET[idx]
            res.append(p if is_upper else p.lower())
        else:
            res.append(char)
    return "".join(res)


# =============================================================================
# 15. Jefferson Disk Wheel Cipher (M-94)
# =============================================================================

JEFFERSON_DISKS = [
    "ABCEIGDJFVUYMHTQKZOLNWXPXR",
    "ACDEHFGIJKLMNOQPRSTUVWXYZB",
    "KPTUVWXHYZABCEFGIJLMNOQDRS",
    "HMNOQPRSTUVWXABCEFGDIJKLYZ",
    "ZABCEFGHIJKLMNPRSTUVWXYZOD",
    "WXYZABCEFGHIJKLMNPQRSTUVOD",
    "RSTUVWXYZABCEFGHIJKLMNOPQD",
    "MNOPQRSTUVWXYZABCDEFGHIKLJ",
    "EFGHIJKLMNOPQRSTUVWXYZABCD",
    "QRSTUVWXYZABCDEFGHIJKLMNOP",
]


def jefferson_wheel_encrypt(text: str, disk_order: list[int] | None = None, offset: int = 6) -> str:
    """Jefferson disk cipher simulator."""
    if not disk_order:
        disk_order = list(range(len(JEFFERSON_DISKS)))

    letters = [c.upper() for c in text if c.isalpha()]
    res = []
    for i, c in enumerate(letters):
        d_idx = disk_order[i % len(disk_order)] % len(JEFFERSON_DISKS)
        disk = JEFFERSON_DISKS[d_idx]
        if c in disk:
            c_idx = (disk.index(c) + offset) % len(disk)
            res.append(disk[c_idx])
        else:
            res.append(c)
    return "".join(res)


def jefferson_wheel_decrypt(text: str, disk_order: list[int] | None = None, offset: int = 6) -> str:
    """Jefferson disk cipher decryption."""
    if not disk_order:
        disk_order = list(range(len(JEFFERSON_DISKS)))

    letters = [c.upper() for c in text if c.isalpha()]
    res = []
    for i, c in enumerate(letters):
        d_idx = disk_order[i % len(disk_order)] % len(JEFFERSON_DISKS)
        disk = JEFFERSON_DISKS[d_idx]
        if c in disk:
            p_idx = (disk.index(c) - offset) % len(disk)
            res.append(disk[p_idx])
        else:
            res.append(c)
    return "".join(res)


# =============================================================================
# 16. Solitaire (Pontifex) Cipher (Bruce Schneier)
# =============================================================================


class SolitaireDeck:
    """Bruce Schneier's Solitaire card deck keystream generator."""

    def __init__(self, deck: list[int] | None = None):
        # 1-52: regular cards (Clubs 1-13, Diamonds 14-26, Hearts 27-39, Spades 40-52)
        # 53: Joker A, 54: Joker B
        self.deck = list(deck) if deck is not None else list(range(1, 55))

    def step(self) -> int | None:
        """Perform 5 steps to generate 1 keystream value (1-26), or None to retry."""
        d = self.deck

        # 1. Move Joker A (53) down 1 card
        i = d.index(53)
        if i == 53:  # bottom card
            d.insert(1, d.pop(53))
        else:
            d[i], d[i + 1] = d[i + 1], d[i]

        # 2. Move Joker B (54) down 2 cards
        i = d.index(54)
        if i == 53:
            d.insert(2, d.pop(53))
        elif i == 52:
            d.insert(1, d.pop(52))
        else:
            val = d.pop(i)
            d.insert(i + 2, val)

        # 3. Triple cut around the two jokers
        j1, j2 = min(d.index(53), d.index(54)), max(d.index(53), d.index(54))
        self.deck = d[j2 + 1 :] + d[j1 : j2 + 1] + d[:j1]
        d = self.deck

        # 4. Count cut using bottom card
        bottom = d[-1]
        count = 53 if bottom in (53, 54) else bottom
        self.deck = d[count:-1] + d[:count] + [bottom]
        d = self.deck

        # 5. Output card
        top = d[0]
        top_val = 53 if top in (53, 54) else top
        card = d[top_val]
        if card in (53, 54):
            return None  # Joker, discard and repeat
        return card if card <= 26 else card - 26

    def generate_keystream(self, length: int) -> list[int]:
        stream = []
        while len(stream) < length:
            val = self.step()
            if val is not None:
                stream.append(val)
        return stream


def solitaire_encrypt(text: str, deck: list[int] | None = None) -> str:
    """Solitaire / Pontifex encryption."""
    letters = [c.upper() for c in text if c.isalpha()]
    sol = SolitaireDeck(deck)
    keystream = sol.generate_keystream(len(letters))

    res = []
    l_idx = 0
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            p_val = ord(char.upper()) - ord("A")
            k_val = keystream[l_idx]
            c_val = (p_val + k_val) % 26
            c_char = chr(c_val + ord("A"))
            res.append(c_char if is_upper else c_char.lower())
            l_idx += 1
        else:
            res.append(char)
    return "".join(res)


def solitaire_decrypt(text: str, deck: list[int] | None = None) -> str:
    """Solitaire / Pontifex decryption."""
    letters = [c.upper() for c in text if c.isalpha()]
    sol = SolitaireDeck(deck)
    keystream = sol.generate_keystream(len(letters))

    res = []
    l_idx = 0
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            c_val = ord(char.upper()) - ord("A")
            k_val = keystream[l_idx]
            p_val = (c_val - k_val) % 26
            p_char = chr(p_val + ord("A"))
            res.append(p_char if is_upper else p_char.lower())
            l_idx += 1
        else:
            res.append(char)
    return "".join(res)


# =============================================================================
# 17. Vernam / One-Time Pad
# =============================================================================


def vernam_encrypt(text: str | bytes, key: str | bytes) -> bytes:
    """Vernam / One-Time Pad byte-level XOR stream cipher."""
    data = text.encode("utf-8") if isinstance(text, str) else text
    k_bytes = key.encode("utf-8") if isinstance(key, str) else key
    if not k_bytes:
        raise ValueError("Key must not be empty.")

    out = bytearray(len(data))
    for i in range(len(data)):
        out[i] = data[i] ^ k_bytes[i % len(k_bytes)]
    return bytes(out)


def vernam_decrypt(ciphertext: str | bytes, key: str | bytes) -> bytes:
    """Vernam decrypt is identical to encrypt (self-inverse XOR)."""
    return vernam_encrypt(ciphertext, key)


# =============================================================================
# Polyalphabetic Solvers / Crackers
# =============================================================================


def crack_beaufort(ciphertext: str, key_length: int) -> Candidate:
    """Crack Beaufort cipher given candidate key length."""
    letters = [c.upper() for c in ciphertext if c.isalpha()]
    if not letters:
        return Candidate(decoded=ciphertext.encode(), method="beaufort-crack", confidence=0.0)

    key_chars = []
    for col in range(key_length):
        col_letters = [letters[i] for i in range(col, len(letters), key_length)]
        best_shift = 0
        best_score = -float("inf")
        for k in range(26):
            # Beaufort: P = (k - C) % 26
            dec_col = "".join(chr(((k - (ord(c) - ord("A"))) % 26) + ord("A")) for c in col_letters)
            score = english_score(dec_col)
            if score > best_score:
                best_score = score
                best_shift = k
        key_chars.append(chr(best_shift + ord("A")))

    key = "".join(key_chars)
    dec = beaufort_decrypt(ciphertext, key)
    score = english_score(dec)
    return Candidate(
        decoded=dec.encode(),
        method="beaufort-crack",
        confidence=min(1.0, max(0.0, score)),
        key=key,
        layers=["beaufort"],
    )
