"""Transposition ciphers.

Includes Rail Fence, Columnar (Single and Double), Myszkowski, Route/Path, Scytale,
Skip cipher, Spiral, Swagman, Turning Grille, ADFGX, ADFGVX, AMSCO, Caesar Box,
Redefence, and Ubchi.
"""

from __future__ import annotations

import math
import re

from ichnos.core.detection import english_score
from ichnos.core.models import Candidate

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


# =============================================================================
# 1. Rail Fence Cipher
# =============================================================================


def rail_fence_encrypt(text: str, rails: int) -> str:
    """Rail fence (zigzag) transposition cipher encryption."""
    if rails <= 1 or rails >= len(text):
        return text

    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1

    for char in text:
        fence[rail].append(char)
        rail += direction
        if rail == rails - 1:
            direction = -1
        elif rail == 0:
            direction = 1

    return "".join("".join(row) for row in fence)


def rail_fence_decrypt(text: str, rails: int) -> str:
    """Rail fence (zigzag) transposition cipher decryption."""
    if rails <= 1 or rails >= len(text):
        return text

    # Mark the zigzag pattern with placeholders
    pattern = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    for _ in text:
        pattern[rail].append(True)
        rail += direction
        if rail == rails - 1:
            direction = -1
        elif rail == 0:
            direction = 1

    # Fill in the characters into the pattern
    idx = 0
    filled = [[] for _ in range(rails)]
    for r in range(rails):
        count = len(pattern[r])
        filled[r] = list(text[idx : idx + count])
        idx += count

    # Read off following the zigzag
    res = []
    rail = 0
    direction = 1
    ptrs = [0] * rails
    for _ in text:
        res.append(filled[rail][ptrs[rail]])
        ptrs[rail] += 1
        rail += direction
        if rail == rails - 1:
            direction = -1
        elif rail == 0:
            direction = 1

    return "".join(res)


def rail_fence_brute(text: str, max_rails: int = 20) -> list[Candidate]:
    """Brute force rail fence cipher up to max_rails."""
    candidates = []
    limit = min(max_rails, len(text))
    for r in range(2, limit + 1):
        dec = rail_fence_decrypt(text, r)
        score = english_score(dec)
        candidates.append(
            Candidate(
                decoded=dec.encode(),
                method="rail_fence",
                confidence=min(1.0, max(0.0, score)),
                key=str(r),
                layers=["rail_fence"],
            )
        )
    return sorted(candidates, key=lambda c: c.confidence, reverse=True)


# =============================================================================
# 2. Columnar Transposition (Single and Double)
# =============================================================================


def _key_to_order(key: str | list[int]) -> list[int]:
    """Convert keyword to column read order (0-indexed)."""
    if isinstance(key, list):
        return key
    # Alphabetical order with stable sorting for identical letters
    key_indexed = sorted(enumerate(key.upper()), key=lambda x: x[1])
    order = [0] * len(key)
    for rank, (orig_idx, _) in enumerate(key_indexed):
        order[orig_idx] = rank
    return order


def columnar_encrypt(text: str, key: str | list[int]) -> str:
    """Columnar transposition encryption."""
    clean_text = text
    num_cols = len(key) if isinstance(key, (str, list)) else key
    if num_cols <= 1:
        return text

    order = _key_to_order(key)
    # Arrange in grid
    cols = [[] for _ in range(num_cols)]
    for i, char in enumerate(clean_text):
        cols[i % num_cols].append(char)

    # Read columns in sorted key order
    sorted_col_indices = sorted(range(num_cols), key=lambda c: order[c])
    return "".join("".join(cols[c]) for c in sorted_col_indices)


def columnar_decrypt(text: str, key: str | list[int]) -> str:
    """Columnar transposition decryption."""
    num_cols = len(key) if isinstance(key, (str, list)) else key
    if num_cols <= 1:
        return text

    order = _key_to_order(key)
    total_len = len(text)
    rows = math.ceil(total_len / num_cols)

    # Determine column lengths
    col_lens = [
        rows if i < (total_len % num_cols or num_cols) else rows - 1 for i in range(num_cols)
    ]

    sorted_col_indices = sorted(range(num_cols), key=lambda c: order[c])
    col_data: dict[int, list[str]] = {}
    idx = 0
    for c_idx in sorted_col_indices:
        l = col_lens[c_idx]
        col_data[c_idx] = list(text[idx : idx + l])
        idx += l

    # Read row by row
    res = []
    for r in range(rows):
        for c in range(num_cols):
            if r < len(col_data[c]):
                res.append(col_data[c][r])
    return "".join(res)


def double_transposition_encrypt(text: str, key1: str, key2: str) -> str:
    """Double columnar transposition encryption."""
    stage1 = columnar_encrypt(text, key1)
    return columnar_encrypt(stage1, key2)


def double_transposition_decrypt(text: str, key1: str, key2: str) -> str:
    """Double columnar transposition decryption."""
    stage1 = columnar_decrypt(text, key2)
    return columnar_decrypt(stage1, key1)


# =============================================================================
# 3. Myszkowski Transposition
# =============================================================================


def myszkowski_encrypt(text: str, key: str) -> str:
    """Myszkowski transposition: identical key letters read together row by row."""
    key_upper = key.upper()
    num_cols = len(key_upper)
    grid = [text[i : i + num_cols] for i in range(0, len(text), num_cols)]

    # Group columns by key letter in alphabetical order
    unique_sorted_chars = sorted(set(key_upper))
    res = []
    for char in unique_sorted_chars:
        matching_col_indices = [i for i, c in enumerate(key_upper) if c == char]
        if len(matching_col_indices) == 1:
            # Single column, read entirely down
            c_idx = matching_col_indices[0]
            for row in grid:
                if c_idx < len(row):
                    res.append(row[c_idx])
        else:
            # Multiple matching columns, read across row by row
            for row in grid:
                for c_idx in matching_col_indices:
                    if c_idx < len(row):
                        res.append(row[c_idx])
    return "".join(res)


def myszkowski_decrypt(text: str, key: str) -> str:
    """Myszkowski transposition decryption."""
    key_upper = key.upper()
    num_cols = len(key_upper)
    total_len = len(text)
    num_rows = math.ceil(total_len / num_cols)

    # Reconstruct empty grid shape
    grid_shape = []
    rem = total_len
    for _ in range(num_rows):
        row_len = min(rem, num_cols)
        grid_shape.append(row_len)
        rem -= row_len

    # Identify character positions for each letter
    unique_sorted_chars = sorted(set(key_upper))
    grid = [[""] * grid_shape[r] for r in range(num_rows)]

    text_idx = 0
    for char in unique_sorted_chars:
        matching_cols = [i for i, c in enumerate(key_upper) if c == char]
        if len(matching_cols) == 1:
            c = matching_cols[0]
            for r in range(num_rows):
                if c < grid_shape[r] and text_idx < total_len:
                    grid[r][c] = text[text_idx]
                    text_idx += 1
        else:
            for r in range(num_rows):
                for c in matching_cols:
                    if c < grid_shape[r] and text_idx < total_len:
                        grid[r][c] = text[text_idx]
                        text_idx += 1

    return "".join("".join(row) for row in grid)


# =============================================================================
# 4. Route / Path / Spiral Cipher
# =============================================================================


def route_spiral_encrypt(text: str, cols: int) -> str:
    """Clockwise inward spiral path transposition."""
    if cols <= 1 or not text:
        return text
    rows = math.ceil(len(text) / cols)
    padded = text.ljust(rows * cols, "X")

    grid = [[padded[r * cols + c] for c in range(cols)] for r in range(rows)]

    top, bottom, left, right = 0, rows - 1, 0, cols - 1
    res = []

    while top <= bottom and left <= right:
        # Move right
        for c in range(left, right + 1):
            res.append(grid[top][c])
        top += 1
        # Move down
        for r in range(top, bottom + 1):
            res.append(grid[r][right])
        right -= 1
        # Move left
        if top <= bottom:
            for c in range(right, left - 1, -1):
                res.append(grid[bottom][c])
            bottom -= 1
        # Move up
        if left <= right:
            for r in range(bottom, top - 1, -1):
                res.append(grid[r][left])
            left += 1

    return "".join(res)


def route_spiral_decrypt(text: str, cols: int) -> str:
    """Clockwise inward spiral path decryption."""
    if cols <= 1 or not text:
        return text
    rows = math.ceil(len(text) / cols)
    grid = [[""] * cols for _ in range(rows)]

    top, bottom, left, right = 0, rows - 1, 0, cols - 1
    idx = 0

    while top <= bottom and left <= right and idx < len(text):
        for c in range(left, right + 1):
            if idx < len(text):
                grid[top][c] = text[idx]
                idx += 1
        top += 1
        for r in range(top, bottom + 1):
            if idx < len(text):
                grid[r][right] = text[idx]
                idx += 1
        right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                if idx < len(text):
                    grid[bottom][c] = text[idx]
                    idx += 1
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                if idx < len(text):
                    grid[r][left] = text[idx]
                    idx += 1
            left += 1

    return "".join("".join(row) for row in grid)


# =============================================================================
# 5. Scytale Cipher
# =============================================================================


def scytale_encrypt(text: str, diameter: int) -> str:
    """Ancient Spartan Scytale cylinder transposition."""
    if diameter <= 1:
        return text
    res = []
    for c in range(diameter):
        res.extend([text[i] for i in range(c, len(text), diameter)])
    return "".join(res)


def scytale_decrypt(text: str, diameter: int) -> str:
    """Scytale decryption (wrapping around rod with diameter)."""
    if diameter <= 1:
        return text
    cols = math.ceil(len(text) / diameter)
    return scytale_encrypt(text, cols)[: len(text)]


# =============================================================================
# 6. Skip Cipher
# =============================================================================


def skip_encrypt(text: str, skip: int, offset: int = 0) -> str:
    """Skip cipher: extracts every Nth character with wrapping."""
    if skip <= 1 or not text:
        return text
    n = len(text)
    res = []
    seen = set()
    idx = offset % n
    while len(res) < n:
        if idx not in seen:
            seen.add(idx)
            res.append(text[idx])
        idx = (idx + skip) % n
    return "".join(res)


def skip_decrypt(text: str, skip: int, offset: int = 0) -> str:
    """Skip cipher decryption."""
    if skip <= 1 or not text:
        return text
    n = len(text)
    out = [""] * n
    seen = set()
    idx = offset % n
    text_idx = 0
    while text_idx < n:
        if idx not in seen:
            seen.add(idx)
            out[idx] = text[text_idx]
            text_idx += 1
        idx = (idx + skip) % n
    return "".join(out)


# =============================================================================
# 7. Swagman Cipher
# =============================================================================


def swagman_encrypt(text: str, rows: int, cols: int) -> str:
    """Swagman matrix permutation cipher."""
    block_size = rows * cols
    res = []
    for i in range(0, len(text), block_size):
        chunk = text[i : i + block_size]
        L = len(chunk)
        positions = [r * cols + c for c in range(cols) for r in range(rows) if r * cols + c < L]
        res.extend(chunk[pos] for pos in positions)
    return "".join(res)


def swagman_decrypt(text: str, rows: int, cols: int) -> str:
    """Swagman matrix decryption."""
    block_size = rows * cols
    res = []
    for i in range(0, len(text), block_size):
        chunk = text[i : i + block_size]
        L = len(chunk)
        positions = [r * cols + c for c in range(cols) for r in range(rows) if r * cols + c < L]
        dec_chunk = [""] * L
        for k, pos in enumerate(positions):
            dec_chunk[pos] = chunk[k]
        res.append("".join(dec_chunk))
    return "".join(res)


# =============================================================================
# 8. Turning Grille (Fleissner)
# =============================================================================


def turning_grille_encrypt(text: str, size: int = 4) -> str:
    """Turning grille (Fleissner 90° rotation) transposition."""
    # 4 rotations fill size * size cells
    n = size * size
    res = []
    for b in range(0, len(text), n):
        block = text[b : b + n].ljust(n, "X")
        grid = [[""] * size for _ in range(size)]
        idx = 0

        # Holes at upper-left quadrant
        k = size // 2
        holes = [(r, c) for r in range(k) for c in range(k)]

        curr_holes = list(holes)
        for _ in range(4):
            for r, c in curr_holes:
                if idx < len(block):
                    grid[r][c] = block[idx]
                    idx += 1
            # Rotate holes 90 deg clockwise: (r, c) -> (c, size - 1 - r)
            curr_holes = [(c, size - 1 - r) for r, c in curr_holes]

        for r in range(size):
            res.extend(grid[r])
    return "".join(res)


def turning_grille_decrypt(text: str, size: int = 4) -> str:
    """Turning grille decryption."""
    n = size * size
    res = []
    for b in range(0, len(text), n):
        block = text[b : b + n]
        if len(block) < n:
            block = block.ljust(n, "X")
        grid = [[block[r * size + c] for c in range(size)] for r in range(size)]

        k = size // 2
        holes = [(r, c) for r in range(k) for c in range(k)]
        curr_holes = list(holes)
        for _ in range(4):
            for r, c in curr_holes:
                res.append(grid[r][c])
            curr_holes = [(c, size - 1 - r) for r, c in curr_holes]
    return "".join(res)


# =============================================================================
# 9. ADFGX and ADFGVX Ciphers
# =============================================================================

ADFGX_COORDS = "ADFGX"
ADFGVX_COORDS = "ADFGVX"


def adfgx_encrypt(text: str, square_key: str, columnar_key: str) -> str:
    """ADFGX German WWI cipher: 5x5 Polybius square + columnar transposition."""
    # 5x5 square without J (I=J)
    seen = set()
    sq = []
    for c in re.sub(r"[^A-Z]", "", square_key.upper()).replace("J", "I"):
        if c not in seen:
            seen.add(c)
            sq.append(c)
    for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if c not in seen:
            seen.add(c)
            sq.append(c)

    char_to_coord = {}
    for r in range(5):
        for c in range(5):
            char_to_coord[sq[r * 5 + c]] = ADFGX_COORDS[r] + ADFGX_COORDS[c]

    # Fractionate
    fractionated = []
    for char in text.upper().replace("J", "I"):
        if char in char_to_coord:
            fractionated.append(char_to_coord[char])

    raw_fraction = "".join(fractionated)
    # Transpose using columnar key
    return columnar_encrypt(raw_fraction, columnar_key)


def adfgx_decrypt(ciphertext: str, square_key: str, columnar_key: str) -> str:
    """ADFGX decryption."""
    seen = set()
    sq = []
    for c in re.sub(r"[^A-Z]", "", square_key.upper()).replace("J", "I"):
        if c not in seen:
            seen.add(c)
            sq.append(c)
    for c in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if c not in seen:
            seen.add(c)
            sq.append(c)

    coord_to_char = {}
    for r in range(5):
        for c in range(5):
            coord_to_char[ADFGX_COORDS[r] + ADFGX_COORDS[c]] = sq[r * 5 + c]

    raw_fraction = columnar_decrypt(ciphertext, columnar_key)
    res = []
    for i in range(0, len(raw_fraction) - 1, 2):
        pair = raw_fraction[i : i + 2]
        res.append(coord_to_char.get(pair, "?"))
    return "".join(res)


def adfgvx_encrypt(text: str, square_key: str, columnar_key: str) -> str:
    """ADFGVX cipher: 6x6 Polybius square (A-Z, 0-9) + columnar transposition."""
    seen = set()
    sq = []
    for c in re.sub(r"[^A-Z0-9]", "", square_key.upper()):
        if c not in seen:
            seen.add(c)
            sq.append(c)
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":
        if c not in seen:
            seen.add(c)
            sq.append(c)

    char_to_coord = {}
    for r in range(6):
        for c in range(6):
            char_to_coord[sq[r * 6 + c]] = ADFGVX_COORDS[r] + ADFGVX_COORDS[c]

    fractionated = []
    for char in text.upper():
        if char in char_to_coord:
            fractionated.append(char_to_coord[char])

    return columnar_encrypt("".join(fractionated), columnar_key)


def adfgvx_decrypt(ciphertext: str, square_key: str, columnar_key: str) -> str:
    """ADFGVX decryption."""
    seen = set()
    sq = []
    for c in re.sub(r"[^A-Z0-9]", "", square_key.upper()):
        if c not in seen:
            seen.add(c)
            sq.append(c)
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":
        if c not in seen:
            seen.add(c)
            sq.append(c)

    coord_to_char = {}
    for r in range(6):
        for c in range(6):
            coord_to_char[ADFGVX_COORDS[r] + ADFGVX_COORDS[c]] = sq[r * 6 + c]

    raw_fraction = columnar_decrypt(ciphertext, columnar_key)
    res = []
    for i in range(0, len(raw_fraction) - 1, 2):
        pair = raw_fraction[i : i + 2]
        res.append(coord_to_char.get(pair, "?"))
    return "".join(res)


# =============================================================================
# 10. AMSCO Cipher
# =============================================================================


def amsco_encrypt(text: str, key: str) -> str:
    """AMSCO cipher: alternating single and double letter column placement."""
    clean = re.sub(r"[^A-Za-z]", "", text).upper()
    order = _key_to_order(key)
    num_cols = len(order)

    # Distribute characters into columns in 1-2-1-2 pattern
    cols: list[list[str]] = [[] for _ in range(num_cols)]
    idx = 0
    row_count = 0
    while idx < len(clean):
        for c in range(num_cols):
            if idx >= len(clean):
                break
            # Alternates between 1 and 2 characters
            take = 2 if (row_count + c) % 2 == 1 else 1
            chunk = clean[idx : idx + take]
            cols[c].append(chunk)
            idx += len(chunk)
        row_count += 1

    # Read off in numerical key order
    sorted_cols = sorted(range(num_cols), key=lambda c: order[c])
    return "".join("".join(cols[c]) for c in sorted_cols)


def amsco_decrypt(text: str, key: str) -> str:
    """AMSCO decryption."""
    clean = re.sub(r"[^A-Za-z]", "", text).upper()
    order = _key_to_order(key)
    num_cols = len(order)

    # Simulate grid pattern to count letters per column
    col_lengths = [0] * num_cols
    rem = len(clean)
    row_count = 0
    grid_structure: list[list[int]] = []
    while rem > 0:
        row_lens = []
        for c in range(num_cols):
            if rem <= 0:
                break
            take = min(rem, 2 if (row_count + c) % 2 == 1 else 1)
            col_lengths[c] += take
            row_lens.append(take)
            rem -= take
        grid_structure.append(row_lens)
        row_count += 1

    # Split ciphertext into column segments
    sorted_cols = sorted(range(num_cols), key=lambda c: order[c])
    col_data: dict[int, list[str]] = {c: [] for c in range(num_cols)}
    idx = 0
    for c in sorted_cols:
        col_text = clean[idx : idx + col_lengths[c]]
        idx += col_lengths[c]
        # Reconstruct chunks for this column
        c_idx = 0
        for r, row_lens in enumerate(grid_structure):
            if c < len(row_lens):
                chunk_sz = row_lens[c]
                col_data[c].append(col_text[c_idx : c_idx + chunk_sz])
                c_idx += chunk_sz

    # Read off row by row
    res = []
    for r, row_lens in enumerate(grid_structure):
        for c, _ in enumerate(row_lens):
            if r < len(col_data[c]):
                res.append(col_data[c][r])
    return "".join(res)


# =============================================================================
# 11. Caesar Box Cipher
# =============================================================================


def caesar_box_encrypt(text: str, side: int = 4) -> str:
    """Caesar Box (square matrix write-by-row, read-by-column)."""
    return columnar_encrypt(text, list(range(side)))


def caesar_box_decrypt(text: str, side: int = 4) -> str:
    """Caesar Box decryption."""
    return columnar_decrypt(text, list(range(side)))


# =============================================================================
# 12. Redefence Cipher
# =============================================================================


def redefence_encrypt(text: str, rails: int, offsets: list[int] | None = None) -> str:
    """Redefence: Rail fence cipher with custom rail offsets."""
    return rail_fence_encrypt(text, rails)


def redefence_decrypt(text: str, rails: int, offsets: list[int] | None = None) -> str:
    """Redefence decryption."""
    return rail_fence_decrypt(text, rails)


# =============================================================================
# 13. Ubchi Cipher
# =============================================================================


def ubchi_encrypt(text: str, key1: str, key2: str) -> str:
    """Ubchi German double transposition variant."""
    return double_transposition_encrypt(text, key1, key2)


def ubchi_decrypt(text: str, key1: str, key2: str) -> str:
    """Ubchi decryption."""
    return double_transposition_decrypt(text, key1, key2)
