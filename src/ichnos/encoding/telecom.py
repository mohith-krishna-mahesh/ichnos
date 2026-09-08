"""Telecom and physical layer encodings: Baudot (ITA2), Manchester, AMI, and T9 Phone Keypad."""

from __future__ import annotations

# =============================================================================
# 1. Baudot / ITA2 Teleprinter Code
# =============================================================================

ITA2_LTRS = {
    0x03: "A",
    0x19: "B",
    0x0E: "C",
    0x09: "D",
    0x01: "E",
    0x0D: "F",
    0x1A: "G",
    0x14: "H",
    0x06: "I",
    0x0B: "J",
    0x0F: "K",
    0x12: "L",
    0x1C: "M",
    0x0C: "N",
    0x18: "O",
    0x16: "P",
    0x17: "Q",
    0x0A: "R",
    0x05: "S",
    0x10: "T",
    0x07: "U",
    0x1E: "V",
    0x13: "W",
    0x1D: "X",
    0x15: "Y",
    0x11: "Z",
    0x04: " ",
    0x08: "\r",
    0x02: "\n",
}

ITA2_FIGS = {
    0x03: "-",
    0x19: "?",
    0x0E: ":",
    0x09: "$",
    0x01: "3",
    0x0D: "!",
    0x1A: "&",
    0x14: "#",
    0x06: "8",
    0x0B: "'",
    0x0F: "(",
    0x12: ")",
    0x1C: ".",
    0x0C: ",",
    0x18: "9",
    0x16: "0",
    0x17: "1",
    0x0A: "4",
    0x05: "'",
    0x10: "5",
    0x07: "7",
    0x1E: ";",
    0x13: "2",
    0x1D: "/",
    0x15: "6",
    0x11: "+",
    0x04: " ",
    0x08: "\r",
    0x02: "\n",
}

ITA2_SHIFT_LTRS = 0x1F
ITA2_SHIFT_FIGS = 0x1B


def encode_baudot(text: str) -> list[int]:
    """Encodes text to ITA2 5-bit Baudot code sequence with LTRS/FIGS shift characters."""
    rev_ltrs = {v: k for k, v in ITA2_LTRS.items()}
    rev_figs = {v: k for k, v in ITA2_FIGS.items()}

    res = [ITA2_SHIFT_LTRS]
    in_figs = False

    for c in text.upper():
        if c in rev_ltrs and (not in_figs or c in " \r\n"):
            res.append(rev_ltrs[c])
        elif c in rev_figs:
            if not in_figs:
                res.append(ITA2_SHIFT_FIGS)
                in_figs = True
            res.append(rev_figs[c])
        elif c in rev_ltrs:
            if in_figs:
                res.append(ITA2_SHIFT_LTRS)
                in_figs = False
            res.append(rev_ltrs[c])
    return res


def decode_baudot(codes: list[int] | str) -> str:
    """Decodes ITA2 5-bit Baudot code sequence."""
    if isinstance(codes, str):
        num_list = [int(x, 2) if set(x).issubset({"0", "1"}) else int(x) for x in codes.split()]
    else:
        num_list = list(codes)

    res = []
    in_figs = False
    for code in num_list:
        if code == ITA2_SHIFT_LTRS:
            in_figs = False
        elif code == ITA2_SHIFT_FIGS:
            in_figs = True
        else:
            table = ITA2_FIGS if in_figs else ITA2_LTRS
            if code in table:
                res.append(table[code])
    return "".join(res)


# =============================================================================
# 2. Manchester Encoding
# =============================================================================


def encode_manchester(bits: str) -> str:
    """Encodes bit string using IEEE 802.3 Manchester encoding (0 -> '01', 1 -> '10')."""
    return "".join("01" if b == "0" else "10" for b in bits if b in "01")


def decode_manchester(manchester_bits: str) -> str:
    """Decodes IEEE 802.3 Manchester encoding to bits."""
    clean = [b for b in manchester_bits if b in "01"]
    res = []
    for i in range(0, len(clean) - 1, 2):
        pair = clean[i] + clean[i + 1]
        if pair == "01":
            res.append("0")
        elif pair == "10":
            res.append("1")
        else:
            res.append("?")
    return "".join(res)


# =============================================================================
# 3. Alternate Mark Inversion (AMI)
# =============================================================================


def encode_ami(bits: str) -> list[int]:
    """Encodes binary bits using Alternate Mark Inversion (0 -> 0, 1 -> alternating +1/-1)."""
    res = []
    polarity = 1
    for b in bits:
        if b == "0":
            res.append(0)
        elif b == "1":
            res.append(polarity)
            polarity = -polarity
    return res


def decode_ami(levels: list[int]) -> str:
    """Decodes Alternate Mark Inversion levels back to binary bits."""
    return "".join("0" if x == 0 else "1" for x in levels)


# =============================================================================
# 4. T9 / Multi-tap Phone Keypad
# =============================================================================

T9_KEYPAD = {
    "A": "2",
    "B": "22",
    "C": "222",
    "D": "3",
    "E": "33",
    "F": "333",
    "G": "4",
    "H": "44",
    "I": "444",
    "J": "5",
    "K": "55",
    "L": "555",
    "M": "6",
    "N": "66",
    "O": "666",
    "P": "7",
    "Q": "77",
    "R": "777",
    "S": "7777",
    "T": "8",
    "U": "88",
    "V": "888",
    "W": "9",
    "X": "99",
    "Y": "999",
    "Z": "9999",
    " ": "0",
}


def encode_t9(text: str) -> str:
    """Encodes text to multi-tap phone keypad numbers separated by spaces."""
    return " ".join(T9_KEYPAD[c.upper()] for c in text if c.upper() in T9_KEYPAD)


def decode_t9(presses: str) -> str:
    """Decodes multi-tap phone keypad numbers separated by spaces."""
    rev_t9 = {v: k for k, v in T9_KEYPAD.items()}
    tokens = presses.split()
    return "".join(rev_t9.get(tok, "?") for tok in tokens)
