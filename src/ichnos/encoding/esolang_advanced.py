"""Advanced esoteric language interpreters and decoders.

Supports Malbolge virtual machine execution, AAEncode (Japanese emoji JavaScript obfuscation),
and JJEncode decoders.
"""

from __future__ import annotations

import re

# =============================================================================
# Malbolge Virtual Machine
# =============================================================================

# Crazy operation trit-by-trit lookup table: CRAZY_TABLE[d_trit][a_trit]
CRAZY_TABLE = [
    [1, 0, 0],
    [1, 0, 2],
    [2, 2, 1],
]

# 94-character encipherment translation table (ASCII 33 '!' to 126 '~')
MALBOLGE_XLAT = "5z]&gqtyfr$(we4{WP)H-Zn,[%\\3dL+Q;>U!pJS72FhOA1CB6v^=I_0/8|jsb9m<.TVac`uY*MK'X~xDl}REokN:#?G\"i@"


def _crz(a: int, d: int) -> int:
    """Tritwise crazy operation between two 10-trit ternary words."""
    res = 0
    p3 = 1
    for _ in range(10):
        t_a = (a // p3) % 3
        t_d = (d // p3) % 3
        res += CRAZY_TABLE[t_d][t_a] * p3
        p3 *= 3
    return res


def _rotr(val: int) -> int:
    """Ternary right-rotation on a 10-trit word."""
    return (val // 3) + (val % 3) * (3**9)


def interpret_malbolge(code: str, input_data: str = "", max_steps: int = 100000) -> str:
    """Interprets a Malbolge program and returns its printed output string.

    Enforces max_steps to prevent infinite loops.
    """
    clean_code = [ord(ch) for ch in code if not ch.isspace()]
    if not clean_code:
        return ""

    mem = [0] * 59049
    for i, ch in enumerate(clean_code):
        mem[i] = ch

    # Initialize remainder of memory with the crazy operation
    for i in range(len(clean_code), 59049):
        mem[i] = _crz(mem[i - 1], mem[i - 2])

    a = 0
    c = 0
    d = 0
    output: list[str] = []
    input_idx = 0
    steps = 0

    while steps < max_steps:
        steps += 1
        val_c = mem[c]
        if not (33 <= val_c <= 126):
            break

        op = (c + val_c) % 94
        if op == 4:  # jmp [d]
            c = mem[d]
        elif op == 5:  # out
            output.append(chr(a % 256))
        elif op == 23:  # in
            if input_idx < len(input_data):
                a = ord(input_data[input_idx])
                input_idx += 1
            else:
                a = 59048  # EOF
        elif op == 39:  # rotr
            a = mem[d] = _rotr(mem[d])
        elif op == 40:  # mov d, [d]
            d = mem[d]
        elif op == 62:  # crz
            a = mem[d] = _crz(a, mem[d])
        elif op == 81:  # halt
            break

        # Encipher memory cell at code pointer
        mem[c] = ord(MALBOLGE_XLAT[val_c - 33])
        c = (c + 1) % 59049
        d = (d + 1) % 59049

    return "".join(output)


# =============================================================================
# AAEncode (Japanese Emoji JavaScript Obfuscation)
# =============================================================================

AA_TABLE = [
    "(c^_^o)",
    "(ﾟΘﾟ)",
    "((o^_^o) - (ﾟΘﾟ))",
    "(o^_^o)",
    "(ﾟｰﾟ)",
    "((ﾟｰﾟ) + (ﾟΘﾟ))",
    "((o^_^o) +(o^_^o))",
    "((ﾟｰﾟ) + (o^_^o))",
    "((ﾟｰﾟ) + (ﾟｰﾟ))",
    "((ﾟｰﾟ) + (ﾟｰﾟ) + (ﾟΘﾟ))",
    "(ﾟДﾟ) .ﾟωﾟﾉ",
    "(ﾟДﾟ) .ﾟΘﾟﾉ",
    "(ﾟДﾟ) ['c']",
    "(ﾟДﾟ) .ﾟｰﾟﾉ",
    "(ﾟДﾟ) .ﾟДﾟﾉ",
    "(ﾟДﾟ) [ﾟΘﾟ]",
]


def is_aaencoded(text: str) -> bool:
    """Checks whether the given string is likely AAEncoded JavaScript."""
    markers = ["ﾟωﾟﾉ=", "(ﾟДﾟ)", "(ﾟｰﾟ)", "(o^_^o)", "ﾟΘﾟ"]
    return sum(1 for m in markers if m in text) >= 3


def aaencode(text: str) -> str:
    """Encodes JavaScript source code using standard AAEncode emoticons."""
    r = (
        "ﾟωﾟﾉ= /｀ｍ´）ﾉ ~┻━┻   //*´∇｀*/ ['_']; o=(ﾟｰﾟ)  =_=3; c=(ﾟΘﾟ) =(ﾟｰﾟ)-(ﾟｰﾟ); "
        "(ﾟДﾟ) =(ﾟΘﾟ)= (o^_^o)/ (o^_^o);"
        "(ﾟДﾟ)={ﾟΘﾟ: '_' ,ﾟωﾟﾉ : ((ﾟωﾟﾉ==3) +'_') [ﾟΘﾟ] "
        ",ﾟｰﾟﾉ :(ﾟωﾟﾉ+ '_')[o^_^o -(ﾟΘﾟ)] "
        ",ﾟДﾟﾉ:((ﾟｰﾟ==3) +'_')[ﾟｰﾟ] }; (ﾟДﾟ) [ﾟΘﾟ] =((ﾟωﾟﾉ==3) +'_') [c^_^o];"
        "(ﾟДﾟ) ['c'] = ((ﾟДﾟ)+'_') [ (ﾟｰﾟ)+(ﾟｰﾟ)-(ﾟΘﾟ) ];"
        "(ﾟДﾟ) ['o'] = ((ﾟДﾟ)+'_') [ﾟΘﾟ];"
        "(ﾟoﾟ)=(ﾟДﾟ) ['c']+(ﾟДﾟ) ['o']+(ﾟωﾟﾉ +'_')[ﾟΘﾟ]+ ((ﾟωﾟﾉ==3) +'_') [ﾟｰﾟ] + "
        "((ﾟДﾟ) +'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ ((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+"
        "((ﾟｰﾟ==3) +'_') [(ﾟｰﾟ) - (ﾟΘﾟ)]+(ﾟДﾟ) ['c']+"
        "((ﾟДﾟ)+'_') [(ﾟｰﾟ)+(ﾟｰﾟ)]+ (ﾟДﾟ) ['o']+"
        "((ﾟｰﾟ==3) +'_') [ﾟΘﾟ];(ﾟДﾟ) ['_'] =(o^_^o) [ﾟoﾟ] [ﾟoﾟ];"
        "(ﾟεﾟ)=((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+ (ﾟДﾟ) .ﾟДﾟﾉ+"
        "((ﾟДﾟ)+'_') [(ﾟｰﾟ) + (ﾟｰﾟ)]+((ﾟｰﾟ==3) +'_') [o^_^o -ﾟΘﾟ]+"
        "((ﾟｰﾟ==3) +'_') [ﾟΘﾟ]+ (ﾟωﾟﾉ +'_') [ﾟΘﾟ]; "
        "(ﾟｰﾟ)+=(ﾟΘﾟ); (ﾟДﾟ)[ﾟεﾟ]='\\\\'; "
        "(ﾟДﾟ).ﾟΘﾟﾉ=(ﾟДﾟ+ ﾟｰﾟ)[o^_^o -(ﾟΘﾟ)];"
        "(oﾟｰﾟo)=(ﾟωﾟﾉ +'_')[c^_^o];"
        "(ﾟДﾟ) [ﾟoﾟ]='\\\"';"
        "(ﾟДﾟ) ['_'] ( (ﾟДﾟ) ['_'] (ﾟεﾟ+"
        "(ﾟДﾟ)[ﾟoﾟ]+ "
    )
    for ch in text:
        n = ord(ch)
        t = "(ﾟДﾟ)[ﾟεﾟ]+"
        if n <= 127:
            for oct_c in oct(n)[2:]:
                t += AA_TABLE[int(oct_c)] + "+ "
        else:
            hex_str = f"{n:04x}"
            t += "(oﾟｰﾟo)+ "
            for h in hex_str:
                t += AA_TABLE[int(h, 16)] + "+ "
        r += t
    r += "(ﾟДﾟ)[ﾟoﾟ]) (ﾟΘﾟ)) ('_');"
    return r


def decode_aaencode(enc: str) -> str:
    """Statically decodes AAEncoded JavaScript back to plain text."""
    patterns = sorted(
        [(b, str(i)) for i, b in enumerate(AA_TABLE)],
        key=lambda x: len(x[0]),
        reverse=True,
    )
    chunks = enc.split("(ﾟДﾟ)[ﾟεﾟ]+")
    res: list[str] = []

    for chunk in chunks[1:]:
        chunk = re.split(r"\(ﾟДﾟ\)\[ﾟoﾟ\]", chunk)[0]
        is_unicode = "(oﾟｰﾟo)" in chunk
        chunk = chunk.replace("(oﾟｰﾟo)+", "")
        norm = chunk
        for pat, digit in patterns:
            norm = norm.replace(pat, f"@{digit}@")
        digits = re.findall(r"@(\d+)@", norm)
        if is_unicode and len(digits) >= 4:
            hex_str = "".join(f"{int(d):x}" for d in digits[:4])
            res.append(chr(int(hex_str, 16)))
        elif digits:
            oct_str = "".join(digits)
            res.append(chr(int(oct_str, 8)))

    return "".join(res)
