"""Base encodings (hex, base16, base32, base58, base64, base85, base91)."""

import base64
import re

from ichnos.core.detection import printable_ratio
from ichnos.core.models import Candidate

BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE91_ALPHABET = (
    b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
)


def encode_hex(data: bytes) -> str:
    """Encode bytes to hex string."""
    return data.hex()


def decode_hex(s: str) -> bytes:
    """Decode hex string to bytes."""
    s = s.strip()
    if len(s) % 2 != 0:
        s = "0" + s
    return bytes.fromhex(s)


def encode_base16(data: bytes) -> str:
    """Encode bytes to base16 string."""
    return base64.b16encode(data).decode("ascii")


def decode_base16(s: str) -> bytes:
    """Decode base16 string to bytes."""
    return base64.b16decode(s.strip().upper())


def encode_base32(data: bytes) -> str:
    """Encode bytes to base32 string."""
    return base64.b32encode(data).decode("ascii")


def decode_base32(s: str) -> bytes:
    """Decode base32 string to bytes."""
    s = s.strip().upper()
    # Add padding if missing
    pad_len = len(s) % 8
    if pad_len > 0:
        s += "=" * (8 - pad_len)
    return base64.b32decode(s)


def encode_base58(data: bytes) -> str:
    """Encode bytes to base58 string."""
    if not data:
        return ""

    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break

    num = int.from_bytes(data, "big")
    res = bytearray()

    while num > 0:
        num, mod = divmod(num, 58)
        res.append(BASE58_ALPHABET[mod])

    return (b"1" * pad + res[::-1]).decode("ascii")


def decode_base58(s: str) -> bytes:
    """Decode base58 string to bytes."""
    if not s:
        return b""

    pad = 0
    for char in s:
        if char == "1":
            pad += 1
        else:
            break

    num = 0
    for char in s:
        num = num * 58 + BASE58_ALPHABET.index(char.encode("ascii")[0])

    if num == 0:
        return b"\x00" * pad

    res = bytearray()
    while num > 0:
        num, mod = divmod(num, 256)
        res.append(mod)

    return b"\x00" * pad + res[::-1]


def encode_base64(data: bytes) -> str:
    """Encode bytes to base64 string."""
    return base64.b64encode(data).decode("ascii")


def decode_base64(s: str) -> bytes:
    """Decode base64 string to bytes."""
    s = s.strip()
    pad_len = len(s) % 4
    if pad_len > 0:
        s += "=" * (4 - pad_len)
    return base64.b64decode(s)


def encode_base64url(data: bytes) -> str:
    """Encode bytes to base64url string."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def decode_base64url(s: str) -> bytes:
    """Decode base64url string to bytes."""
    s = s.strip()
    pad_len = len(s) % 4
    if pad_len > 0:
        s += "=" * (4 - pad_len)
    return base64.urlsafe_b64decode(s)


def encode_base85(data: bytes) -> str:
    """Encode bytes to base85 string."""
    return base64.b85encode(data).decode("ascii")


def decode_base85(s: str) -> bytes:
    """Decode base85 string to bytes."""
    return base64.b85decode(s.strip())


def encode_base91(data: bytes) -> str:
    """Encode bytes to base91 string."""
    b = 0
    n = 0
    out = bytearray()
    for byte in data:
        b |= byte << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            out.append(BASE91_ALPHABET[v % 91])
            out.append(BASE91_ALPHABET[v // 91])
    if n > 0:
        out.append(BASE91_ALPHABET[b % 91])
        if n > 7 or b > 90:
            out.append(BASE91_ALPHABET[b // 91])
    return out.decode("ascii")


def decode_base91(s: str) -> bytes:
    """Decode base91 string to bytes."""
    s = s.strip()
    if not s:
        return b""
    v = -1
    b = 0
    n = 0
    out = bytearray()

    # Precompute reverse alphabet
    reverse_alpha = {char: i for i, char in enumerate(BASE91_ALPHABET)}

    for char in s:
        byte_val = ord(char)
        if byte_val not in reverse_alpha:
            raise ValueError(f"Invalid character in base91 string: {char!r}")
        c = reverse_alpha[byte_val]
        if v < 0:
            v = c
        else:
            v += c * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while n > 7:
                out.append(b & 255)
                b >>= 8
                n -= 8
            v = -1
    if v + 1 > 0:
        out.append((b | v << n) & 255)
    return bytes(out)


# =============================================================================
# Expanded Bases
# =============================================================================

CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
ZBASE32_ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769"
BASE45_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
BASE62_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
BASE92_CHARS = (
    "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}"
)


def encode_base32_crockford(data: bytes) -> str:
    """Encode bytes to Crockford's Base32 string."""
    if not data:
        return ""
    num = int.from_bytes(data, "big")
    res = []
    while num > 0:
        num, rem = divmod(num, 32)
        res.append(CROCKFORD_ALPHABET[rem])
    return "".join(reversed(res)) if res else "0"


def decode_base32_crockford(s: str) -> bytes:
    """Decode Crockford's Base32 string to bytes."""
    s_clean = s.upper().replace("-", "").replace("I", "1").replace("L", "1").replace("O", "0")
    idx = {c: i for i, c in enumerate(CROCKFORD_ALPHABET)}
    num = 0
    for c in s_clean:
        if c in idx:
            num = num * 32 + idx[c]
    return num.to_bytes((num.bit_length() + 7) // 8, "big") if num > 0 else b""


def encode_zbase32(data: bytes) -> str:
    """Encode bytes to z-base-32 human-oriented string."""
    if not data:
        return ""
    bits = "".join(f"{b:08b}" for b in data)
    rem = len(bits) % 5
    if rem:
        bits += "0" * (5 - rem)
    res = []
    for i in range(0, len(bits), 5):
        val = int(bits[i : i + 5], 2)
        res.append(ZBASE32_ALPHABET[val])
    return "".join(res)


def decode_zbase32(s: str) -> bytes:
    """Decode z-base-32 string to bytes."""
    if not s:
        return b""
    idx = {c: i for i, c in enumerate(ZBASE32_ALPHABET)}
    bits = "".join(f"{idx[c]:05b}" for c in s.lower() if c in idx)
    num_bytes = len(bits) // 8
    res = bytearray()
    for i in range(num_bytes):
        res.append(int(bits[i * 8 : (i + 1) * 8], 2))
    return bytes(res)


def encode_base45(data: bytes) -> str:
    """Encode bytes using Base45 (RFC 9285)."""
    res = []
    for i in range(0, len(data), 2):
        chunk = data[i : i + 2]
        if len(chunk) == 2:
            val = (chunk[0] << 8) | chunk[1]
            res.append(BASE45_CHARS[val % 45])
            res.append(BASE45_CHARS[(val // 45) % 45])
            res.append(BASE45_CHARS[(val // 2025) % 45])
        else:
            val = chunk[0]
            res.append(BASE45_CHARS[val % 45])
            res.append(BASE45_CHARS[(val // 45) % 45])
    return "".join(res)


def decode_base45(s: str) -> bytes:
    """Decode Base45 string (RFC 9285) to bytes."""
    res = bytearray()
    idx = {c: i for i, c in enumerate(BASE45_CHARS)}
    for i in range(0, len(s), 3):
        chunk = s[i : i + 3]
        if len(chunk) == 3:
            val = idx[chunk[0]] + idx[chunk[1]] * 45 + idx[chunk[2]] * 2025
            res.append((val >> 8) & 0xFF)
            res.append(val & 0xFF)
        elif len(chunk) == 2:
            val = idx[chunk[0]] + idx[chunk[1]] * 45
            res.append(val & 0xFF)
    return bytes(res)


def encode_base62(data: bytes) -> str:
    """Encode bytes to Base62 string."""
    if not data:
        return ""
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    num = int.from_bytes(data, "big")
    res = []
    while num > 0:
        num, rem = divmod(num, 62)
        res.append(BASE62_CHARS[rem])
    return ("0" * pad) + "".join(reversed(res))


def decode_base62(s: str) -> bytes:
    """Decode Base62 string to bytes."""
    if not s:
        return b""
    pad = 0
    for c in s:
        if c == "0":
            pad += 1
        else:
            break
    idx = {c: i for i, c in enumerate(BASE62_CHARS)}
    num = 0
    for c in s:
        if c in idx:
            num = num * 62 + idx[c]
    b = num.to_bytes((num.bit_length() + 7) // 8, "big") if num > 0 else b""
    return (b"\x00" * pad) + b


def encode_base92(data: bytes) -> str:
    """Encode bytes to Base92 string."""
    if not data:
        return "~"
    res = []
    bit_buf = 0
    bit_count = 0
    for byte in data:
        bit_buf = (bit_buf << 8) | byte
        bit_count += 8
        if bit_count >= 13:
            val = (bit_buf >> (bit_count - 13)) & 0x1FFF
            bit_count -= 13
            res.append(BASE92_CHARS[val // 91])
            res.append(BASE92_CHARS[val % 91])
    if bit_count > 0:
        val = (bit_buf << (13 - bit_count)) & 0x1FFF
        res.append(BASE92_CHARS[val // 91])
        res.append(BASE92_CHARS[val % 91])
    return "".join(res)


def decode_base92(s: str) -> bytes:
    """Decode Base92 string to bytes."""
    if not s or s == "~":
        return b""
    idx = {c: i for i, c in enumerate(BASE92_CHARS)}
    bit_buf = 0
    bit_count = 0
    res = bytearray()
    for i in range(0, len(s) - 1, 2):
        c1, c2 = s[i], s[i + 1]
        if c1 in idx and c2 in idx:
            val = idx[c1] * 91 + idx[c2]
            bit_buf = (bit_buf << 13) | val
            bit_count += 13
            while bit_count >= 8:
                res.append((bit_buf >> (bit_count - 8)) & 0xFF)
                bit_count -= 8
    return bytes(res)


BASE100_START = 0x1F3F7


def encode_base100(data: bytes) -> str:
    """Encode bytes using Emoji Base100 format."""
    return "".join(chr(BASE100_START + b) for b in data)


def decode_base100(s: str) -> bytes:
    """Decode Emoji Base100 string to bytes."""
    return bytes(ord(c) - BASE100_START for c in s)


def encode_base26(data: bytes) -> str:
    """Encode bytes as Base26 (A-Z)."""
    if not data:
        return ""
    num = int.from_bytes(data, "big")
    res = []
    while num > 0:
        num, rem = divmod(num, 26)
        res.append(chr(rem + ord("A")))
    return "".join(reversed(res)) if res else "A"


def decode_base26(s: str) -> bytes:
    """Decode Base26 (A-Z) string to bytes."""
    num = 0
    for c in s.upper():
        if "A" <= c <= "Z":
            num = num * 26 + (ord(c) - ord("A"))
    return num.to_bytes((num.bit_length() + 7) // 8, "big") if num > 0 else b""


def encode_base36(data: bytes) -> str:
    """Encode bytes as Base36 (0-9A-Z)."""
    if not data:
        return ""
    num = int.from_bytes(data, "big")
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    res = []
    while num > 0:
        num, rem = divmod(num, 36)
        res.append(chars[rem])
    return "".join(reversed(res)) if res else "0"


def decode_base36(s: str) -> bytes:
    """Decode Base36 (0-9A-Z) string to bytes."""
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    idx = {c: i for i, c in enumerate(chars)}
    num = 0
    for c in s.upper():
        if c in idx:
            num = num * 36 + idx[c]
    return num.to_bytes((num.bit_length() + 7) // 8, "big") if num > 0 else b""


def _is_valid_decoded(data: bytes) -> tuple[bool, float]:
    """Validates if decoded bytes represent meaningful plaintext or a recognized file format."""
    if not data:
        return False, 0.0
    from ichnos.core.detection import detect_file_type

    pr = printable_ratio(data)
    ftype = detect_file_type(data)
    if ftype not in ("unknown", "binary", "text"):
        return True, max(pr, 0.9)
    if pr >= 0.80:
        return True, pr
    return False, pr


def auto_detect(s: str) -> list[Candidate]:
    """Analyze charset and padding to guess which base encoding was used."""
    candidates = []
    clean = re.sub(r"[\r\n\t]", "", s).strip().rstrip("\x00")
    has_spaces = " " in clean

    # Check Hex / Base16
    try:
        if (not has_spaces and re.match(r"^[0-9a-fA-F]+$", clean) and len(clean) % 2 == 0) or (
            has_spaces and re.match(r"^([0-9a-fA-F]{2}\s+)+[0-9a-fA-F]{2}$", clean)
        ):
            decoded = decode_hex(clean)
            valid, conf = _is_valid_decoded(decoded)
            if valid:
                candidates.append(
                    Candidate(
                        decoded=decoded, method="hex/base16", confidence=conf * 0.9, layers=["hex"]
                    )
                )
    except Exception:
        pass

    # Check Base32
    try:
        if not has_spaces and re.match(r"^[A-Z2-7=]+$", clean.upper()) and len(clean) >= 8:
            decoded = decode_base32(clean)
            valid, conf = _is_valid_decoded(decoded)
            if valid:
                candidates.append(
                    Candidate(
                        decoded=decoded, method="base32", confidence=conf * 0.85, layers=["base32"]
                    )
                )
    except Exception:
        pass

    # Check Base58
    try:
        if not has_spaces and re.match(r"^[1-9A-HJ-NP-Za-km-z]+$", clean):
            decoded = decode_base58(clean)
            valid, conf = _is_valid_decoded(decoded)
            if valid:
                candidates.append(
                    Candidate(
                        decoded=decoded, method="base58", confidence=conf * 0.8, layers=["base58"]
                    )
                )
    except Exception:
        pass

    # Check Base64
    try:
        if not has_spaces and re.match(r"^[A-Za-z0-9+/=]+$", clean) and len(clean) >= 4:
            decoded = decode_base64(clean)
            valid, conf = _is_valid_decoded(decoded)
            if valid:
                candidates.append(
                    Candidate(
                        decoded=decoded, method="base64", confidence=conf * 0.95, layers=["base64"]
                    )
                )
    except Exception:
        pass

    # Check Base64URL
    try:
        if re.match(r"^[A-Za-z0-9\-_=\s]+$", s):
            decoded = decode_base64url(s)
            valid, conf = _is_valid_decoded(decoded)
            if valid:
                candidates.append(
                    Candidate(
                        decoded=decoded,
                        method="base64url",
                        confidence=conf * 0.9,
                        layers=["base64url"],
                    )
                )
    except Exception:
        pass

    # Check Base85
    try:
        decoded = decode_base85(s)
        valid, conf = _is_valid_decoded(decoded)
        if valid:
            candidates.append(
                Candidate(
                    decoded=decoded, method="base85", confidence=conf * 0.8, layers=["base85"]
                )
            )
    except Exception:
        pass

    # Check Base91
    try:
        if not has_spaces and len(clean) >= 2 and all(ord(c) in BASE91_ALPHABET for c in clean):
            has_b91_symbols = any(c in '!#$%&()*+,./:;<=>?@[]^_`{|}~"' for c in clean)
            decoded = decode_base91(clean)
            valid, conf = _is_valid_decoded(decoded)
            if valid and (has_b91_symbols or conf >= 0.85):
                candidates.append(
                    Candidate(
                        decoded=decoded, method="base91", confidence=conf * 0.8, layers=["base91"]
                    )
                )
    except Exception:
        pass

    candidates.sort(key=lambda x: x.confidence, reverse=True)
    return candidates
