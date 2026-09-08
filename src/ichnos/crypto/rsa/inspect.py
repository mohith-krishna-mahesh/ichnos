"""RSA key inspection and ASN.1 DER / PEM parsing."""

from __future__ import annotations

import base64
from dataclasses import dataclass


@dataclass
class RSAParameters:
    n: int
    e: int
    d: int | None = None
    p: int | None = None
    q: int | None = None
    dp: int | None = None
    dq: int | None = None
    qi: int | None = None
    bit_length: int = 0
    is_private: bool = False


class ASN1Parser:
    """Minimal ASN.1 DER parser for RSA keys."""

    @staticmethod
    def read_length(data: bytes, offset: int) -> tuple[int, int]:
        """Returns (length, new_offset)."""
        b = data[offset]
        offset += 1
        if b < 0x80:
            return b, offset
        num_bytes = b & 0x7F
        length = 0
        for _ in range(num_bytes):
            length = (length << 8) | data[offset]
            offset += 1
        return length, offset

    @classmethod
    def parse_sequence(cls, data: bytes, offset: int = 0) -> list[tuple[int, bytes]]:
        """Parses a DER sequence into list of (tag, content)."""
        if offset >= len(data) or data[offset] != 0x30:
            raise ValueError("Expected SEQUENCE tag 0x30")
        offset += 1
        seq_len, offset = cls.read_length(data, offset)
        end = offset + seq_len
        items = []
        while offset < end:
            tag = data[offset]
            offset += 1
            item_len, offset = cls.read_length(data, offset)
            content = data[offset : offset + item_len]
            items.append((tag, content))
            offset += item_len
        return items

    @staticmethod
    def bytes_to_int(b: bytes) -> int:
        return int.from_bytes(b, byteorder="big", signed=False)


def parse_rsa_pem(pem_str: str) -> RSAParameters:
    """Parses PEM-encoded RSA public or private key (PKCS#1 or PKCS#8)."""
    # Strip PEM headers and footers
    lines = [
        line.strip()
        for line in pem_str.strip().splitlines()
        if not line.startswith("-----") and line.strip()
    ]
    raw_b64 = "".join(lines)
    der = base64.b64decode(raw_b64)
    return parse_rsa_der(der)


def parse_rsa_der(der: bytes) -> RSAParameters:
    """Parses DER-encoded RSA public or private key."""
    items = ASN1Parser.parse_sequence(der)

    # Check if this is PKCS#1 RSAPrivateKey:
    # SEQUENCE { version, n, e, d, p, q, d mod (p-1), d mod (q-1), q^-1 mod p }
    # All 9 fields are INTEGER (tag 0x02)
    if len(items) >= 9 and all(tag == 0x02 for tag, _ in items[:9]):
        n = ASN1Parser.bytes_to_int(items[1][1])
        e = ASN1Parser.bytes_to_int(items[2][1])
        d = ASN1Parser.bytes_to_int(items[3][1])
        p = ASN1Parser.bytes_to_int(items[4][1])
        q = ASN1Parser.bytes_to_int(items[5][1])
        dp = ASN1Parser.bytes_to_int(items[6][1])
        dq = ASN1Parser.bytes_to_int(items[7][1])
        qi = ASN1Parser.bytes_to_int(items[8][1])
        return RSAParameters(
            n=n,
            e=e,
            d=d,
            p=p,
            q=q,
            dp=dp,
            dq=dq,
            qi=qi,
            bit_length=n.bit_length(),
            is_private=True,
        )

    # Check if PKCS#1 RSAPublicKey:
    # SEQUENCE { n, e }
    if len(items) == 2 and items[0][0] == 0x02 and items[1][0] == 0x02:
        n = ASN1Parser.bytes_to_int(items[0][1])
        e = ASN1Parser.bytes_to_int(items[1][1])
        return RSAParameters(n=n, e=e, bit_length=n.bit_length(), is_private=False)

    # Check if PKCS#8 / X.509 SubjectPublicKeyInfo:
    # SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
    for tag, content in items:
        if tag == 0x03:  # BIT STRING
            # Skip unused bits byte
            inner_der = content[1:]
            return parse_rsa_der(inner_der)

    # Check if PKCS#8 PrivateKeyInfo:
    # SEQUENCE { version, privateKeyAlgorithm, privateKey OCTET STRING }
    for tag, content in items:
        if tag == 0x04:  # OCTET STRING
            return parse_rsa_der(content)

    raise ValueError("Could not recognize RSA DER structure")


def rsa_summary(params: RSAParameters) -> dict[str, str | int | bool]:
    """Provides a security summary of RSA parameters."""
    return {
        "bit_length": params.bit_length,
        "is_private": params.is_private,
        "modulus_hex": hex(params.n),
        "public_exponent": params.e,
        "has_small_e": params.e <= 3,
        "has_weak_bits": params.bit_length < 2048,
    }
