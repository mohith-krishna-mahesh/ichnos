"""Elliptic Curve definitions over prime fields GF(p)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EllipticCurve:
    """Short Weierstrass elliptic curve: y^2 = x^3 + ax + b (mod p)."""

    name: str
    p: int
    a: int
    b: int
    order: int | None = None
    gx: int | None = None
    gy: int | None = None

    def is_on_curve(self, x: int | None, y: int | None) -> bool:
        """Check if point (x, y) lies on the curve (including point at infinity)."""
        if x is None or y is None:
            return True
        left = pow(y, 2, self.p)
        right = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
        return left == right

    def discriminant(self) -> int:
        """Curve discriminant: -16 * (4*a^3 + 27*b^2) mod p."""
        return (-16 * (4 * pow(self.a, 3, self.p) + 27 * pow(self.b, 2, self.p))) % self.p

    def is_singular(self) -> bool:
        """Check if curve is singular (discriminant is 0 mod p)."""
        return (4 * pow(self.a, 3, self.p) + 27 * pow(self.b, 2, self.p)) % self.p == 0


# =============================================================================
# Standard Curves
# =============================================================================

# secp256k1 (Bitcoin, Ethereum)
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

SECP256K1 = EllipticCurve(
    name="secp256k1",
    p=SECP256K1_P,
    a=0,
    b=7,
    order=SECP256K1_N,
    gx=SECP256K1_GX,
    gy=SECP256K1_GY,
)

# NIST P-256 / secp256r1
NIST_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
NIST_P256_A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
NIST_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
NIST_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
NIST_P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
NIST_P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

NIST_P256 = EllipticCurve(
    name="nist_p256",
    p=NIST_P256_P,
    a=NIST_P256_A,
    b=NIST_P256_B,
    order=NIST_P256_N,
    gx=NIST_P256_GX,
    gy=NIST_P256_GY,
)

CURVES: dict[str, EllipticCurve] = {
    "secp256k1": SECP256K1,
    "nist_p256": NIST_P256,
}
