"""Elliptic Curve Parameter and Flag Recovery from Point Doublings.

Recovers prime field modulus p and Weierstrass curve coefficients (a, b)
from doubling points P, Q, R satisfying 2P = Q and 2Q = R.
Supports inverting public key / ciphertext scalar multiplications C = k*F.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from ichnos.crypto.ecc.curve import EllipticCurve
from ichnos.crypto.ecc.point import Point
from ichnos.crypto.numtheory import is_prime, mod_inverse
from ichnos.crypto.pqc.lattice import run_sage_script, sage_available


@dataclass
class RecoveredCurve:
    """Represents recovered elliptic curve parameters and verification points."""

    p: int
    a: int
    b: int
    curve: EllipticCurve
    point_P: Point
    point_Q: Point
    point_R: Point
    order: int | None = None
    decrypted_point: Point | None = None
    flag: bytes | None = None


def int_to_bytes(val: int) -> bytes:
    """Converts an integer into big-endian bytes."""
    if val <= 0:
        return b""
    length = (val.bit_length() + 7) // 8
    return val.to_bytes(length, "big")


def recover_curve_from_doublings(
    P: tuple[int, int],
    Q: tuple[int, int],
    R: tuple[int, int],
    C: tuple[int, int] | None = None,
    k: int | None = None,
    order: int | None = None,
) -> RecoveredCurve:
    """Recovers prime p, curve coefficients (a, b), and optional flag from 2P=Q, 2Q=R.

    Args:
        P: Coordinates (xP, yP) of initial point.
        Q: Coordinates (xQ, yQ) of doubled point (2P = Q).
        R: Coordinates (xR, yR) of quadrupled point (2Q = R).
        C: Optional ciphertext/target point (xC, yC) where C = k*F.
        k: Scalar multiplier relating C to secret point F (C = k*F).
        order: Optional curve order (#E). If None and Sage is installed, computed automatically.

    Returns:
        RecoveredCurve containing curve and verified points.
    """
    xP, yP = P
    xQ, yQ = Q
    xR, yR = R

    # Tangent chord relation: (yP + yQ)^2 = (xP - xQ)^2 * (xQ + 2*xP) (mod p)
    D1 = (yP + yQ) ** 2 - (xP - xQ) ** 2 * (xQ + 2 * xP)
    D2 = (yQ + yR) ** 2 - (xQ - xR) ** 2 * (xR + 2 * xQ)

    candidate_p = math.gcd(abs(D1), abs(D2))
    if candidate_p <= 1:
        raise ValueError("Failed to recover modulus p: gcd is <= 1")

    # Remove small composite factors
    for small_factor in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
        while candidate_p % small_factor == 0 and candidate_p > small_factor:
            candidate_p //= small_factor

    p = candidate_p
    if not is_prime(p):
        # In case gcd still contains larger cofactor, verify if D1 % p == 0
        pass

    # Recover a, b (mod p)
    dx = (xP - xQ) % p
    dy = (yP + yQ) % p
    lam = (dy * mod_inverse(dx, p)) % p

    a = (2 * yP * lam - 3 * pow(xP, 2, p)) % p
    b = (pow(yP, 2, p) - pow(xP, 3, p) - a * xP) % p

    curve = EllipticCurve(name="recovered_curve", p=p, a=a, b=b)
    pt_P = Point(xP % p, yP % p, curve)
    pt_Q = Point(xQ % p, yQ % p, curve)
    pt_R = Point(xR % p, yR % p, curve)

    # Verification: 2P == Q and 2Q == R
    if not (2 * pt_P == pt_Q):
        raise ValueError("Verification failed: 2P != Q on recovered curve")
    if not (2 * pt_Q == pt_R):
        raise ValueError("Verification failed: 2Q != R on recovered curve")

    recovered_order = order
    decrypted_point: Point | None = None
    flag: bytes | None = None

    # If ciphertext point C and scalar k are given, invert C = k*F
    if C is not None and k is not None:
        xC, yC = C
        pt_C = Point(xC % p, yC % p, curve)

        # Attempt to determine curve order
        if recovered_order is None and sage_available():
            sage_script = f"""
p = {p}
a = {a}
b = {b}
k = {k}
xC = {xC}
yC = {yC}
Fp = GF(p)
E = EllipticCurve(Fp, [a, b])
C = E(xC, yC)
n = E.order()
d = inverse_mod(k, n)
F = d * C
print(n)
print(int(F[0]))
print(int(F[1]))
"""
            try:
                out = run_sage_script(sage_script, timeout=60)
                lines = [line.strip() for line in out.splitlines() if line.strip()]
                if len(lines) >= 3:
                    recovered_order = int(lines[0])
                    fx = int(lines[1])
                    fy = int(lines[2])
                    decrypted_point = Point(fx, fy, curve)
                    flag = int_to_bytes(fx)
            except Exception:
                pass

        if recovered_order is not None and decrypted_point is None:
            # Pure-Python scalar inversion
            if math.gcd(k, recovered_order) == 1:
                d = mod_inverse(k, recovered_order)
                decrypted_point = d * pt_C
                if decrypted_point.x is not None:
                    flag = int_to_bytes(decrypted_point.x)

    return RecoveredCurve(
        p=p,
        a=a,
        b=b,
        curve=curve,
        point_P=pt_P,
        point_Q=pt_Q,
        point_R=pt_R,
        order=recovered_order,
        decrypted_point=decrypted_point,
        flag=flag,
    )
