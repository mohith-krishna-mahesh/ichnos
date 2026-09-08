"""Weak curve detection and ECC security auditing."""

from __future__ import annotations

from ichnos.crypto.ecc.curve import EllipticCurve


def is_singular_curve(curve: EllipticCurve) -> bool:
    """Checks if curve has discriminant == 0 mod p."""
    return curve.is_singular()


def is_anomalous_curve(curve: EllipticCurve) -> bool:
    """Checks if curve order == field characteristic p (vulnerable to Smart's attack)."""
    if curve.order is None:
        return False
    return curve.order == curve.p


def is_smooth_order(order: int, b_limit: int = 50_000) -> bool:
    """Checks if order is B-smooth (vulnerable to Pohlig-Hellman)."""
    n = order
    d = 2
    while d * d <= n and d <= b_limit:
        while n % d == 0:
            n //= d
        d += 1
    return n <= b_limit


def audit_curve(curve: EllipticCurve) -> dict[str, bool | str]:
    """Runs a suite of cryptographic checks against an elliptic curve."""
    singular = curve.is_singular()
    anomalous = is_anomalous_curve(curve)
    smooth = is_smooth_order(curve.order) if curve.order else False

    is_weak = singular or anomalous or smooth

    return {
        "is_singular": singular,
        "is_anomalous": anomalous,
        "is_smooth_order": smooth,
        "is_weak": is_weak,
        "recommendation": "Insecure curve: do not use"
        if is_weak
        else "No obvious mathematical weaknesses found",
    }
