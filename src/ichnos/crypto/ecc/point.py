"""Point arithmetic on elliptic curves over prime fields."""

from __future__ import annotations

from dataclasses import dataclass

from ichnos.crypto.ecc.curve import EllipticCurve
from ichnos.crypto.numtheory import mod_inverse


@dataclass(frozen=True)
class Point:
    """Affine point (x, y) on an EllipticCurve, or point at infinity if x is None."""

    x: int | None
    y: int | None
    curve: EllipticCurve

    @property
    def is_infinity(self) -> bool:
        return self.x is None or self.y is None

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            return False
        if self.curve != other.curve:
            return False
        return (self.x, self.y) == (other.x, other.y)

    def __neg__(self) -> Point:
        if self.is_infinity:
            return self
        return Point(self.x, (-self.y) % self.curve.p, self.curve)

    def __add__(self, other: Point) -> Point:
        if self.curve != other.curve:
            raise ValueError("Cannot add points on different curves")

        if self.is_infinity:
            return other
        if other.is_infinity:
            return self

        p = self.curve.p
        x1, y1 = self.x, self.y
        x2, y2 = other.x, other.y

        # P + (-P) = Infinity
        if x1 == x2 and (y1 + y2) % p == 0:
            return Point(None, None, self.curve)

        # Point doubling
        if x1 == x2 and y1 == y2:
            if y1 == 0:
                return Point(None, None, self.curve)
            # slope = (3*x1^2 + a) / (2*y1) mod p
            num = (3 * pow(x1, 2, p) + self.curve.a) % p
            den = (2 * y1) % p
            slope = (num * mod_inverse(den, p)) % p
        else:
            # Point addition: slope = (y2 - y1) / (x2 - x1) mod p
            num = (y2 - y1) % p
            den = (x2 - x1) % p
            slope = (num * mod_inverse(den, p)) % p

        # x3 = slope^2 - x1 - x2 mod p
        x3 = (pow(slope, 2, p) - x1 - x2) % p
        # y3 = slope*(x1 - x3) - y1 mod p
        y3 = (slope * (x1 - x3) - y1) % p

        return Point(x3, y3, self.curve)

    def __rmul__(self, scalar: int) -> Point:
        return self.__mul__(scalar)

    def __mul__(self, scalar: int) -> Point:
        """Scalar multiplication k * P using double-and-add."""
        if scalar < 0:
            return (-self) * (-scalar)
        if scalar == 0 or self.is_infinity:
            return Point(None, None, self.curve)

        res = Point(None, None, self.curve)
        addend = self

        while scalar > 0:
            if scalar & 1:
                res = res + addend
            addend = addend + addend
            scalar >>= 1

        return res


def get_generator(curve: EllipticCurve) -> Point:
    """Returns the base generator point G for the curve."""
    if curve.gx is None or curve.gy is None:
        raise ValueError(f"Curve {curve.name} does not have a defined generator point")
    return Point(curve.gx, curve.gy, curve)
