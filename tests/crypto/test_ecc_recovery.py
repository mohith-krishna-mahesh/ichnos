from ichnos.crypto.ecc.curve import EllipticCurve
from ichnos.crypto.ecc.point import Point
from ichnos.crypto.ecc.point_recovery import int_to_bytes, recover_curve_from_doublings


def test_recover_curve_synthetic():
    # Known curve: y^2 = x^3 + 7x + 11 (mod 10007)
    p = 10007
    a = 7
    b = 11
    curve = EllipticCurve(name="test", p=p, a=a, b=b)

    # Pick a point on curve
    # Let x = 1: y^2 = 1 + 7 + 11 = 19 (mod 10007)
    # Find valid point:
    P = None
    for x in range(1, 100):
        rhs = (pow(x, 3, p) + a * x + b) % p
        # Check quadratic residue
        if pow(rhs, (p - 1) // 2, p) == 1:
            # find y
            for y in range(1, p):
                if pow(y, 2, p) == rhs:
                    P = Point(x, y, curve)
                    break
            if P:
                break

    assert P is not None
    Q = 2 * P
    R = 2 * Q
    assert not Q.is_infinity and not R.is_infinity

    # Recover
    rec = recover_curve_from_doublings(
        P=(P.x, P.y),
        Q=(Q.x, Q.y),
        R=(R.x, R.y)
    )

    assert rec.p == p
    assert rec.a == a
    assert rec.b == b
    assert 2 * rec.point_P == rec.point_Q
    assert 2 * rec.point_Q == rec.point_R

def test_int_to_bytes():
    val = 0x464c4147
    assert int_to_bytes(val) == b"FLAG"
    assert int_to_bytes(0) == b""
