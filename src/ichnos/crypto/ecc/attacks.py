"""Elliptic Curve Cryptanalysis attacks: Smart's attack, Pohlig-Hellman, and small subgroup attacks."""

from __future__ import annotations

from ichnos.crypto.ecc.curve import EllipticCurve
from ichnos.crypto.ecc.point import Point
from ichnos.crypto.pqc.lattice import run_sage_script, sage_available


def small_order_attack(
    curve: EllipticCurve, G: Point, P: Point, max_order: int = 100_000
) -> int | None:
    """Solves P = d * G when order of G is small (<= max_order) via baby-step giant-step."""
    order = curve.order or max_order
    # Baby-step giant-step on curve points
    m = int(order**0.5) + 1
    table: dict[str, int] = {}

    cur = Point(None, None, curve)
    for j in range(m):
        table[f"{cur.x},{cur.y}"] = j
        cur = cur + G

    mG = cur
    # Giant step: P - i*mG
    cur_p = P
    for i in range(m):
        key = f"{cur_p.x},{cur_p.y}"
        if key in table:
            return i * m + table[key]
        # subtract mG
        cur_p = cur_p + Point(mG.x, -mG.y % curve.p if mG.y else None, curve)

    return None


def smarts_attack(curve: EllipticCurve, G: Point, P: Point) -> int | None:
    """Executes Smart's attack on anomalous curves (#E(F_p) == p).

    Solves ECDLP in linear time by lifting points to Q_p and evaluating p-adic formal logarithm.
    Uses SageMath when available for exact p-adic curve arithmetic.
    """
    if curve.order != curve.p:
        return None

    if sage_available():
        script = f"""
p = {curve.p}
a = {curve.a}
b = {curve.b}
Gx, Gy = {G.x}, {G.y}
Px, Py = {P.x}, {P.y}

E = EllipticCurve(GF(p), [a, b])
P_G = E(Gx, Gy)
P_P = E(Px, Py)

# Smart's attack via p-adic formal group log
# Lift to Q_p
E_lift = EllipticCurve(Qp(p, 2), [ZZ(a), ZZ(b)])
G_lift = E_lift.lift_x(ZZ(Gx))
if (G_lift[1] - Gy) % p != 0:
    G_lift = -G_lift

P_lift = E_lift.lift_x(ZZ(Px))
if (P_lift[1] - Py) % p != 0:
    P_lift = -P_lift

pG = p * G_lift
pP = p * P_lift

logG = -pG[0] / pG[1]
logP = -pP[0] / pP[1]

d = (logP / logG).lift() % p
print(int(d))
"""
        try:
            out = run_sage_script(script, timeout=15)
            return int(out.split()[-1])
        except Exception:
            pass

    return None
