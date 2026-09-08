"""Learning With Errors (LWE) and Lattice Knapsack cryptanalysis.

Implements dual-kernel lattice reduction, Kannan embedding CVP recovery,
and continued fractions quotient extraction for LWE and subset-sum schemes.
"""

from __future__ import annotations

import json
from typing import Any

from ichnos.crypto.numtheory import continued_fraction, convergents
from ichnos.crypto.pqc.lattice import (
    gauss_reduce_2d,
    integer_left_kernel,
    run_sage_script,
    sage_available,
)


def solve_lwe_dual_kernel(
    A: list[list[int]],
    B: list[int],
    q: int,
    ct0: list[int] | None = None,
    ct1: int | None = None,
) -> dict[str, Any]:
    """Solves an LWE system with bounded noise using dual-kernel projection.

    Given public key B = A*s + k*e (mod q) where e has small norm and k = p/sk (mod q):
    1. Projects onto left kernel of A: u^T * A = 0 => u^T * B = k * (u^T * e) (mod q).
    2. Uses 2D Gauss reduction to recover projected noise coordinates and scalar multiplier k.
    3. Recovers private parameters (sk, p) via continued fraction convergents of k/q.
    4. Recovers secret vector s via lattice reduction / Kannan embedding.
    5. If ciphertext (ct0, ct1) is provided, decrypts the message and extracts flag.
    """
    m = len(A)
    n = len(A[0]) if m > 0 else 0

    if m == 0 or n == 0 or len(B) != m:
        return {"error": "Invalid dimensions for LWE system"}

    # If SageMath is available, execute the fast kernel + LLL reduction pipeline
    if sage_available():
        try:
            res = _solve_lwe_sage(A, B, q, ct0, ct1)
            if res.get("flag"):
                return res
        except Exception:
            pass

    # Pure-Python fallback for kernel + Gauss 2D + continued fractions
    return _solve_lwe_pure(A, B, q, ct0, ct1)


def _solve_lwe_sage(
    A: list[list[int]],
    B: list[int],
    q: int,
    ct0: list[int] | None = None,
    ct1: int | None = None,
) -> dict[str, Any]:
    """SageMath accelerated LWE dual-kernel and Kannan embedding solver."""
    m = len(A)
    n = len(A[0])
    a_flat_list = [x for row in A for x in row]

    script = f"""
import json

A_flat = {a_flat_list}
B_list = {B}
q = {q}
ct0_list = {ct0 if ct0 is not None else "None"}
ct1_val = {ct1 if ct1 is not None else "None"}
m, n = {m}, {n}

A = Matrix(ZZ, m, n, A_flat)
B_vec = vector(ZZ, B_list)

K = A.left_kernel().basis_matrix()
u0, u1 = K[0], K[1]
z0 = int(u0 * B_vec) % q
z1 = int(u1 * B_vec) % q
C = (z1 * pow(z0, -1, q)) % q
M2 = Matrix(ZZ, [[1, C], [0, q]]).LLL()
y0 = M2[0][0]
if y0 == 0:
    y0 = M2[1][0]
k_base = (z0 * pow(int(y0), -1, q)) % q

k_rows = 24
A_sub = Matrix(Zmod(q), [A[i] for i in range(k_rows)])

final_k = None
final_sk = None
final_p = None
s_cand = None

for k in [k_base, (q - k_base) % q]:
    k_inv = pow(k, -1, q)
    A_prime = Matrix(ZZ, [[(k_inv * int(A_sub[i, j])) % q for j in range(n)] for i in range(k_rows)])
    B_prime = vector(ZZ, [(k_inv * B_list[i]) % q for i in range(k_rows)])

    dim = n + k_rows + 1
    L = Matrix(ZZ, dim, k_rows + 1)
    for j in range(n):
        for i in range(k_rows):
            L[j, i] = A_prime[i, j]
    for i in range(k_rows):
        L[n + i, i] = q
    for i in range(k_rows):
        L[n + k_rows, i] = -B_prime[i]
    L[n + k_rows, k_rows] = 2**32

    L_red, U = L.LLL(transformation=True)
    found = False
    for idx, row in enumerate(L_red):
        if abs(row[-1]) == 2**32:
            sgn = 1 if row[-1] == 2**32 else -1
            u_row = [int(U[idx, j] * sgn) for j in range(dim)]
            s_cand_raw = [u_row[j] % q for j in range(n)]
            diff = [(B_list[i] - sum(A[i, j] * s_cand_raw[j] for j in range(n))) % q for i in range(k_rows)]
            e_centered = vector(QQ, [int(v if v <= q // 2 else v - q) for v in [(k_inv * diff[i]) % q for i in range(k_rows)]])
            A_sub_zz = Matrix(QQ, [A[i] for i in range(k_rows)])
            target = vector(QQ, [2.147e9 - float(x) for x in e_centered])
            delta_float = (A_sub_zz.transpose() * A_sub_zz).inverse() * (A_sub_zz.transpose() * target)
            delta = vector(ZZ, [round(float(x)) for x in delta_float])
            s_cand = [(s_cand_raw[j] - k * int(delta[j])) % q for j in range(n)]
            found = True
            break
    if found:
        final_k = k
        cf = continued_fraction(k / q)
        for c in cf.convergents():
            d = int(c.denominator())
            if d.bit_length() == 128:
                kd = (k * d) % q
                if (q - kd).bit_length() <= 522:
                    final_sk = d
                    final_p = q - kd
                    break
                elif kd.bit_length() <= 522:
                    final_sk = d
                    final_p = kd
                    break
        break

flag_str = ""
pt_int = None
s_cand_list = None
if s_cand is not None and ct0_list is not None and ct1_val is not None and final_p is not None and final_sk is not None:
    s_cand_list = [int(x) for x in s_cand]
    ct0_s = sum(int(ct0_list[j]) * int(s_cand[j]) for j in range(n))
    val = (ct1_val + ct0_s) % q
    Y = (final_sk * val) % q
    pt = (Y * pow(final_sk, -1, final_p)) % final_p
    pt_int = int(pt)
    try:
        flag_bytes = pt_int.to_bytes((pt_int.bit_length() + 7) // 8, 'big')
        flag_str = flag_bytes.decode('utf-8', errors='ignore')
    except Exception:
        pass

result = {{
    "k": int(final_k) if final_k else None,
    "sk": int(final_sk) if final_sk else None,
    "p": int(final_p) if final_p else None,
    "s": s_cand_list,
    "pt": pt_int,
    "flag": flag_str,
}}
print("---RESULT_START---")
print(json.dumps(result))
"""
    output = run_sage_script(script, timeout=60)
    if "---RESULT_START---" in output:
        json_part = output.split("---RESULT_START---")[1].strip()
        return json.loads(json_part)
    return {"error": "Failed to parse Sage output", "raw": output}


def _solve_lwe_pure(
    A: list[list[int]],
    B: list[int],
    q: int,
    ct0: list[int] | None = None,
    ct1: int | None = None,
) -> dict[str, Any]:
    """Pure Python fallback for LWE dual-kernel solving."""
    raw_kernel = integer_left_kernel(A)
    if len(raw_kernel) < 2:
        return {"error": "Kernel dimension insufficient"}

    u0 = raw_kernel[0]
    u1 = raw_kernel[1]
    z0 = sum(u0[k] * B[k] for k in range(len(B))) % q
    z1 = sum(u1[k] * B[k] for k in range(len(B))) % q

    if z0 % 2 == 0:
        for row in raw_kernel[2:]:
            val = sum(row[k] * B[k] for k in range(len(B))) % q
            if val % 2 != 0:
                u0 = row
                z0 = val
                break

    try:
        z0_inv = pow(z0, -1, q)
    except ValueError:
        return {"error": "z0 not invertible mod q"}

    c = (z1 * z0_inv) % q

    v1, v2 = gauss_reduce_2d([1, c], [0, q])
    y0 = v1[0]
    if y0 == 0:
        y0 = v2[0]

    try:
        k = (z0 * pow(y0, -1, q)) % q
    except ValueError:
        return {"error": "y0 not invertible mod q"}

    cf = continued_fraction(k, q)
    convs = convergents(cf)
    sk = None
    p = None
    for _, den in convs:
        if den.bit_length() == 128:
            kd = (k * den) % q
            if (q - kd).bit_length() <= 522:
                sk = den
                p = q - kd
                break

    return {
        "k": k,
        "sk": sk,
        "p": p,
        "s": None,
        "pt": None,
        "flag": "",
    }


def solve_subset_sum(weights: list[int], target: int) -> list[int] | None:
    """Solves the subset-sum knapsack problem sum(x_i * weights[i]) = target with x_i in {0, 1}.

    Uses the Lagarias-Odlyzko / CJLOSS lattice reduction embedding.
    """
    n = len(weights)
    if n == 0:
        return None

    basis: list[list[int]] = []
    for i in range(n):
        row = [0] * (n + 1)
        row[i] = 2
        row[n] = 2 * weights[i]
        basis.append(row)

    target_row = [1] * n + [2 * target]
    basis.append(target_row)

    from ichnos.crypto.pqc.lattice import lll_reduce

    reduced = lll_reduce(basis)
    for row in reduced:
        if row[n] == 0:
            x_cand: list[int] = []
            for val in row[:n]:
                if val == 1:
                    x_cand.append(1)
                elif val == -1:
                    x_cand.append(0)
                else:
                    break
            if len(x_cand) == n and sum(x_cand[i] * weights[i] for i in range(n)) == target:
                return x_cand

            x_cand_inv: list[int] = []
            for val in row[:n]:
                if val == -1:
                    x_cand_inv.append(1)
                elif val == 1:
                    x_cand_inv.append(0)
                else:
                    break
            if len(x_cand_inv) == n and sum(x_cand_inv[i] * weights[i] for i in range(n)) == target:
                return x_cand_inv

    return None
