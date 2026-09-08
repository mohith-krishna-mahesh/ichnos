"""Lattice algorithms: Gram-Schmidt, Babai's Closest Vector Problem (CVP) / Nearest Plane.

CAVEAT: Educational and CTF-analysis scope only. Not intended for production cryptographic use.
"""

from __future__ import annotations

import math


def dot_product(v1: list[float], v2: list[float]) -> float:
    return sum(x * y for x, y in zip(v1, v2))


def vector_norm_sq(v: list[float]) -> float:
    return sum(x * x for x in v)


def vector_norm(v: list[float]) -> float:
    return math.sqrt(vector_norm_sq(v))


def vector_sub(v1: list[float], v2: list[float]) -> list[float]:
    return [x - y for x, y in zip(v1, v2)]


def vector_add(v1: list[float], v2: list[float]) -> list[float]:
    return [x + y for x, y in zip(v1, v2)]


def scalar_mul(s: float, v: list[float]) -> list[float]:
    return [s * x for x in v]


def gram_schmidt(basis: list[list[float]]) -> tuple[list[list[float]], list[list[float]]]:
    """Gram-Schmidt orthogonalization of basis vectors.

    Returns (ortho_basis, mu_matrix) where mu[i][j] is projection coefficient.
    """
    n = len(basis)
    ortho = [[0.0] * len(basis[0]) for _ in range(n)]
    mu = [[0.0] * n for _ in range(n)]

    for i in range(n):
        ortho[i] = list(basis[i])
        for j in range(i):
            denom = vector_norm_sq(ortho[j])
            if denom > 1e-12:
                mu[i][j] = dot_product(basis[i], ortho[j]) / denom
                ortho[i] = vector_sub(ortho[i], scalar_mul(mu[i][j], ortho[j]))
            else:
                mu[i][j] = 0.0
        mu[i][i] = 1.0

    return ortho, mu


def lattice_determinant(basis: list[list[float]]) -> float:
    """Computes the determinant (volume) of the lattice using Gram-Schmidt norms."""
    ortho, _ = gram_schmidt(basis)
    det = 1.0
    for b_star in ortho:
        det *= vector_norm(b_star)
    return det


def babai_round_off(basis: list[list[float]], target: list[float]) -> list[int]:
    """Babai's Round-Off algorithm for CVP.

    Returns lattice vector coordinates (coefficients).
    """
    n = len(basis)
    # Solve target = sum(c_i * basis[i])
    # For simplicity with full-rank square basis, use Gaussian elimination or Gram-Schmidt
    ortho, _ = gram_schmidt(basis)
    b = target
    coeffs = [0] * n
    for i in range(n - 1, -1, -1):
        c = dot_product(b, ortho[i]) / (vector_norm_sq(ortho[i]) + 1e-12)
        k = round(c)
        coeffs[i] = k
        b = vector_sub(b, scalar_mul(k, basis[i]))
    return coeffs


def babai_nearest_plane(basis: list[list[float]], target: list[float]) -> list[float]:
    """Babai's Nearest Plane algorithm for Closest Vector Problem (CVP).

    Returns the closest lattice point found.
    """
    n = len(basis)
    ortho, _ = gram_schmidt(basis)
    b = list(target)
    for i in range(n - 1, -1, -1):
        denom = vector_norm_sq(ortho[i])
        c = dot_product(b, ortho[i]) / (denom if denom > 1e-12 else 1.0)
        k = round(c)
        b = vector_sub(b, scalar_mul(k, basis[i]))
    return vector_sub(target, b)


def gauss_reduce_2d(
    v1: tuple[int, int] | list[int], v2: tuple[int, int] | list[int]
) -> tuple[list[int], list[int]]:
    """Gauss (Lagrange) 2D lattice reduction.

    Finds the shortest non-zero vector and minimal basis of a 2D integer lattice in O(log(||v||)) steps.
    """
    u = [int(v1[0]), int(v1[1])]
    v = [int(v2[0]), int(v2[1])]

    while True:
        norm_u = u[0] * u[0] + u[1] * u[1]
        norm_v = v[0] * v[0] + v[1] * v[1]
        if norm_u > norm_v:
            u, v = v, u
            norm_u, norm_v = norm_v, norm_u

        if norm_u == 0:
            return u, v

        num = u[0] * v[0] + u[1] * v[1]
        m = round(num / norm_u)
        if m == 0:
            return u, v

        v = [v[0] - m * u[0], v[1] - m * u[1]]


def integer_left_kernel(matrix: list[list[int]]) -> list[list[int]]:
    """Calculates an exact integer basis for the left kernel (nullspace of M^T).

    Finds all integer vectors u such that u * M = 0.
    Uses Gaussian elimination with exact rational arithmetic.
    """
    from fractions import Fraction
    from math import lcm

    m = len(matrix)
    if m == 0:
        return []
    n = len(matrix[0])

    # Transpose M: n rows, m cols
    mt = [[Fraction(matrix[i][j]) for i in range(m)] for j in range(n)]

    # RREF
    lead = 0
    pivot_cols = []
    for r in range(n):
        if lead >= m:
            break
        i = r
        while i < n and mt[i][lead] == 0:
            i += 1
        if i == n:
            lead += 1
            r -= 1
            continue
        mt[i], mt[r] = mt[r], mt[i]
        lv = mt[r][lead]
        mt[r] = [x / lv for x in mt[r]]
        for row_idx in range(n):
            if row_idx != r:
                factor = mt[row_idx][lead]
                if factor != 0:
                    mt[row_idx] = [mt[row_idx][c] - factor * mt[r][c] for c in range(m)]
        pivot_cols.append(lead)
        lead += 1

    pivot_set = set(pivot_cols)
    free_cols = [c for c in range(m) if c not in pivot_set]

    kernel: list[list[int]] = []
    for fc in free_cols:
        vec = [Fraction(0)] * m
        vec[fc] = Fraction(1)
        for r_idx, pc in enumerate(pivot_cols):
            vec[pc] = -mt[r_idx][fc]

        den_lcm = 1
        for val in vec:
            den_lcm = lcm(den_lcm, val.denominator)
        int_vec = [int(val * den_lcm) for val in vec]
        kernel.append(int_vec)

    return kernel


def lll_reduce(basis: list[list[int]], delta: float = 0.75) -> list[list[int]]:
    """Pure-Python exact-arithmetic Lenstra-Lenstra-Lovasz (LLL) lattice reduction.

    Reduces basis vectors using rational Gram-Schmidt orthogonalization.
    """
    from fractions import Fraction

    n = len(basis)
    if n <= 1:
        return [list(row) for row in basis]
    m = len(basis[0])

    b = [[Fraction(x) for x in row] for row in basis]
    delta_frac = Fraction(int(delta * 1000), 1000)

    def dot_frac(v1: list[Fraction], v2: list[Fraction]) -> Fraction:
        return sum((x * y for x, y in zip(v1, v2)), Fraction(0))

    def compute_gs(
        cur_b: list[list[Fraction]],
    ) -> tuple[list[list[Fraction]], list[list[Fraction]]]:
        b_star: list[list[Fraction]] = []
        mu: list[list[Fraction]] = [[Fraction(0)] * n for _ in range(n)]
        for i in range(n):
            v = list(cur_b[i])
            for j in range(i):
                denom = dot_frac(b_star[j], b_star[j])
                if denom != 0:
                    mu[i][j] = dot_frac(cur_b[i], b_star[j]) / denom
                    v = [v[k] - mu[i][j] * b_star[j][k] for k in range(m)]
            mu[i][i] = Fraction(1)
            b_star.append(v)
        return b_star, mu

    k = 1
    b_star, mu = compute_gs(b)

    while k < n:
        # Size reduction
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Fraction(1, 2):
                q_coeff = round(float(mu[k][j]))
                if q_coeff != 0:
                    b[k] = [b[k][x] - q_coeff * b[j][x] for x in range(m)]
                    b_star, mu = compute_gs(b)

        norm_k = dot_frac(b_star[k], b_star[k])
        norm_km1 = dot_frac(b_star[k - 1], b_star[k - 1])
        if norm_k >= (delta_frac - mu[k][k - 1] ** 2) * norm_km1:
            k += 1
        else:
            b[k], b[k - 1] = b[k - 1], b[k]
            b_star, mu = compute_gs(b)
            k = max(k - 1, 1)

    return [[int(x) for x in row] for row in b]


def sage_available() -> bool:
    """Checks whether SageMath is available on the local host."""
    import os
    import shutil

    return shutil.which("sage") is not None or os.path.exists("/usr/local/bin/sage")


def run_sage_script(script_code: str, timeout: int = 30) -> str:
    """Executes a SageMath script securely and returns its stdout."""
    import os
    import shutil
    import subprocess

    sage_bin = shutil.which("sage") or "/usr/local/bin/sage"
    env = dict(os.environ)
    scratch_dir = os.path.abspath("scratch")
    os.makedirs(scratch_dir, exist_ok=True)
    env["HOME"] = scratch_dir
    env["DOT_SAGE"] = os.path.join(scratch_dir, ".sage")

    proc = subprocess.run(
        [sage_bin, "-c", script_code],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Sage execution failed: {proc.stderr}")
    return proc.stdout.strip()
