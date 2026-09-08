"""Unit tests for Lattice and Post-Quantum Cryptography (LWE) algorithms."""

import math

from ichnos.crypto.pqc.lattice import (
    babai_nearest_plane,
    gauss_reduce_2d,
    integer_left_kernel,
    lll_reduce,
)
from ichnos.crypto.pqc.lwe import solve_lwe_dual_kernel


def test_gauss_reduce_2d():
    """Test 2D Gauss lattice reduction yields short, nearly orthogonal basis."""
    v1 = [1234567, 7654321]
    v2 = [2345678, 8765432]
    u, v = gauss_reduce_2d(v1, v2)

    norm_u_sq = u[0] ** 2 + u[1] ** 2
    norm_v_sq = v[0] ** 2 + v[1] ** 2
    assert norm_u_sq <= norm_v_sq

    dot = abs(u[0] * v[0] + u[1] * v[1])
    assert dot <= norm_u_sq / 2.0 + 1e-6


def test_integer_left_kernel():
    """Test integer left kernel finds nullspace vectors u * M = 0."""
    # 4x2 matrix
    M = [
        [1, 2],
        [3, 4],
        [5, 6],
        [7, 8],
    ]
    kernel = integer_left_kernel(M)
    assert len(kernel) == 2  # rank is 2, so nullity is 4 - 2 = 2

    for u in kernel:
        # Check u * M == [0, 0]
        col0 = sum(u[i] * M[i][0] for i in range(4))
        col1 = sum(u[i] * M[i][1] for i in range(4))
        assert col0 == 0
        assert col1 == 0


def test_lll_reduce_small():
    """Test LLL reduction on a small basis."""
    basis = [
        [1, 1, 1],
        [-1, 0, 2],
        [3, 5, 6],
    ]
    red = lll_reduce(basis, delta=0.75)
    assert len(red) == 3
    norms = [math.isqrt(sum(x * x for x in row)) for row in red]
    assert all(n > 0 for n in norms)


def test_babai_nearest_plane():
    """Test Babai nearest plane algorithm."""
    basis = [
        [2.0, 0.0],
        [0.0, 2.0],
    ]
    target = [1.1, 1.9]
    cv = babai_nearest_plane(basis, target)
    assert round(cv[0]) == 2 and round(cv[1]) == 2


def test_lwe_input_validation():
    """Test solve_lwe_dual_kernel returns error dict on invalid inputs."""
    res = solve_lwe_dual_kernel([], [], 123)
    assert "error" in res
