"""Unit tests for AutoSolver RSA attack suite."""

import math

from ichnos.core.solver import AutoSolver

# Verified 256-bit prime numbers
P = 91504757838363943504295625810220813967989474844339778893801137976004695306807
Q = 68153637887010023264406645865511423597382660425424362250152301727681392470611
R = 110413925358020719269592417955850500969137321350008250905077228929880941219911


def test_solver_rsa_shared_factor():
    n1 = P * Q
    n2 = Q * R
    e = 65537

    msg = b"FLAG{shared_factor_auto_solved}"
    m = int.from_bytes(msg, "big")
    c1 = pow(m, e, n1)

    challenge_text = f"""
N1 = {n1}
N2 = {n2}
e = {e}
c1 = {c1}
"""
    trace, result = AutoSolver.solve(active_text=challenge_text)

    assert trace.solved is True
    assert trace.flag == "FLAG{shared_factor_auto_solved}"
    assert "Shared Prime" in trace.attack_name
    assert result.status == "success"


def test_solver_rsa_common_modulus():
    n = P * Q
    e1 = 3
    e2 = 65537
    assert math.gcd(e1, e2) == 1

    msg = b"FLAG{common_modulus_solved}"
    m = int.from_bytes(msg, "big")

    c1 = pow(m, e1, n)
    c2 = pow(m, e2, n)

    challenge_text = f"""
n = {n}
e1 = {e1}
e2 = {e2}
c1 = {c1}
c2 = {c2}
"""
    trace, result = AutoSolver.solve(active_text=challenge_text)

    assert trace.solved is True
    assert trace.flag == "FLAG{common_modulus_solved}"
    assert "Common Modulus" in trace.attack_name


def test_solver_rsa_small_e_direct_root():
    n = P * Q
    e = 3

    msg = b"FLAG{cube_root}"
    m = int.from_bytes(msg, "big")
    c = pow(m, e)
    assert c < n  # Unpadded small e condition (360 bits < 512 bits)

    challenge_text = f"""
N = {n}
e = {e}
c = {c}
"""
    trace, result = AutoSolver.solve(active_text=challenge_text)

    assert trace.solved is True
    assert trace.flag == "FLAG{cube_root}"
    assert "Direct Root" in trace.attack_name


def test_solver_rsa_small_factors_partial_modulus():
    # Construct smooth component from small primes
    primes = [
        10007,
        10009,
        10037,
        10039,
        10061,
        10067,
        10069,
        10079,
        10091,
        10093,
        10099,
        10103,
        10111,
        10133,
        10139,
        10141,
        10151,
    ]
    n_small = 1
    for p in primes:
        n_small *= p
    n = n_small * P
    e = 65537

    msg = b"FLAG{small_factors_solved}"
    m = int.from_bytes(msg, "big")
    assert m < n_small

    c = pow(m, e, n)

    challenge_text = f"""
N = {n}
e = {e}
ct = {c}
"""
    trace, result = AutoSolver.solve(active_text=challenge_text)

    assert trace.solved is True
    assert trace.flag == "FLAG{small_factors_solved}"
    assert "Small Prime Factor" in trace.attack_name
