"""Lattice and Post-Quantum Cryptography attack analysis tools.

CAVEAT: Educational and CTF-analysis scope only. Not intended for production cryptographic use.
"""

from __future__ import annotations

import math


def estimate_lwe_hardness(n: int, q: int, sigma: float) -> dict[str, float | bool | str]:
    """Estimates security level and required root Hermite factor delta for LWE(n, q, sigma).

    If required delta >= 1.01, standard BKZ reduction can recover secret in practical CTF time.
    """
    if sigma <= 0 or q <= 0 or n <= 0:
        return {"error": "Invalid parameters"}

    alpha = sigma / q
    log_q = math.log2(q)
    log_alpha_inv = math.log2(1.0 / alpha) if alpha < 1.0 else 0.0

    # Required root Hermite factor delta for primal attack
    log_delta = (log_alpha_inv**2) / (4.0 * n * log_q) if n * log_q > 0 else 0.0
    delta = 2**log_delta

    # Hardness classification:
    # delta >= 1.01 -> Easy / Fast (BKZ-20 or LLL)
    # 1.005 <= delta < 1.01 -> Medium (BKZ-40/60)
    # delta < 1.005 -> Hard (Cryptographic strength)
    is_vulnerable_ctf = delta >= 1.01

    return {
        "n": n,
        "q": q,
        "sigma": sigma,
        "noise_ratio": alpha,
        "root_hermite_factor_delta": delta,
        "is_vulnerable_ctf": is_vulnerable_ctf,
        "attack_feasibility": (
            "Feasible via LLL/BKZ reduction"
            if is_vulnerable_ctf
            else "Infeasible for standard reduction"
        ),
    }


def audit_pqc_parameters(scheme: str, params: dict) -> dict[str, bool | str | dict]:
    """Audits PQC scheme parameters for common CTF weaknesses."""
    scheme_lower = scheme.lower()
    if "lwe" in scheme_lower or "kyber" in scheme_lower:
        n = params.get("n", 256)
        q = params.get("q", 3329)
        sigma = params.get("sigma", 1.0)
        est = estimate_lwe_hardness(n, q, sigma)
        return {
            "scheme": scheme,
            "analysis": est,
            "is_weak": est.get("is_vulnerable_ctf", False),
        }
    elif "ntru" in scheme_lower:
        n = params.get("n", 509)
        q = params.get("q", 2048)
        is_weak = n < 100 or q < 64
        return {
            "scheme": scheme,
            "is_weak": is_weak,
            "comment": "Small NTRU dimension allows lattice reduction recovery of private key f"
            if is_weak
            else "Standard NTRU parameters",
        }
    return {"scheme": scheme, "is_weak": False, "comment": "Unknown scheme"}
