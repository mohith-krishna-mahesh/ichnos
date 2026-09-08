"""Biased-Nonce ECDSA Private Key Recovery via Lattice Reduction.

Solves the Hidden Number Problem (HNP) for ECDSA signatures where nonces k_i
have partially known, small, or biased bits (e.g. leading 8 zero bits).
"""

from __future__ import annotations

from ichnos.crypto.pqc.lattice import lll_reduce


def recover_private_key_biased_nonce(
    signatures: list[tuple[int, int, int]],
    n: int,
    nonce_bit_bound: int,
) -> int | None:
    """Recovers the ECDSA private key d from signatures with biased (small) nonces.

    Args:
        signatures: List of (r, s, z) tuples where r, s are signature components
            and z is the message hash integer.
        n: The elliptic curve order.
        nonce_bit_bound: Upper bound on the nonce bit-length (e.g. 248 for 256-bit curve with 8 bits zero).

    Returns:
        The recovered private key d if successful, None otherwise.
    """
    m = len(signatures)
    if m < 2:
        return None

    t_list: list[int] = []
    u_list: list[int] = []

    for r, s, z in signatures:
        s_inv = pow(s, -1, n)
        t = (s_inv * r) % n
        u = (s_inv * z) % n
        t_list.append(t)
        u_list.append(u)

    K = 2 ** nonce_bit_bound

    # Construct the HNP lattice basis of dimension (m + 2) x (m + 2)
    # Rows:
    # row 0..m-1: [0, ..., n, ..., 0, 0]
    # row m:      [t_0, t_1, ..., t_{m-1}, K / n, 0]
    # row m+1:    [u_0, u_1, ..., u_{m-1}, 0, K]
    scale = max(1, K // n) if K > n else 1
    dim = m + 2
    matrix: list[list[int]] = []

    for i in range(m):
        row = [0] * dim
        row[i] = n
        matrix.append(row)

    row_t = [t for t in t_list] + [scale, 0]
    matrix.append(row_t)

    row_u = [u for u in u_list] + [0, K]
    matrix.append(row_u)

    reduced = lll_reduce(matrix, delta=0.75)

    # Search reduced vectors for candidate d
    for row in reduced:
        cand_d_scaled = row[m]
        if cand_d_scaled != 0:
            cand_d = abs(cand_d_scaled) // scale
            for d in (cand_d % n, (n - cand_d) % n):
                if d > 0:
                    # Check consistency with first signature
                    r0, s0, z0 = signatures[0]
                    k0 = (pow(s0, -1, n) * (z0 + r0 * d)) % n
                    if k0 < (K * 4):
                        # Verify against second signature
                        r1, s1, z1 = signatures[1]
                        k1 = (pow(s1, -1, n) * (z1 + r1 * d)) % n
                        if k1 < (K * 4):
                            return d

    return None
