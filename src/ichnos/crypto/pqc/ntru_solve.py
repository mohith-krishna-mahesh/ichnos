"""NTRU / Negacyclic Ring-LWE Lattice Reduction Solver.

Recovers secret polynomials (f, g) from public key h over Z_q[x] / (x^n + 1)
using block lattice reduction:
    B = [ I  H ]
        [ 0 qI ]
Supports pure-Python LLL for small instances and SageMath BKZ for larger instances.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from ichnos.crypto.pqc.lattice import lll_reduce, run_sage_script, sage_available
from ichnos.crypto.symmetric.aes import decrypt_ecb


@dataclass
class NTRUSolution:
    """Represents recovered NTRU private key and decrypted payload."""

    f: list[int]
    g: list[int]
    aes_key: bytes | None = None
    plaintext: bytes | None = None
    method: str = "lll"


def build_negacyclic_matrix(pk: list[int], n: int) -> list[list[int]]:
    """Builds the n x n negacyclic multiplication matrix H for Z[x] / (x^n + 1).

    H[i, j] = pk[j - i] if j >= i else -pk[j - i + n].
    """
    H = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            k = j - i
            if k >= 0:
                H[i][j] = pk[k]
            else:
                H[i][j] = -pk[k + n]
    return H


def verify_ntru_relation(f: list[int], g: list[int], pk: list[int], n: int, q: int) -> bool:
    """Verifies if f * pk == g (mod q) in the negacyclic ring Z_q[x] / (x^n + 1)."""
    for i in range(n):
        s = 0
        for j in range(n):
            k = i - j
            if k >= 0:
                s += f[j] * pk[k]
            else:
                s -= f[j] * pk[k + n]
        if (s - g[i]) % q != 0:
            return False
    return True


def solve_ntru_lattice(
    pk: list[int],
    q: int,
    n: int | None = None,
    ciphertext: bytes | None = None,
    bound: int = 6,
    block_size: int = 45,
    force_sage: bool = False,
) -> NTRUSolution | None:
    """Recovers small private polynomials f, g from public key pk mod q in (x^n + 1).

    Args:
        pk: Public key polynomial coefficients of length n.
        q: Modulus q.
        n: Polynomial degree / dimension (defaults to len(pk)).
        ciphertext: Optional AES ciphertext to decrypt using derived key.
        bound: Maximum absolute coefficient value for secret polynomial.
        block_size: BKZ block size when delegating to SageMath.
        force_sage: If True, requires SageMath execution.

    Returns:
        NTRUSolution on success, or None if no valid key was recovered.
    """
    dim = n or len(pk)
    pk = list(pk[:dim])

    secret_f: list[int] | None = None
    secret_g: list[int] | None = None
    method_used = "lll"

    # If dimension is small (<= 16) and Sage not forced, attempt pure-Python LLL
    if dim <= 16 and not force_sage:
        H = build_negacyclic_matrix(pk, dim)
        # Construct 2n x 2n block lattice:
        # [ I  H ]
        # [ 0 qI ]
        basis: list[list[int]] = []
        for i in range(dim):
            row_i = [1 if k == i else 0 for k in range(dim)] + H[i]
            basis.append(row_i)
        for i in range(dim):
            row_qi = [0] * dim + [q if k == i else 0 for k in range(dim)]
            basis.append(row_qi)

        reduced = lll_reduce(basis, delta=0.75)
        for row in reduced:
            f0 = row[:dim]
            g0 = row[dim:]
            for cand_f, cand_g in [(f0, g0), (g0, f0)]:
                if max(abs(x) for x in cand_f) <= bound and max(abs(x) for x in cand_g) <= bound:
                    for sf in [cand_f, [-x for x in cand_f]]:
                        for sg in [cand_g, [-x for x in cand_g]]:
                            if verify_ntru_relation(sf, sg, pk, dim, q):
                                secret_f = sf
                                secret_g = sg
                                break
                        if secret_f is not None:
                            break
                if secret_f is not None:
                    break
            if secret_f is not None:
                break

    # If not solved yet and Sage is available, run Sage BKZ
    if secret_f is None and sage_available():
        method_used = f"sage_bkz_{block_size}"
        sage_code = f"""
import json

n = {dim}
q = {q}
pk = {pk}
bound = {bound}
b_size = {block_size}

H = matrix(ZZ, n, n)
for i in range(n):
    for j in range(n):
        k = j - i
        if k >= 0:
            H[i, j] = pk[k]
        else:
            H[i, j] = -pk[k + n]

I = identity_matrix(ZZ, n)
Z = zero_matrix(ZZ, n)

B = block_matrix(ZZ, [
    [I, H],
    [Z, q * I]
])

L = B.BKZ(block_size=b_size) if b_size > 2 else B.LLL()

def small(v, b):
    return max(abs(ZZ(x)) for x in v) <= b

def verify(f, g):
    for i in range(n):
        s = 0
        for j in range(n):
            k = i - j
            if k >= 0:
                s += f[j] * pk[k]
            else:
                s -= f[j] * pk[k + n]
        if (s - g[i]) % q != 0:
            return False
    return True

found = None
for row in L.rows():
    f0 = list(row[:n])
    g0 = list(row[n:])
    for cand_f, cand_g in [(f0, g0), (g0, f0)]:
        if small(cand_f, bound) and small(cand_g, bound):
            for sf in [cand_f, [-x for x in cand_f]]:
                for sg in [cand_g, [-x for x in cand_g]]:
                    if verify(sf, sg):
                        found = (sf, sg)
                        break
                if found:
                    break
        if found:
            break
    if found:
        break

if found:
    print(json.dumps({{"f": [int(x) for x in found[0]], "g": [int(x) for x in found[1]]}}))
else:
    print("null")
"""
        try:
            out = run_sage_script(sage_code, timeout=120)
            data = json.loads(out)
            if data and "f" in data:
                secret_f = data["f"]
                secret_g = data.get("g", [])
        except Exception:
            pass

    if secret_f is None:
        return None

    # Optional AES decryption
    aes_key: bytes | None = None
    plaintext: bytes | None = None
    if ciphertext:
        # Challenge convention: key = sha256(bytes(f[i] % 256 for i in range(n)))
        raw_key_bytes = bytes(x % 256 for x in secret_f)
        aes_key = hashlib.sha256(raw_key_bytes).digest()

        try:
            pt = decrypt_ecb(aes_key, ciphertext)
            # Remove PKCS#7 padding if present
            if pt:
                pad_len = pt[-1]
                if 1 <= pad_len <= 16 and pt.endswith(bytes([pad_len]) * pad_len):
                    pt = pt[:-pad_len]
            plaintext = pt
        except Exception:
            pass

    return NTRUSolution(
        f=secret_f,
        g=secret_g or [],
        aes_key=aes_key,
        plaintext=plaintext,
        method=method_used,
    )
