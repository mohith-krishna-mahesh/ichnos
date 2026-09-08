"""NTRU educational lattice-based public key cryptosystem.

CAVEAT: Educational and CTF-analysis scope only. Not intended for production cryptographic use.
"""

from __future__ import annotations

import random

from ichnos.crypto.numtheory import mod_inverse


def poly_add(a: list[int], b: list[int], mod: int | None = None) -> list[int]:
    n = max(len(a), len(b))
    res = [0] * n
    for i in range(n):
        v = (a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)
        res[i] = v % mod if mod else v
    return res


def poly_mul_mod_ring(a: list[int], b: list[int], n: int, q: int | None = None) -> list[int]:
    """Multiplies polynomials in Z[x] / (x^N - 1) mod q (cyclic convolution)."""
    res = [0] * n
    for i in range(len(a)):
        for j in range(len(b)):
            idx = (i + j) % n
            res[idx] += a[i] * b[j]
    if q is not None:
        res = [x % q for x in res]
    return res


def poly_center_mod(a: list[int], q: int) -> list[int]:
    """Centers coefficients in [-q/2, q/2]."""
    half = q // 2
    return [((x % q + q) % q) - q if ((x % q + q) % q) > half else ((x % q + q) % q) for x in a]


def invert_poly_mod_prime(f: list[int], n: int, p: int) -> list[int] | None:
    """Inverts polynomial f in (Z_p[x] / (x^N - 1)) via circulant matrix Gaussian elimination."""
    # Construct circulant matrix M where M[k][i] = f[(k - i) % n] mod p
    mat = [[f[(r - c) % n] % p for c in range(n)] for r in range(n)]
    # Augmented matrix with identity column (1, 0, ..., 0)^T
    target = [1] + [0] * (n - 1)

    # Gaussian elimination mod p
    for col in range(n):
        # Pivot
        pivot_row = None
        for r in range(col, n):
            if mat[r][col] % p != 0:
                pivot_row = r
                break
        if pivot_row is None:
            return None

        mat[col], mat[pivot_row] = mat[pivot_row], mat[col]
        target[col], target[pivot_row] = target[pivot_row], target[col]

        inv = mod_inverse(mat[col][col] % p, p)
        mat[col] = [(x * inv) % p for x in mat[col]]
        target[col] = (target[col] * inv) % p

        for r in range(n):
            if r != col and mat[r][col] % p != 0:
                factor = mat[r][col] % p
                mat[r] = [(mat[r][c] - factor * mat[col][c]) % p for c in range(n)]
                target[r] = (target[r] - factor * target[col]) % p

    return target


class NTRUEncrypt:
    """Educational NTRUEncrypt instance.

    N: polynomial degree (x^N - 1)
    p: small modulus (typically 3)
    q: large modulus (typically power of 2 or prime)
    """

    def __init__(self, n: int = 11, p: int = 3, q: int = 32):
        self.n = n
        self.p = p
        self.q = q
        self.f: list[int] | None = None
        self.f_p: list[int] | None = None
        self.g: list[int] | None = None
        self.h: list[int] | None = None  # Public key

    def generate_keypair(self) -> tuple[list[int], list[int]]:
        """Generates (public_key_h, private_key_f)."""
        # Small ternary polynomial f with invertible f_p and f_q
        while True:
            # Random ternary f with d+1 ones and d minus ones
            f = [random.choice([-1, 0, 1]) for _ in range(self.n)]
            f[0] = 1
            f_p = invert_poly_mod_prime(f, self.n, self.p)
            f_q = invert_poly_mod_prime(f, self.n, 2)  # For power of 2, check mod 2
            if f_p is not None and f_q is not None:
                break

        # Invert mod q (by Hensel lifting from mod 2 or direct matrix if prime)
        # For small educational params, invert directly mod q using matrix if coprime
        # Or let q = 31 (prime) or 127
        g = [random.choice([-1, 0, 1]) for _ in range(self.n)]
        self.f = f
        self.f_p = f_p
        self.g = g

        # Compute f^-1 mod q
        f_inv_q = invert_poly_mod_prime(f, self.n, self.q)
        if f_inv_q is None:
            # Retry
            return self.generate_keypair()

        # Public key: h = p * f_inv_q * g mod q
        f_inv_g = poly_mul_mod_ring(f_inv_q, g, self.n, self.q)
        self.h = [(self.p * x) % self.q for x in f_inv_g]
        return self.h, self.f

    def encrypt(self, message: list[int], pub_h: list[int]) -> list[int]:
        """Encrypts ternary message m in {-1, 0, 1}^N."""
        # Random small polynomial r in {-1, 0, 1}^N
        r = [random.choice([-1, 0, 1]) for _ in range(self.n)]
        # e = (r * h + m) mod q
        rh = poly_mul_mod_ring(r, pub_h, self.n, self.q)
        return [(rh[i] + message[i]) % self.q for i in range(self.n)]

    def decrypt(self, ciphertext: list[int], priv_f: list[int]) -> list[int]:
        """Decrypts ciphertext using private polynomial f."""
        if self.f_p is None:
            self.f_p = invert_poly_mod_prime(priv_f, self.n, self.p)

        # a = f * e mod q, centered
        a = poly_mul_mod_ring(priv_f, ciphertext, self.n, self.q)
        a_centered = poly_center_mod(a, self.q)

        # m = f_p * a mod p, centered
        m = poly_mul_mod_ring(self.f_p, a_centered, self.n, self.p)
        return poly_center_mod(m, self.p)
