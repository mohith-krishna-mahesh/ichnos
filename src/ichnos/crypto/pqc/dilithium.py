"""Educational Dilithium (CRYSTALS-Dilithium / ML-DSA) signature implementation.

CAVEAT: Educational and CTF-analysis scope only. Not intended for production cryptographic use.
"""

from __future__ import annotations

import hashlib
import random

from ichnos.crypto.pqc.kyber import poly_add, poly_mul_anticyclic, poly_sub


class EducationalDilithium:
    """Pedagogical Dilithium ML-DSA with small parameters (n=8, k=2, l=2, q=8380417)."""

    def __init__(self, n: int = 8, k: int = 2, l: int = 2, q: int = 8380417):
        self.n = n
        self.k = k  # Dimensions of A (k x l)
        self.l = l
        self.q = q
        self.gamma1 = 1 << 17

    def _sample_small_poly(self, bound: int = 2) -> list[int]:
        return [random.randint(-bound, bound) % self.q for _ in range(self.n)]

    def _sample_mask_poly(self) -> list[int]:
        return [random.randint(0, self.gamma1) % self.q for _ in range(self.n)]

    def keygen(self) -> tuple[tuple[list[list[list[int]]], list[list[int]]], list[list[int]]]:
        """Generates (public_key=(A, t), secret_key=s1)."""
        # A is k x l matrix of uniform polynomials
        A = [
            [[random.randint(0, self.q - 1) for _ in range(self.n)] for _ in range(self.l)]
            for _ in range(self.k)
        ]
        s1 = [self._sample_small_poly() for _ in range(self.l)]

        # t = A * s1 (mod q)
        t = []
        for i in range(self.k):
            ti = [0] * self.n
            for j in range(self.l):
                prod = poly_mul_anticyclic(A[i][j], s1[j], self.n, self.q)
                ti = poly_add(ti, prod, self.q)
            t.append(ti)

        return (A, t), s1

    def _challenge_hash(self, w: list[list[int]], message: bytes) -> list[int]:
        """Simple hash to challenge polynomial with small ternary coefficients."""
        h = hashlib.sha256()
        h.update(message)
        for poly in w:
            for coeff in poly:
                h.update(str(coeff).encode())
        digest = h.digest()
        # Derive n coefficients in {-1, 0, 1}
        c = []
        for b in digest[: self.n]:
            c.append((b % 3) - 1)
        while len(c) < self.n:
            c.append(0)
        return [x % self.q for x in c]

    def sign(
        self,
        message: bytes,
        public_key: tuple[list[list[list[int]]], list[list[int]]],
        secret_key: list[list[int]],
    ) -> tuple[list[list[int]], list[int]]:
        """Computes signature (z, c)."""
        A, _ = public_key
        s1 = secret_key

        y = [self._sample_mask_poly() for _ in range(self.l)]
        # w = A * y (mod q)
        w = []
        for i in range(self.k):
            wi = [0] * self.n
            for j in range(self.l):
                prod = poly_mul_anticyclic(A[i][j], y[j], self.n, self.q)
                wi = poly_add(wi, prod, self.q)
            w.append(wi)

        c = self._challenge_hash(w, message)

        # z = y + c * s1 (mod q)
        z = []
        for j in range(self.l):
            cs = poly_mul_anticyclic(c, s1[j], self.n, self.q)
            zj = poly_add(y[j], cs, self.q)
            z.append(zj)

        return z, c

    def verify(
        self,
        message: bytes,
        signature: tuple[list[list[int]], list[int]],
        public_key: tuple[list[list[list[int]]], list[list[int]]],
    ) -> bool:
        """Verifies signature (z, c)."""
        z, c = signature
        A, t = public_key

        # w_prime = A * z - c * t (mod q)
        w_prime = []
        for i in range(self.k):
            wi = [0] * self.n
            for j in range(self.l):
                prod = poly_mul_anticyclic(A[i][j], z[j], self.n, self.q)
                wi = poly_add(wi, prod, self.q)
            ct = poly_mul_anticyclic(c, t[i], self.n, self.q)
            wi = poly_sub(wi, ct, self.q)
            w_prime.append(wi)

        c_prime = self._challenge_hash(w_prime, message)
        return c == c_prime
