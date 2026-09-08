"""Educational Kyber (CRYSTALS-Kyber / ML-KEM) Module-LWE implementation.

CAVEAT: Educational and CTF-analysis scope only. Not intended for production cryptographic use.
"""

from __future__ import annotations

import random


def poly_mul_anticyclic(a: list[int], b: list[int], n: int, q: int) -> list[int]:
    """Multiplies polynomials in Z_q[x] / (x^n + 1) (anti-cyclic convolution)."""
    res = [0] * n
    for i in range(len(a)):
        for j in range(len(b)):
            deg = i + j
            if deg < n:
                res[deg] = (res[deg] + a[i] * b[j]) % q
            else:
                res[deg - n] = (res[deg - n] - a[i] * b[j]) % q
    return res


def poly_add(a: list[int], b: list[int], q: int) -> list[int]:
    n = max(len(a), len(b))
    return [((a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)) % q for i in range(n)]


def poly_sub(a: list[int], b: list[int], q: int) -> list[int]:
    n = max(len(a), len(b))
    return [((a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0)) % q for i in range(n)]


class EducationalKyber:
    """Pedagogical Kyber ML-KEM with small parameters (n=8, k=2, q=3329)."""

    def __init__(self, n: int = 8, k: int = 2, q: int = 3329):
        self.n = n  # Polynomial degree
        self.k = k  # Module dimension (matrix size k x k)
        self.q = q  # Modulus

    def _sample_small_poly(self) -> list[int]:
        """Samples small noise polynomial with coefficients in {-1, 0, 1}."""
        return [random.choice([-1, 0, 1]) % self.q for _ in range(self.n)]

    def _sample_uniform_poly(self) -> list[int]:
        """Samples uniform polynomial in Z_q."""
        return [random.randint(0, self.q - 1) for _ in range(self.n)]

    def keygen(self) -> tuple[tuple[list[list[list[int]]], list[list[int]]], list[list[int]]]:
        """Generates (public_key=(A, t), secret_key=s)."""
        # A is a k x k matrix of polynomials
        A = [[self._sample_uniform_poly() for _ in range(self.k)] for _ in range(self.k)]
        s = [self._sample_small_poly() for _ in range(self.k)]
        e = [self._sample_small_poly() for _ in range(self.k)]

        # t = A * s + e (mod q)
        t = []
        for i in range(self.k):
            ti = [0] * self.n
            for j in range(self.k):
                prod = poly_mul_anticyclic(A[i][j], s[j], self.n, self.q)
                ti = poly_add(ti, prod, self.q)
            ti = poly_add(ti, e[i], self.q)
            t.append(ti)

        return (A, t), s

    def encrypt(
        self,
        message_bits: list[int],
        public_key: tuple[list[list[list[int]]], list[list[int]]],
    ) -> tuple[list[list[int]], list[int]]:
        """Encrypts message_bits (length up to n) into (u, v)."""
        A, t = public_key
        r = [self._sample_small_poly() for _ in range(self.k)]
        e1 = [self._sample_small_poly() for _ in range(self.k)]
        e2 = self._sample_small_poly()

        # u = A^T * r + e1 (mod q)
        u = []
        for j in range(self.k):
            uj = [0] * self.n
            for i in range(self.k):
                prod = poly_mul_anticyclic(A[i][j], r[i], self.n, self.q)
                uj = poly_add(uj, prod, self.q)
            uj = poly_add(uj, e1[j], self.q)
            u.append(uj)

        # v = t^T * r + e2 + round(q/2) * m (mod q)
        v = [0] * self.n
        for i in range(self.k):
            prod = poly_mul_anticyclic(t[i], r[i], self.n, self.q)
            v = poly_add(v, prod, self.q)
        v = poly_add(v, e2, self.q)

        # Encode message bits as delta = round(q/2) * bit
        delta = self.q // 2
        for idx, bit in enumerate(message_bits[: self.n]):
            if bit:
                v[idx] = (v[idx] + delta) % self.q

        return u, v

    def decrypt(
        self,
        ciphertext: tuple[list[list[int]], list[int]],
        secret_key: list[list[int]],
    ) -> list[int]:
        """Decrypts (u, v) using secret_key s to recover message bits."""
        u, v = ciphertext
        s = secret_key

        # m_approx = v - s^T * u (mod q)
        s_u = [0] * self.n
        for i in range(self.k):
            prod = poly_mul_anticyclic(s[i], u[i], self.n, self.q)
            s_u = poly_add(s_u, prod, self.q)

        diff = poly_sub(v, s_u, self.q)

        # Decode each coefficient: if closer to q/2 than 0, bit is 1
        delta = self.q // 2
        recovered = []
        for c in diff:
            c_mod = c % self.q
            dist_0 = min(c_mod, self.q - c_mod)
            dist_delta = abs(c_mod - delta)
            recovered.append(1 if dist_delta < dist_0 else 0)

        return recovered
