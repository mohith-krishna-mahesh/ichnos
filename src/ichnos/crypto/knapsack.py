"""Merkle-Hellman Knapsack Cryptosystem."""

from __future__ import annotations

import random

from ichnos.crypto.numtheory import gcd, mod_inverse


def is_superincreasing(seq: list[int]) -> bool:
    """Checks if sequence is superincreasing (each element > sum of preceding elements)."""
    running_sum = 0
    for val in seq:
        if val <= running_sum:
            return False
        running_sum += val
    return True


def solve_superincreasing(target: int, seq: list[int]) -> list[int]:
    """Solves subset-sum for a superincreasing sequence greedily."""
    bits = [0] * len(seq)
    curr = target
    for i in range(len(seq) - 1, -1, -1):
        if curr >= seq[i]:
            bits[i] = 1
            curr -= seq[i]
    if curr != 0:
        raise ValueError("Target sum cannot be formed by the superincreasing sequence")
    return bits


class MerkleHellman:
    """Merkle-Hellman additive knapsack cryptosystem."""

    def __init__(self, private_w: list[int], q: int, r: int):
        if not is_superincreasing(private_w):
            raise ValueError("Private key sequence must be superincreasing")
        if q <= sum(private_w):
            raise ValueError("Modulus q must be greater than sum of private sequence")
        if gcd(r, q) != 1:
            raise ValueError("Multiplier r must be coprime to modulus q")

        self.w = private_w
        self.q = q
        self.r = r
        # Public key: beta_i = (r * w_i) mod q
        self.public_key = [(r * x) % q for x in private_w]

    @classmethod
    def generate(cls, n_bits: int = 8) -> MerkleHellman:
        """Generates a random keypair."""
        w = []
        s = 2
        for _ in range(n_bits):
            val = s + random.randint(1, 10)
            w.append(val)
            s += val
        q = s + random.randint(5, 50)
        while True:
            r = random.randint(2, q - 1)
            if gcd(r, q) == 1:
                break
        return cls(w, q, r)

    def encrypt(self, bitstring: str | list[int]) -> int:
        """Encrypts bits into knapsack sum."""
        if isinstance(bitstring, str):
            bits = [int(b) for b in bitstring]
        else:
            bits = list(bitstring)

        if len(bits) != len(self.public_key):
            raise ValueError(f"Bit length {len(bits)} must match key length {len(self.public_key)}")

        return sum(b * k for b, k in zip(bits, self.public_key))

    def decrypt(self, ciphertext: int) -> list[int]:
        """Decrypts ciphertext sum using private multiplier inverse and superincreasing sequence."""
        r_inv = mod_inverse(self.r, self.q)
        c_prime = (ciphertext * r_inv) % self.q
        return solve_superincreasing(c_prime, self.w)
