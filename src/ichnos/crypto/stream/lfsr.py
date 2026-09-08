"""Linear Feedback Shift Register (LFSR) & Berlekamp–Massey Algorithm.

Finds the minimal connection polynomial C(x) over GF(2) that generates an observed
sequence of bits, enabling future keystream prediction and state recovery.
"""

from __future__ import annotations


def berlekamp_massey(sequence: list[int]) -> list[int]:
    """Computes the minimal connection polynomial C(x) over GF(2) for a given binary sequence.

    Returns coefficients of C(x) = c0 + c1*x + ... + cL*x^L with c0 = 1.
    """
    n = len(sequence)
    # c and b are polynomials over GF(2) represented as lists
    c = [1]
    b = [1]
    l = 0
    m = 1

    for i in range(n):
        # Calculate discrepancy d = s[i] ^ sum(c[j] * s[i - j] for j in 1..l)
        d = sequence[i]
        for j in range(1, len(c)):
            if j <= i:
                d ^= c[j] & sequence[i - j]

        if d == 0:
            m += 1
        else:
            t = list(c)
            # c = c ^ (x^m * b)
            # Pad c if necessary
            target_len = max(len(c), len(b) + m)
            while len(c) < target_len:
                c.append(0)

            for j in range(len(b)):
                c[j + m] ^= b[j]

            if 2 * l <= i:
                l = i + 1 - l
                b = t
                m = 1
            else:
                m += 1

    # Strip trailing zeros
    while len(c) > 1 and c[-1] == 0:
        c.pop()
    return c


def lfsr_step(state: list[int], taps: list[int]) -> tuple[int, list[int]]:
    """Performs one step of Fibonacci LFSR.

    taps: indices (1-indexed) of tap positions that feedback to new bit.
    """
    out_bit = state[0]
    feedback = 0
    for tap in taps:
        if 1 <= tap <= len(state):
            feedback ^= state[tap - 1]
    new_state = state[1:] + [feedback]
    return out_bit, new_state


def lfsr_recover_and_predict(observed_bits: list[int], num_future_bits: int) -> list[int]:
    """Recovers the LFSR polynomial from observed bits and predicts future bits."""
    poly = berlekamp_massey(observed_bits)
    length = len(poly) - 1
    if length == 0 or len(observed_bits) < 2 * length:
        raise ValueError(f"Insufficient bits to reliably reconstruct LFSR (need >= 2*L={2*length} bits)")

    # Taps are indices where poly[j] == 1 for j in 1..length
    taps = [j for j in range(1, len(poly)) if poly[j] == 1]

    # Most recent `length` bits form current state
    state = list(observed_bits[-length:])
    predicted = []

    for _ in range(num_future_bits):
        feedback = 0
        for tap in taps:
            feedback ^= state[-tap]
        predicted.append(feedback)
        state = state[1:] + [feedback]

    return predicted
