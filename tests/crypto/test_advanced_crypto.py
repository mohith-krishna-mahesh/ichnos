"""Tests for advanced cryptanalysis techniques in Ichnos.

Covers:
- Meet-in-the-Middle (MITM) attack engine
- DES weak and semi-weak key detection and properties
- Coppersmith univariate small roots (stereotyped message)
- Bleichenbacher Million Message PKCS#1 v1.5 padding oracle
- Biased-nonce ECDSA lattice recovery (Hidden Number Problem)
- Franklin-Reiter related message attack
- Boneh-Durfee low private exponent attack
- Bellcore RSA-CRT fault injection
"""

import math

from ichnos.crypto.ecc.ecdsa_bias import recover_private_key_biased_nonce
from ichnos.crypto.rsa.bellcore import bellcore_fault_attack
from ichnos.crypto.rsa.bleichenbacher import bleichenbacher_attack
from ichnos.crypto.rsa.boneh_durfee import boneh_durfee_attack
from ichnos.crypto.rsa.coppersmith import stereotyped_message
from ichnos.crypto.rsa.franklin_reiter import franklin_reiter_poly_attack
from ichnos.crypto.symmetric.attacks.mitm import meet_in_the_middle
from ichnos.crypto.symmetric.des import (
    des_encrypt_ecb,
    is_des_semi_weak_key,
    is_des_weak_key,
)


def test_meet_in_the_middle():
    # Simple 2-byte key Caesar-like double cipher
    def enc(k: bytes, p: bytes) -> bytes:
        shift = k[0]
        return bytes((b + shift) % 256 for b in p)

    def dec(k: bytes, p: bytes) -> bytes:
        shift = k[0]
        return bytes((b - shift) % 256 for b in p)

    target_k1 = bytes([42])
    target_k2 = bytes([137])
    p1 = b"HELLO_MITM_ATTACK_1"
    c1 = enc(target_k2, enc(target_k1, p1))
    p2 = b"HELLO_MITM_ATTACK_2"
    c2 = enc(target_k2, enc(target_k1, p2))

    keys1 = [bytes([i]) for i in range(256)]
    keys2 = [bytes([i]) for i in range(256)]

    res = meet_in_the_middle([(p1, c1), (p2, c2)], enc, dec, keys1, keys2)
    assert res is not None
    k1_rec, k2_rec = res
    # Verify recovered keys decrypt correctly
    assert enc(k2_rec, enc(k1_rec, p1)) == c1


def test_des_weak_and_semi_weak_keys():
    weak_key = bytes.fromhex("0101010101010101")
    assert is_des_weak_key(weak_key) is True
    assert is_des_weak_key(b"12345678") is False

    k1 = bytes.fromhex("01FE01FE01FE01FE")
    is_semi, k2 = is_des_semi_weak_key(k1)
    assert is_semi is True
    assert k2 == bytes.fromhex("FE01FE01FE01FE01")

    # Involutory dual key property: E_k2(E_k1(P)) == P
    pt = b"FLAG_123"
    ct1 = des_encrypt_ecb(k1, pt)
    ct2 = des_encrypt_ecb(k2, ct1)
    assert ct2 == pt


def test_coppersmith_stereotyped_message():
    p = 1000000007
    q = 1000000009
    N = p * q
    e = 3
    # Plaintext: prefix + 1 unknown char + suffix
    prefix = b"FLAG{"
    unknown = b"X"
    suffix = b"}"
    full_msg = prefix + unknown + suffix
    c = pow(int.from_bytes(full_msg, "big"), e, N)

    recovered = stereotyped_message(
        prefix=prefix,
        suffix=suffix,
        total_len=len(full_msg),
        c=c,
        e=e,
        N=N,
    )
    assert recovered == full_msg


def test_bleichenbacher_attack():
    p = 1009
    q = 1013
    N = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    assert math.gcd(e, phi) == 1
    d = pow(e, -1, phi)

    k_bytes = (N.bit_length() + 7) // 8
    B = 2 ** (8 * (k_bytes - 2))

    # m satisfies 2*B <= m < 3*B
    m = 2 * B + 50
    c = pow(m, e, N)

    def oracle(ciphertext: int) -> bool:
        dec = pow(ciphertext, d, N)
        return 2 * B <= dec < 3 * B

    rec_m = bleichenbacher_attack(c, e, N, oracle, k_bytes=k_bytes, max_queries=2000)
    assert rec_m == m


def test_franklin_reiter_attack():
    p = 1000000007
    q = 1000000009
    N = p * q
    e = 3
    m1 = 123456789
    # m2 = m1 + 5
    m2 = m1 + 5
    c1 = pow(m1, e, N)
    c2 = pow(m2, e, N)

    rec = franklin_reiter_poly_attack(N, e, c1, c2, a=1, b=5)
    assert rec == m1


def test_boneh_durfee_attack():
    p = 10007
    q = 10009
    N = p * q
    phi = (p - 1) * (q - 1)
    d = 7
    assert math.gcd(d, phi) == 1
    e = pow(d, -1, phi)

    factors = boneh_durfee_attack(N, e)
    assert factors is not None
    p_rec, q_rec = factors
    assert p_rec * q_rec == N


def test_bellcore_fault_attack():
    p = 61
    q = 53
    N = p * q
    e = 17
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = 65

    # Correct signature
    s = pow(m, d, N)

    # Faulty signature in CRT computation mod q
    dp = d % (p - 1)
    dq = d % (q - 1)
    sp = pow(m, dp, p)
    sq = pow(m, dq, q)
    sq_faulty = (sq + 1) % q

    # Combine CRT with faulty sq
    q_inv = pow(q, -1, p)
    h = ((sp - sq_faulty) * q_inv) % p
    s_faulty = (sq_faulty + h * q) % N

    factors = bellcore_fault_attack(N, s_faulty, valid_sig=s)
    assert factors is not None
    p_rec, q_rec = factors
    assert p_rec * q_rec == N
    assert {p_rec, q_rec} == {p, q}


def test_ecdsa_bias_hnp():
    # Test solving biased ECDSA
    # Using order q where nonce k is bounded
    order = 65537
    target_d = 42
    # Samples with small k (nonce < 2^8)
    samples = []
    for i in range(1, 8):
        k = i * 15
        z = (i * 997) % order
        r = (k * 3) % order
        s = (pow(k, -1, order) * (z + target_d * r)) % order
        samples.append((r, s, z))

    rec = recover_private_key_biased_nonce(samples, order, nonce_bit_bound=8)
    assert rec is not None
