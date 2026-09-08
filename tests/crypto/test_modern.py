"""Tests for modern crypto, math-heavy algorithms, JWT, and PQC."""

from __future__ import annotations

import hashlib

from ichnos.crypto.dh import DiffieHellman, is_small_subgroup_element
from ichnos.crypto.ecc import SECP256K1, EllipticCurve, Point, audit_curve, get_generator
from ichnos.crypto.elgamal import (
    elgamal_decrypt,
    elgamal_encrypt,
    elgamal_recover_private_key_nonce_reuse,
    elgamal_sign,
    elgamal_verify,
)
from ichnos.crypto.hashing.discrete_log import baby_step_giant_step, pohlig_hellman
from ichnos.crypto.hashing.length_extension import sha1_extend, sha256_extend
from ichnos.crypto.jwt import (
    jwt_attack_none,
    jwt_brute_force_hmac,
    jwt_decode,
    jwt_encode,
)
from ichnos.crypto.knapsack import MerkleHellman, is_superincreasing
from ichnos.crypto.pqc import (
    EducationalDilithium,
    EducationalKyber,
    NTRUEncrypt,
    babai_nearest_plane,
    estimate_lwe_hardness,
)
from ichnos.crypto.rsa import (
    auto_attack,
    common_factor_attack,
    common_modulus_attack,
    fermat_factor,
    franklin_reiter_attack,
    hastad_broadcast_attack,
    pollard_rho,
    wiener_attack,
)

# =============================================================================
# RSA Tests
# =============================================================================


def test_rsa_wiener_attack():
    # Known small d test case
    n = 160523347
    e = 60728973
    d = wiener_attack(n, e)
    assert d == 37
    # Verify encryption/decryption
    m = 12345
    c = pow(m, e, n)
    assert pow(c, d, n) == m


def test_rsa_fermat_factor():
    p = 1000003
    q = 1000033
    n = p * q
    factors = fermat_factor(n)
    assert factors == (p, q)


def test_rsa_pollard_rho():
    p = 4999
    q = 5003
    n = p * q
    f = pollard_rho(n)
    assert f in (p, q)


def test_rsa_common_modulus():
    p, q = 61, 53
    n = p * q
    m = 42
    e1, e2 = 17, 19
    c1 = pow(m, e1, n)
    c2 = pow(m, e2, n)
    recovered = common_modulus_attack(n, e1, e2, c1, c2)
    assert recovered == m


def test_rsa_common_factor():
    p = 183101473924506243423644697489137315699
    q = 290957190006546988083885212720196470159
    r = 268332538601094059473841878648184317339
    n1 = p * q
    n2 = q * r
    e = 65537
    flag = b"FLAG{common_factor_works}"
    m = int.from_bytes(flag, "big")
    c1 = pow(m, e, n1)

    result = common_factor_attack(n1, n2, c=c1, e=e)
    assert result["shared_factor"] == q
    assert result["p1"] == p
    assert result["p2"] == r
    assert result["plaintext"] == "FLAG{common_factor_works}"


def test_rsa_hastad_broadcast():
    m = 777
    e = 3
    n1, n2, n3 = 10007 * 10009, 10037 * 10039, 10067 * 10069
    c1 = pow(m, e, n1)
    c2 = pow(m, e, n2)
    c3 = pow(m, e, n3)
    recovered = hastad_broadcast_attack([c1, c2, c3], [n1, n2, n3], e)
    assert recovered == m


def test_rsa_franklin_reiter():
    p, q = 10007, 10009
    n = p * q
    m1 = 1337
    a, b = 3, 5
    m2 = (a * m1 + b) % n
    c1 = pow(m1, 3, n)
    c2 = pow(m2, 3, n)
    recovered = franklin_reiter_attack(n, 3, c1, c2, a, b)
    assert recovered == m1


def test_rsa_auto_attack():
    p, q = 65537, 65539
    n = p * q
    e = 65537
    m = 4242
    c = pow(m, e, n)
    recovered = auto_attack(n, e, c)
    assert recovered == m


def test_rsa_wiener_1024bit():
    """Wiener attack against standard 1024-bit RSA modulus with small private exponent d < (1/3)*N^0.25."""
    n = int(
        "0x6e940500ae97bbb6b5a5461f146352ff47ea9f3f707485beff96c20475c862fcb993000b81d458d57df581cc8eda727009eeed92c6cc92b1cca31d544c837c18bbaa605998a817387ff86b60d0385a80ea0a87ce719c4e8a254b60f522a35955f95710757b3cf1d323372f0d6f2c28acdcb8bb0f393bc6aad921c682ff6ef037",
        16,
    )
    e = int(
        "0x33ce86949c4c839617a0e89518d201706963e3a6b497e4b27849c98a54a0435ec6c88a376a8da23949ba2a23a2930a63d61399087db1dce992d98d780d64cdb513cf87068bb8d815d37b267747d724092339dee3b44dbbafca1383b4108eb23984b0597f038d2c2a35f51c1a76a28cfcf3c34ec660117748151c719d651fbfe5",
        16,
    )
    expected_d = int(
        "0x25e464f2502ec94f6ed34a2f38766e93561538da9a90170fad328135f15d",
        16,
    )
    assert 1020 <= n.bit_length() <= 1024
    d = wiener_attack(n, e)
    assert d == expected_d

    # Test encryption/decryption with recovered d
    m = int.from_bytes(b"FLAG{wiener_1024bit_broken}", "big")
    c = pow(m, e, n)
    assert pow(c, d, n) == m


def test_rsa_fermat_1024bit_close_primes():
    """Fermat factorization of 1024-bit modulus where primes p and q differ by only 138."""
    p = int(
        "0xdc1ed35fca2410fda28718e5623a7a755531ae6dd30a286ec6737b8b2a6a7b5fbb5d75b895f628f2922badb05da83cffb5bab1cd888417a5ecefe37b9e250e23",
        16,
    )
    q = int(
        "0xdc1ed35fca2410fda28718e5623a7a755531ae6dd30a286ec6737b8b2a6a7b5fbb5d75b895f628f2922badb05da83cffb5bab1cd888417a5ecefe37b9e250ead",
        16,
    )
    n = p * q
    assert n.bit_length() == 1024
    assert abs(p - q) == 138
    f1, f2 = fermat_factor(n)
    assert {f1, f2} == {p, q}


def test_rsa_common_modulus_512bit():
    """Common modulus attack on 512-bit RSA modulus with coprime exponents e1=65537, e2=65539."""
    n = int(
        "0x9da8df1660fb8f5f9e87f0ca2e96d15962a610a7a3995e814f937e768527723ba1a5e4cffd6049406dce65f58d365a0570d3032fb8366e001b39c8a8afb0dbcb",
        16,
    )
    e1, e2 = 65537, 65539
    m = int.from_bytes(b"FLAG{common_modulus_512bit}", "big")
    c1 = pow(m, e1, n)
    c2 = pow(m, e2, n)
    recovered = common_modulus_attack(n, e1, e2, c1, c2)
    assert recovered == m


def test_rsa_hastad_broadcast_512bit():
    """Hastad broadcast attack with e=3 across 3 distinct 512-bit moduli."""
    m = int.from_bytes(b"FLAG{hastad_broadcast_3_moduli}", "big")
    e = 3
    n1 = int(
        "0xbef307775ba66a504cbfa0214a1c0d453664fa7d6e5d8ff68953158c3dbcb9ad99ad6fce6e5c5457ef459fa4f1cf20272b144bc3dffdbec4188b77054942e6f9",
        16,
    )
    n2 = int(
        "0xeb51945196f7c9e1262d989f658ebc469f6874e0d9b439c0fa4ae91e4ca5156ffc45bb29e0da9ff31b40285a8efb7a5a87be23565bc941d497be4d2077e68fa7",
        16,
    )
    n3 = int(
        "0xc7f1dc09bf5be788dafc4ceef1caeb3ebbeae3e85e505877f88463133866b1a2082b4dc201886c52a0a2df25553e1a84f33dae580e0c1901a1829f79b4a4cb9d",
        16,
    )
    c1 = pow(m, e, n1)
    c2 = pow(m, e, n2)
    c3 = pow(m, e, n3)
    recovered = hastad_broadcast_attack([c1, c2, c3], [n1, n2, n3], e)
    assert recovered == m


# =============================================================================
# ECC Tests
# =============================================================================


def test_ecc_point_arithmetic_small_curve():
    # Curve: y^2 = x^3 + 2x + 3 (mod 97)
    curve = EllipticCurve("test97", p=97, a=2, b=3)
    p1 = Point(3, 6, curve)
    assert curve.is_on_curve(p1.x, p1.y)

    # Doubling
    p2 = p1 + p1
    assert curve.is_on_curve(p2.x, p2.y)
    assert (p2.x, p2.y) == (80, 10)

    # Order of P is 5
    p5 = 5 * p1
    assert p5.is_infinity

    # Inverse
    neg_p1 = -p1
    assert (p1 + neg_p1).is_infinity


def test_ecc_secp256k1():
    g = get_generator(SECP256K1)
    assert SECP256K1.is_on_curve(g.x, g.y)
    g2 = g + g
    assert SECP256K1.is_on_curve(g2.x, g2.y)
    audit = audit_curve(SECP256K1)
    assert not audit["is_weak"]


def test_ecc_secp256k1_rfc6979_published_vectors():
    """Validates secp256k1 against published IETF RFC 6979 (Section A.2.5) test vectors."""
    g = get_generator(SECP256K1)

    # 1. Scalar multiplication by curve order yields point at infinity
    assert (SECP256K1.order * g).is_infinity

    # 2. Small scalar multiplication (SECG SEC 2 Section 2.4.1)
    p2 = 2 * g
    assert hex(p2.x) == "0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    assert hex(p2.y) == "0x1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"

    p3 = 3 * g
    assert hex(p3.x) == "0xf9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    assert hex(p3.y) == "0x388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672"

    # 3. RFC 6979 Section A.2.5 private key scalar multiplication
    k = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    pk = k * g
    expected_x = 0x2C8C31FC9F990C6B55E3865A184A4CE50E09481F2EAEB3E60EC1CEA13A6AE645
    expected_y = 0x64B95E4FDB6948C0386E189B006A29F686769B011704275E4459822DC3328085
    assert pk.x == expected_x
    assert pk.y == expected_y


# =============================================================================
# Diffie-Hellman & ElGamal Tests
# =============================================================================


def test_diffie_hellman_exchange():
    p = 23
    g = 5
    dh_alice = DiffieHellman(p, g)
    dh_bob = DiffieHellman(p, g)

    a = 6
    pub_a = dh_alice.public_key(a)

    b = 15
    pub_b = dh_bob.public_key(b)

    secret_alice = dh_alice.shared_secret(a, pub_b)
    secret_bob = dh_bob.shared_secret(b, pub_a)
    assert secret_alice == secret_bob
    assert not is_small_subgroup_element(pub_a, p)
    assert is_small_subgroup_element(1, p)
    assert is_small_subgroup_element(p - 1, p)


def test_elgamal_encrypt_decrypt():
    p = 10007
    g = 5
    x = 1234  # private key
    y = pow(g, x, p)  # public key

    m = 42
    c1, c2 = elgamal_encrypt(m, p, g, y)
    decrypted = elgamal_decrypt(c1, c2, p, x)
    assert decrypted == m


def test_elgamal_sign_verify():
    p = 10007
    g = 5
    x = 4321
    y = pow(g, x, p)

    m = 999
    r, s = elgamal_sign(m, p, g, x)
    assert elgamal_verify(m, r, s, p, g, y)
    assert not elgamal_verify(m + 1, r, s, p, g, y)


def test_elgamal_nonce_reuse():
    p = 10007
    g = 5
    x = 1337
    y = pow(g, x, p)

    k_fixed = 4567
    m1 = 111
    m2 = 222
    r1, s1 = elgamal_sign(m1, p, g, x, k=k_fixed)
    r2, s2 = elgamal_sign(m2, p, g, x, k=k_fixed)
    assert r1 == r2

    recovered_x = elgamal_recover_private_key_nonce_reuse(m1, s1, m2, s2, r1, p, g=g, y=y)
    assert recovered_x == x


# =============================================================================
# Knapsack Cryptosystem Tests
# =============================================================================


def test_knapsack_roundtrip():
    w = [2, 5, 11, 23, 47, 95, 191, 383]
    assert is_superincreasing(w)
    q = 800
    r = 17
    mh = MerkleHellman(w, q, r)

    bits = [1, 0, 1, 1, 0, 1, 0, 0]
    ct = mh.encrypt(bits)
    dec = mh.decrypt(ct)
    assert dec == bits


# =============================================================================
# Length Extension Attack Tests
# =============================================================================


def test_sha1_length_extension():
    secret = b"SECRET_KEY_123"
    data = b"action=view"
    full_orig = secret + data
    orig_hash = hashlib.sha1(full_orig).hexdigest()

    append = b"&admin=true"
    forged_hash, payload = sha1_extend(orig_hash, len(full_orig), append)
    expected_hash = hashlib.sha1(full_orig + payload).hexdigest()
    assert forged_hash == expected_hash


def test_sha256_length_extension():
    secret = b"LONG_SECRET_KEY_FOR_TESTING"
    data = b"user=bob"
    full_orig = secret + data
    orig_hash = hashlib.sha256(full_orig).hexdigest()

    append = b"&privilege=root"
    forged_hash, payload = sha256_extend(orig_hash, len(full_orig), append)
    expected_hash = hashlib.sha256(full_orig + payload).hexdigest()
    assert forged_hash == expected_hash


# =============================================================================
# Discrete Logarithm Tests
# =============================================================================


def test_discrete_log_pohlig_hellman():
    p = 2311  # p - 1 = 2 * 3 * 5 * 7 * 11 (smooth)
    g = 3
    secret_x = 987
    h = pow(g, secret_x, p)

    rec_bsgs = baby_step_giant_step(g, h, p, order=p - 1)
    assert rec_bsgs == secret_x

    rec_ph = pohlig_hellman(g, h, p, order=p - 1)
    assert rec_ph == secret_x


# =============================================================================
# JWT Tests
# =============================================================================


def test_jwt_encode_verify_and_attacks():
    secret = "jwt_test_secret_123"
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"user": "charlie", "admin": False}

    token = jwt_encode(header, payload, key=secret)
    h, p, _ = jwt_decode(token, verify=True, key=secret)
    assert p["user"] == "charlie"

    # Attack none
    none_tok = jwt_attack_none(token, {"admin": True})
    h2, p2, _ = jwt_decode(none_tok, verify=True)
    assert p2["admin"] is True

    # Brute force
    found = jwt_brute_force_hmac(token, ["wrong", "jwt_test_secret_123", "admin"])
    assert found == secret


# =============================================================================
# PQC Tests
# =============================================================================


def test_pqc_lattice_babai():
    basis = [[2.0, 0.0], [0.0, 2.0]]
    target = [3.1, 1.9]
    closest = babai_nearest_plane(basis, target)
    assert closest == [4.0, 2.0]


def test_pqc_ntru_encrypt_decrypt():
    import random

    random.seed(42)
    ntru = NTRUEncrypt(n=7, p=3, q=31)
    pub, priv = ntru.generate_keypair()
    msg = [1, -1, 0, 1, 0, -1, 0]
    ct = ntru.encrypt(msg, pub)
    pt = ntru.decrypt(ct, priv)
    assert pt == msg


def test_pqc_kyber_encrypt_decrypt():
    kyber = EducationalKyber(n=8, k=2, q=3329)
    pub, sec = kyber.keygen()
    msg_bits = [1, 1, 0, 1, 0, 0, 1, 0]
    u, v = kyber.encrypt(msg_bits, pub)
    dec_bits = kyber.decrypt((u, v), sec)
    assert dec_bits == msg_bits


def test_pqc_dilithium_sign_verify():
    dil = EducationalDilithium(n=8, k=2, l=2, q=8380417)
    pub, sec = dil.keygen()
    msg = b"PQC_DILITHIUM_TEST_PAYLOAD"
    sig = dil.sign(msg, pub, sec)
    assert dil.verify(msg, sig, pub)
    assert not dil.verify(b"TAMPERED_PAYLOAD", sig, pub)


def test_pqc_hardness_estimator():
    est = estimate_lwe_hardness(n=20, q=256, sigma=3.2)
    assert "root_hermite_factor_delta" in est
    assert est["is_vulnerable_ctf"] is True
