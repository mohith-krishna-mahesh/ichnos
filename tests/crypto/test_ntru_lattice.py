import hashlib

from ichnos.crypto.pqc.ntru_solve import (
    build_negacyclic_matrix,
    solve_ntru_lattice,
    verify_ntru_relation,
)
from ichnos.crypto.symmetric.aes import encrypt_ecb


def test_build_negacyclic_matrix():
    pk = [5, 6, 7]
    H = build_negacyclic_matrix(pk, 3)
    assert len(H) == 3
    assert len(H[0]) == 3
    assert H[0] == [5, 6, 7]
    assert H[1] == [-7, 5, 6]
    assert H[2] == [-6, -7, 5]

def test_verify_ntru_relation():
    n = 4
    q = 17
    # If pk = [2, 0, 0, 0], f = [1, 0, 0, 0], then g = [2, 0, 0, 0]
    pk = [2, 0, 0, 0]
    f = [1, 0, 0, 0]
    g = [2, 0, 0, 0]
    assert verify_ntru_relation(f, g, pk, n, q) is True

def test_solve_ntru_small():
    # Small test case with trivial short vector
    n = 4
    q = 17
    pk = [3, 0, 0, 0]
    # f = [1, 0, 0, 0], g = [3, 0, 0, 0]
    # f * pk = [3, 0, 0, 0] == g (mod 17)

    # Generate ciphertext
    secret_f = [1, 0, 0, 0]
    raw_key = bytes(x % 256 for x in secret_f)
    aes_key = hashlib.sha256(raw_key).digest()
    pt = b"flag{ntru_lll_solved_cleanly}"
    # pad pkcs7 to 32 bytes
    pad_len = 32 - len(pt)
    padded_pt = pt + bytes([pad_len]) * pad_len
    ct = encrypt_ecb(aes_key, padded_pt)

    sol = solve_ntru_lattice(pk, q=q, n=n, ciphertext=ct, bound=3)
    assert sol is not None
    assert sol.plaintext is not None
    assert b"flag{ntru_lll_solved_cleanly}" in sol.plaintext
