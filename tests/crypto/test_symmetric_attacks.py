"""Tests for symmetric cryptanalysis attack suites (ECB, CBC, Stream, GCM)."""

from __future__ import annotations

from ichnos.crypto.symmetric.aes import decrypt_cbc, encrypt_cbc, encrypt_ecb
from ichnos.crypto.symmetric.attacks.cbc import cbc_bit_flip, cbc_padding_oracle
from ichnos.crypto.symmetric.attacks.ecb import (
    count_duplicate_blocks,
    crack_ecb_byte_at_a_time,
    detect_ecb,
    ecb_cut_and_paste,
)
from ichnos.crypto.symmetric.attacks.gcm import (
    gf128_inv,
    gf128_mul,
)
from ichnos.crypto.symmetric.attacks.stream import crib_drag_stream


def test_detect_ecb():
    key = b"0123456789abcdef"
    pt_repeating = b"A" * 64
    ct_ecb = encrypt_ecb(key, pt_repeating)
    assert detect_ecb(ct_ecb) is True
    assert count_duplicate_blocks(ct_ecb) >= 2


def test_ecb_cut_and_paste():
    blocks = [b"B000000000000000", b"B111111111111111", b"B222222222222222"]
    reordered = ecb_cut_and_paste(blocks, [2, 0, 1])
    assert reordered == blocks[2] + blocks[0] + blocks[1]


def test_crack_ecb_byte_at_a_time():
    secret = b"FLAG{byte_at_a_time}"
    key = b"supersecretkey12"

    def oracle(prefix: bytes) -> bytes:
        data = prefix + secret
        # Pad to 16 bytes
        pad_len = 16 - (len(data) % 16)
        padded = data + bytes([pad_len] * pad_len)
        return encrypt_ecb(key, padded)

    recovered = crack_ecb_byte_at_a_time(oracle, block_size=16, max_len=len(secret))
    assert recovered == secret


def test_cbc_bit_flip():
    # 2 blocks
    ct = b"A" * 32
    # Flip byte at offset 5 of block 1
    modified = cbc_bit_flip(ct, block_index=1, byte_offset=5, original_val=ord("0"), target_val=ord("1"))
    assert modified != ct
    assert modified[5] == ct[5] ^ (ord("0") ^ ord("1"))


def test_cbc_padding_oracle():
    key = b"1234567890abcdef"
    iv = b"abcdef1234567890"
    plaintext = b"SecretToken12345"

    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    ct = encrypt_cbc(key, iv, padded)

    def oracle(test_iv: bytes, test_ct: bytes) -> bool:
        try:
            pt = decrypt_cbc(key, test_iv, test_ct)
            p_len = pt[-1]
            if 1 <= p_len <= 16 and all(b == p_len for b in pt[-p_len:]):
                return True
            return False
        except Exception:
            return False

    decrypted = cbc_padding_oracle(oracle, iv, ct)
    assert decrypted == plaintext


def test_stream_crib_drag():
    p1 = b"THE FLAG IS HERE"
    p2 = b"A SECRET MESSAGE"
    key = b"K" * 16
    c1 = bytes([a ^ b for a, b in zip(p1, key)])
    c2 = bytes([a ^ b for a, b in zip(p2, key)])

    matches = crib_drag_stream(c1, c2, b"FLAG")
    assert len(matches) > 0
    # At offset 4, 'FLAG' XOR (P1^P2) should produce 'ECRE'
    found_offsets = [off for off, _ in matches]
    assert 4 in found_offsets


def test_gf128_arithmetic():
    a = 0x123456789ABCDEF0123456789ABCDEF0
    inv = gf128_inv(a)
    prod = gf128_mul(a, inv)
    assert prod == 1
