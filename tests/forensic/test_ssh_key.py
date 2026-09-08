"""Unit tests for OpenSSH public key parsing and XOR cryptanalysis."""

import base64
import struct

import pytest

from ichnos.forensic.ssh_key import (
    _take_string,
    build_keystream,
    extract_blobs,
    extract_key_body,
    inspect_and_reveal_ssh,
    reveal_hidden_data,
)


def make_ssh_ed25519_blob(key_bytes: bytes) -> bytes:
    tag = b"ssh-ed25519"
    return (
        struct.pack(">I", len(tag))
        + tag
        + struct.pack(">I", len(key_bytes))
        + key_bytes
    )


def test_take_string():
    buf = struct.pack(">I", 5) + b"hello" + b"extra"
    s, nxt = _take_string(buf, 0)
    assert s == b"hello"
    assert nxt == 9

    with pytest.raises(ValueError, match="truncated"):
        _take_string(b"\x00\x00\x00\x10short", 0)


def test_extract_blobs():
    raw_key = b"A" * 32
    blob = make_ssh_ed25519_blob(raw_key)
    b64 = base64.b64encode(blob).decode("ascii")

    # Format 1: standard id_ed25519.pub
    pub_text = f"ssh-ed25519 {b64} test@host\n"
    blobs = extract_blobs(pub_text, "ssh-ed25519")
    assert len(blobs) == 1
    assert blobs[0] == blob

    # Format 2: known_hosts entry
    known_hosts = f"192.168.1.50 ssh-ed25519 {b64}\n"
    blobs2 = extract_blobs(known_hosts, "ssh-ed25519")
    assert len(blobs2) == 1
    assert blobs2[0] == blob


def test_extract_key_body():
    raw_key = b"B" * 32
    blob = make_ssh_ed25519_blob(raw_key)
    body = extract_key_body(blob, "ssh-ed25519", expected_len=32)
    assert body == raw_key

    # Type mismatch error
    with pytest.raises(ValueError, match="expected ecdsa"):
        extract_key_body(blob, "ecdsa-sha2-nistp256")

    # Length mismatch error
    with pytest.raises(ValueError, match="expected 64-byte"):
        extract_key_body(blob, "ssh-ed25519", expected_len=64)


def test_keystream_and_reveal():
    # Keystream construction
    ks = build_keystream(4, xor_bytes=b"\x01\x02")
    assert ks == b"\x01\x02\x01\x02"

    ks_kw = build_keystream(3, keyword=b"KEY")
    assert ks_kw == b"KEY"

    ks_lin = build_keystream(4, linear=(3, 1))
    # i=0: 1, i=1: 4, i=2: 7, i=3: 10
    assert list(ks_lin) == [1, 4, 7, 10]

    # Reveal hidden data
    # Plaintext: b"FLAG\x00padding"
    secret = b"FLAG\x00padding"
    stream = bytes(range(len(secret)))
    key_with_hidden = bytes(s ^ k for s, k in zip(secret, stream))
    revealed = reveal_hidden_data(key_with_hidden, stream)
    assert revealed == b"FLAG"


def test_inspect_and_reveal_ssh_e2e():
    # Hide flag b"FLAG{ssh_revealed}\x00" XORed with keyword "MYSECRET"
    flag = b"FLAG{ssh_revealed}\x00" + b"\x00" * 13
    kw = "MYSECRET"
    kw_bytes = kw.encode()
    ks = bytes(kw_bytes[i % len(kw_bytes)] for i in range(32))
    key_body = bytes(f ^ k for f, k in zip(flag, ks))

    blob = make_ssh_ed25519_blob(key_body)
    b64 = base64.b64encode(blob).decode("ascii")
    line = f"ssh-ed25519 {b64} admin@ctf"

    res = inspect_and_reveal_ssh(line, key_type="ssh-ed25519", keyword=kw)
    assert res["blobs_count"] == 1
    assert len(res["keys"]) == 1
    assert res["keys"][0]["revealed_text"] == "FLAG{ssh_revealed}"

    # Error case: empty input
    res_empty = inspect_and_reveal_ssh("invalid text", key_type="ssh-ed25519")
    assert "error" in res_empty
