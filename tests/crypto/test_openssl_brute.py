import subprocess

import pytest

from ichnos.crypto.symmetric.openssl_brute import crack_openssl_params, looks_interesting


@pytest.fixture
def openssl_ciphertext(tmp_path):
    target = tmp_path / "secret.enc"
    plaintext = b"flag{openssl_cracked_success}\n"
    cmd = [
        "openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "1000",
        "-md", "sha256", "-pass", "pass:secret123"
    ]
    proc = subprocess.run(cmd, input=plaintext, capture_output=True)
    if proc.returncode != 0:
        pytest.skip("OpenSSL enc command unavailable or failed")
    target.write_bytes(proc.stdout)
    return target

def test_openssl_crack_params(openssl_ciphertext):
    results = crack_openssl_params(
        data_or_path=openssl_ciphertext,
        passwords=["wrongpass", "admin", "secret123"],
        ciphers=["aes-256-cbc"],
        digests=["sha256"],
        iterations=[1000],
        skip_legacy=True,
    )
    assert len(results) > 0
    top = results[0]
    assert top.password == "secret123"
    assert top.cipher == "aes-256-cbc"
    assert top.digest == "sha256"
    assert b"flag{openssl_cracked_success}" in top.plaintext

def test_looks_interesting():
    assert looks_interesting(b"some random CTF{found_flag} text", [b"CTF{"]) == b"CTF{"
    assert looks_interesting(b"no markers here", [b"CTF{", b"flag{"]) is None
