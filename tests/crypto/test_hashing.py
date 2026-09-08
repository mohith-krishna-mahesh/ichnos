import hashlib

from ichnos.crypto.hashing.compute import compute_all, compute_hash
from ichnos.crypto.hashing.identify import identify_hash


def test_identify_md5():
    hash_str = "5d41402abc4b2a76b9719d911017c592"
    findings = identify_hash(hash_str)
    labels = [f.label for f in findings]
    assert "MD5" in labels


def test_identify_sha256():
    hash_str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    findings = identify_hash(hash_str)
    labels = [f.label for f in findings]
    assert "SHA-256" in labels


def test_identify_bcrypt():
    hash_str = "$2b$12$Gz6Y7J..././..."
    findings = identify_hash(hash_str)
    labels = [f.label for f in findings]
    assert "bcrypt" in labels


def test_compute_md5():
    data = b"hello"
    expected = hashlib.md5(data).hexdigest()
    assert compute_hash(data, "md5") == expected


def test_compute_sha256():
    data = b"hello"
    expected = hashlib.sha256(data).hexdigest()
    assert compute_hash(data, "sha256") == expected


def test_compute_all():
    data = b"hello"
    results = compute_all(data)
    assert "md5" in results
    assert "sha1" in results
    assert "sha256" in results
    assert "sha512" in results
    assert results["md5"] == hashlib.md5(data).hexdigest()
