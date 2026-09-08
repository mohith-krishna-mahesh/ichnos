import hashlib

from ichnos.password.crack import crack_hash
from ichnos.password.mutator import mutate_word
from ichnos.password.wordlist import combine_lists, deduplicate, filter_wordlist


def test_mutator():
    mutations = mutate_word("cat", include_leet=True, include_casing=True, include_affixes=True)
    # Check casing
    assert "CAT" in mutations
    assert "Cat" in mutations
    # Check leet
    assert "c@t" in mutations or "c4t" in mutations
    # Check suffixes
    assert "cat123" in mutations
    assert "cat!" in mutations
    # Check reverse & duplicate
    assert "tac" in mutations
    assert "catcat" in mutations


def test_wordlist_tools():
    # Deduplicate
    raw = ["admin", "root", "admin", "test", "root"]
    assert deduplicate(raw) == ["admin", "root", "test"]

    # Combine lists
    w = ["admin", "root"]
    s = ["123", "!"]
    combined = combine_lists([w, s])
    assert "admin123" in combined
    assert "root!" in combined

    # Filter wordlist
    candidates = ["short", "verylongpassword123!", "no_digits!"]
    filtered = filter_wordlist(
        candidates, min_length=6, must_contain_digit=True, must_contain_special=True
    )
    assert filtered == ["verylongpassword123!"]


def test_crack_hashes():
    # MD5 test
    md5_target = hashlib.md5(b"secretflag").hexdigest()
    assert crack_hash(md5_target, ["admin", "secretflag", "test"], algorithm="md5") == "secretflag"

    # SHA256 test
    sha256_target = hashlib.sha256(b"cyber").hexdigest()
    assert crack_hash(sha256_target, ["apple", "banana", "cyber"], algorithm="sha256") == "cyber"

    # NTLM test
    # NTLM of "password" is 8846f7eaee8fb117ad06bdd830b7586c
    ntlm_target = "8846f7eaee8fb117ad06bdd830b7586c"
    assert crack_hash(ntlm_target, ["qwerty", "password"], algorithm="ntlm") == "password"

    # Rule-mutated crack: hash of "Password123" cracked from base word "password"
    mutated_target = hashlib.sha256(b"Password123").hexdigest()
    assert (
        crack_hash(mutated_target, ["password"], algorithm="sha256", apply_rules=True)
        == "Password123"
    )
