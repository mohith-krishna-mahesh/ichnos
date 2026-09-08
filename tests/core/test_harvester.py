"""Unit tests for CTFHarvester AST and regex extraction."""

from ichnos.core.harvester import CTFHarvester


def test_harvester_python_ast():
    code = """
from Crypto.Util.number import bytes_to_long

n = 0xabcdef1234567890abcdef1234567890abcdef1234567890
e = 65537
c = bytes_to_long(b"hello")
p, q = 10007, 10009
flag = "FLAG{ast_harvest_success}"
"""
    params = CTFHarvester.harvest_text(code, source_name="chall.py")

    assert len(params.moduli) >= 1
    assert params.moduli[0][0] == "n"
    assert params.moduli[0][1] == 0xABCDEF1234567890ABCDEF1234567890ABCDEF1234567890

    assert 65537 in params.get_exponents()
    assert len(params.ciphertexts) >= 1
    assert "FLAG{ast_harvest_success}" in params.flags
    assert len(params.primes) == 2


def test_harvester_text_regex():
    log_text = """
N1 = 990732808080808080808080808080808080808080808080808080808080808080
c1 = 814908989898989898989898989898989898989898989898989898989898989898
e: 65537
flag: NSS{regex_harvest_success}
"""
    params = CTFHarvester.harvest_text(log_text, source_name="output.txt")

    assert len(params.moduli) == 1
    assert len(params.ciphertexts) == 1
    assert params.exponents[0][1] == 65537
    assert "NSS{regex_harvest_success}" in params.flags


def test_harvester_json_log():
    json_line = (
        '{"modulus": 1234567890123456789012345678901234567890, "ciphertext": 987654321, "e": 3}'
    )
    params = CTFHarvester.harvest_text(json_line, source_name="log.json")

    assert len(params.moduli) == 1
    assert len(params.ciphertexts) == 1
    assert 3 in params.get_exponents()


def test_harvester_multi_language_source_code():
    # 1. Lua
    lua_code = 'local N = 1234567890123456789012345678901234567890\nflag = "FLAG{lua_flag}"\n'
    p_lua = CTFHarvester.harvest_text(lua_code, source_name="chall.lua")
    assert len(p_lua.moduli) == 1
    assert "FLAG{lua_flag}" in p_lua.flags

    # 2. PHP
    php_code = '<?php\n$N = 9876543210987654321098765432109876543210;\n$ct = 0xabcdef;\n$flag = "FLAG{php_flag}";\n'
    p_php = CTFHarvester.harvest_text(php_code, source_name="chall.php")
    assert len(p_php.moduli) == 1
    assert len(p_php.ciphertexts) == 1
    assert "FLAG{php_flag}" in p_php.flags

    # 3. TypeScript / JavaScript
    ts_code = 'const modulus: bigint = 1122334455667788990011223344556677889900n;\nlet c = 0x1234n;\nconst flag: string = "FLAG{ts_flag}";\n'
    p_ts = CTFHarvester.harvest_text(ts_code, source_name="chall.ts")
    assert len(p_ts.moduli) == 1
    assert len(p_ts.ciphertexts) == 1
    assert "FLAG{ts_flag}" in p_ts.flags

    # 4. Go & Rust
    go_code = "N := 9988776655443322110099887766554433221100\nconst c = 0x5678\n"
    p_go = CTFHarvester.harvest_text(go_code, source_name="chall.go")
    assert len(p_go.moduli) == 1
    assert len(p_go.ciphertexts) == 1

    rust_code = "let n: u128 = 4455667788990011223344556677889900112233;\nlet mut ct = 123456;\n"
    p_rust = CTFHarvester.harvest_text(rust_code, source_name="chall.rs")
    assert len(p_rust.moduli) == 1
    assert len(p_rust.ciphertexts) == 1
