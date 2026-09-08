"""Tests for advanced reverse engineering and binary analysis modules.

Covers:
- Non-cryptographic hash identification (FNV, djb2, sdbm, Murmur3)
- ROP/JOP gadget scanning and classification
- Dynamic execution emulation (Unicorn & pure-Python micro-emulator)
- Format string vulnerability pattern scanning
- Control Flow Flattening (CFF) / OLLVM dispatcher detection
"""

from ichnos.binary.hash_id import (
    djb2,
    fnv1a_32,
    fnv1a_64,
    identify_noncrypto_hash,
    murmur3_32,
    sdbm,
)
from ichnos.reverse.cff import detect_control_flow_flattening
from ichnos.reverse.emulate import emulate_execution, is_unicorn_available
from ichnos.reverse.gadgets import scan_gadgets
from ichnos.reverse.patterns import scan_format_string_vulns


def test_noncrypto_hash_identification():
    # Test FNV1a-32
    target = b"VirtualAlloc"
    h_fnv = fnv1a_32(target)
    matches = identify_noncrypto_hash(h_fnv, wordlist=["VirtualAlloc", "CreateFileA"])
    assert any(m["algorithm"] == "fnv1a_32" and m["preimage"] == "VirtualAlloc" for m in matches)

    # Test djb2
    h_djb = djb2(target)
    matches_djb = identify_noncrypto_hash(h_djb, wordlist=["VirtualAlloc"])
    assert any(m["algorithm"] == "djb2" and m["preimage"] == "VirtualAlloc" for m in matches_djb)

    # Test Murmur3
    h_mur = murmur3_32(target)
    matches_mur = identify_noncrypto_hash(h_mur, wordlist=["VirtualAlloc"])
    assert any(m["algorithm"] == "murmur3_32" for m in matches_mur)

    # Test sdbm and 64-bit
    assert sdbm(b"test") != 0
    assert fnv1a_64(b"test") != 0


def test_gadget_scanner():
    # Construct synthetic code containing classic gadgets:
    # 5f c3 -> pop rdi; ret
    # 31 c0 c3 -> xor eax, eax; ret
    # 0f 05 -> syscall
    code = b"\x90\x90\x5f\xc3\x31\xc0\xc3\x0f\x05\xc3"
    gadgets = scan_gadgets(code, base_addr=0x400000, arch="x86_64", max_len=4)
    assert len(gadgets) >= 2

    # Check categories
    categories = [g["category"] for g in gadgets]
    assert "load_reg" in categories or "arithmetic" in categories or "syscall" in categories


def test_emulate_execution():
    # Simple NOP sled or mov
    code = b"\x90\x90\x90\xc3"
    res = emulate_execution(code, base_addr=0x400000, arch="x86_64", max_steps=10)
    assert "steps" in res
    assert "regs" in res
    assert isinstance(is_unicorn_available(), bool)


def test_format_string_vuln_scanner():
    # Synthetic code: call to a symbol identified as printf
    # e8 05 00 00 00 -> call relative +5
    code = b"\x48\x89\xc7\xe8\x05\x00\x00\x00\xc3"
    symbol_table = {0x400000 + 3 + 5 + 5: "printf"}  # call target
    vulns = scan_format_string_vulns(code, base_addr=0x400000, symbol_table=symbol_table)
    assert isinstance(vulns, list)


def test_cff_detection_linear():
    # Linear instructions without dispatcher loop
    code = b"\x48\x31\xc0\x48\xff\xc0\xc3"
    res = detect_control_flow_flattening(code, base_addr=0x400000, arch="x86_64")
    assert res["flattened"] is False
    assert res["dispatcher_addr"] is None
