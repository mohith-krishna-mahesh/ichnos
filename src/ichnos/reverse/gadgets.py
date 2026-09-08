"""ROP and JOP Gadget Scanner for x86 and x86-64 binaries.

Finds useful instruction sequences ending in ret, syscall, int 0x80, or indirect jumps,
categorizing gadgets for exploit chain synthesis.
"""

from __future__ import annotations

from typing import Any

from ichnos.reverse.disasm import disassemble


def _classify_gadget(mnemonics: list[str]) -> str:
    """Classifies a gadget sequence into functional categories."""
    full_str = " ; ".join(mnemonics)
    if "syscall" in full_str or "int 0x80" in full_str:
        return "syscall"
    if "leave" in full_str or "rsp" in full_str or "esp" in full_str:
        return "stack_pivot"
    if any(m.startswith("pop") for m in mnemonics):
        return "load_reg"
    if any(m.startswith("xor") for m in mnemonics):
        return "arithmetic"
    if "[" in full_str and "mov" in full_str:
        return "memory_access"
    if any(m.startswith("jmp") or m.startswith("call") for m in mnemonics):
        return "jop"
    return "general"


def scan_gadgets(
    code: bytes,
    base_addr: int = 0x400000,
    arch: str = "x86_64",
    max_len: int = 4,
) -> list[dict[str, Any]]:
    """Scans binary code for ROP/JOP gadgets.

    Args:
        code: Executable bytes.
        base_addr: Base virtual address of the code section.
        arch: Architecture ('x86_64' or 'x86').
        max_len: Maximum number of instructions in a gadget.

    Returns:
        List of dicts with: 'address', 'instructions', 'category', 'raw_bytes'.
    """
    terminator_bytes = {
        b"\xc3": "ret",
        b"\xcb": "retf",
        b"\x0f\x05": "syscall",
        b"\xcd\x80": "int 0x80",
    }

    found_gadgets: dict[str, dict[str, Any]] = {}

    # Scan for terminators
    for term_seq, _ in terminator_bytes.items():
        seq_len = len(term_seq)
        pos = 0
        while True:
            idx = code.find(term_seq, pos)
            if idx == -1:
                break
            pos = idx + 1

            # Try disassembling backward up to (max_len * 5) bytes
            for back_offset in range(1, min(max_len * 6, idx + 1)):
                start_idx = idx - back_offset
                gadget_bytes = code[start_idx : idx + seq_len]
                gadget_addr = base_addr + start_idx

                try:
                    insns = disassemble(gadget_bytes, arch=arch, base_addr=gadget_addr)
                except Exception:
                    continue

                if not insns:
                    continue

                # Check if the last instruction ends at the terminator
                last_insn = insns[-1]
                last_end = last_insn.address + last_insn.size
                if last_end != gadget_addr + len(gadget_bytes):
                    continue

                # Must end with ret / syscall / int 0x80
                if not (last_insn.is_ret or "syscall" in last_insn.mnemonic or "int" in last_insn.mnemonic):
                    continue

                # Cap instruction length
                if len(insns) > max_len:
                    continue

                # Discard branches/calls inside the body before the terminator
                body = insns[:-1]
                if any(i.is_branch or i.is_call for i in body):
                    continue

                # Valid gadget!
                insn_strs = [f"{i.mnemonic} {i.op_str}".strip() for i in insns]
                gadget_str = " ; ".join(insn_strs)

                if gadget_str not in found_gadgets:
                    found_gadgets[gadget_str] = {
                        "address": gadget_addr,
                        "instructions": gadget_str,
                        "category": _classify_gadget(insn_strs),
                        "size": len(gadget_bytes),
                        "raw_bytes": gadget_bytes.hex(),
                    }

    # Sort deterministically by address
    results = list(found_gadgets.values())
    results.sort(key=lambda g: g["address"])
    return results
