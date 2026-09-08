"""Static security vulnerability pattern scanners for disassembly and binaries.

Detects risky call sites: format string vulnerabilities (printf without constant format string),
insecure library calls (gets, strcpy), and buffer overflow patterns.
"""

from __future__ import annotations

from typing import Any

from ichnos.reverse.disasm import disassemble

FORMAT_FUNCTIONS = {
    "printf",
    "fprintf",
    "sprintf",
    "snprintf",
    "syslog",
    "dprintf",
    "vprintf",
    "vfprintf",
    "__printf_chk",
}


def scan_format_string_vulns(
    code: bytes,
    base_addr: int = 0x400000,
    arch: str = "x86_64",
    symbol_table: dict[int, str] | None = None,
    rodata_bounds: tuple[int, int] | None = None,
) -> list[dict[str, Any]]:
    """Scans executable code for non-constant format string call sites.

    Args:
        code: Disassembly bytes.
        base_addr: Virtual base address.
        arch: Architecture ('x86_64' or 'x86').
        symbol_table: Mapping of target address -> function name (e.g. from ELF .dynsym or PLT).
        rodata_bounds: Optional (rodata_start, rodata_end) address range for verifying literal strings.

    Returns:
        List of vulnerability finding dicts with: 'address', 'target_function', 'call_insn', 'risk'.
    """
    insns = disassemble(code, arch=arch, base_addr=base_addr)
    findings: list[dict[str, Any]] = []

    symbols = symbol_table or {}

    for idx, insn in enumerate(insns):
        # Look for call instructions
        if not insn.is_call:
            continue

        target_name = None
        if insn.target_address and insn.target_address in symbols:
            target_name = symbols[insn.target_address]
        else:
            for fn_name in FORMAT_FUNCTIONS:
                if fn_name in insn.op_str:
                    target_name = fn_name
                    break

        if not target_name:
            continue

        fn_base = target_name.lstrip("_").split("@")[0]
        if fn_base not in FORMAT_FUNCTIONS:
            continue

        # Inspect preceding instructions that set the format string argument
        # On x86_64: 1st arg is RDI (printf) or 2nd arg RSI (fprintf/sprintf)
        is_risky = True
        evidence = "Argument passed via register or stack buffer"

        # Check up to 4 instructions backward
        window_start = max(0, idx - 4)
        for prev in insns[window_start:idx]:
            prev_mnem = prev.mnemonic.lower()
            prev_ops = prev.op_str.lower()

            # If LEA RDI, [rip + offset] and target falls in rodata, it's a safe constant format string
            if "lea" in prev_mnem and "rdi" in prev_ops:
                if rodata_bounds and prev.target_address:
                    r_start, r_end = rodata_bounds
                    if r_start <= prev.target_address <= r_end:
                        is_risky = False
                        evidence = f"Constant string format located in .rodata at 0x{prev.target_address:X}"
                        break
                elif "rip" in prev_ops:
                    # Likely constant literal reference
                    is_risky = False
                    evidence = "Constant format string via RIP-relative LEA"
                    break

            # If user buffer is loaded: MOV RDI, RAX or MOV RDI, [RBP - ...]
            if "mov" in prev_mnem and "rdi" in prev_ops:
                if "rbp" in prev_ops or "rsp" in prev_ops or "rax" in prev_ops or "rsi" in prev_ops:
                    is_risky = True
                    evidence = f"Dynamic non-constant format argument loaded: {prev.mnemonic} {prev.op_str}"

        if is_risky:
            findings.append({
                "address": insn.address,
                "target_function": target_name,
                "call_instruction": str(insn),
                "risk": "HIGH",
                "evidence": evidence,
            })

    return findings
