"""Disassembly engine supporting Capstone when available with a pure-Python fallback.

Provides structured Instruction objects, branch/call/return classification,
and target address resolution for Control Flow Graph generation.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass
class Instruction:
    """Represents a disassembled machine instruction."""

    address: int
    mnemonic: str
    op_str: str
    bytes: bytes
    size: int
    is_branch: bool = False
    is_call: bool = False
    is_ret: bool = False
    target_address: int | None = None

    def __str__(self) -> str:
        addr_str = f"0x{self.address:08X}"
        bytes_str = self.bytes.hex().ljust(12)
        return f"{addr_str}:  {bytes_str}  {self.mnemonic.ljust(8)} {self.op_str}".rstrip()


def is_capstone_available() -> bool:
    """Returns True if the Capstone disassembly framework is installed."""
    try:
        import capstone  # noqa: F401

        return True
    except ImportError:
        return False


def _disassemble_capstone(code: bytes, arch: str, base_addr: int) -> list[Instruction]:
    """Disassembles binary code using the Capstone engine."""
    import capstone as cs

    arch_map = {
        "x86": (cs.CS_ARCH_X86, cs.CS_MODE_32),
        "x86_64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
        "x64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
        "arm": (cs.CS_ARCH_ARM, cs.CS_MODE_ARM),
        "arm64": (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM),
        "mips": (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32),
    }

    cs_arch, cs_mode = arch_map.get(arch.lower(), (cs.CS_ARCH_X86, cs.CS_MODE_64))
    md = cs.Cs(cs_arch, cs_mode)
    md.detail = True

    instructions: list[Instruction] = []
    branch_groups = {cs.CS_GRP_JUMP, cs.CS_GRP_CALL, cs.CS_GRP_RET}

    for insn in md.disasm(code, base_addr):
        groups = set(insn.groups)
        is_call = cs.CS_GRP_CALL in groups
        is_ret = cs.CS_GRP_RET in groups
        is_jump = cs.CS_GRP_JUMP in groups
        is_branch = bool(groups & branch_groups)

        target = None
        if (is_jump or is_call) and insn.operands and insn.operands[0].type == cs.CS_OP_IMM:
            target = insn.operands[0].imm

        instructions.append(
            Instruction(
                address=insn.address,
                mnemonic=insn.mnemonic,
                op_str=insn.op_str,
                bytes=bytes(insn.bytes),
                size=insn.size,
                is_branch=is_branch,
                is_call=is_call,
                is_ret=is_ret,
                target_address=target,
            )
        )

    return instructions


def _disassemble_builtin_x86(code: bytes, base_addr: int, is_64: bool = True) -> list[Instruction]:
    """Lightweight pure-Python instruction decoder for common x86/x64 instructions."""
    instructions: list[Instruction] = []
    idx = 0
    size = len(code)

    reg_names_64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]
    reg_names_32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
    regs = reg_names_64 if is_64 else reg_names_32

    while idx < size:
        curr_addr = base_addr + idx
        b = code[idx]

        # REX prefix for x64 (0x48 etc.)
        is_rex_w = False
        if is_64 and 0x48 <= b <= 0x4F:
            is_rex_w = True
            idx += 1
            if idx >= size:
                instructions.append(Instruction(curr_addr, "db", f"0x{b:02x}", bytes([b]), 1))
                break
            b = code[idx]

        # NOP (0x90)
        if b == 0x90:
            instructions.append(Instruction(curr_addr, "nop", "", bytes([b]), 1))
            idx += 1
        # INT3 (0xCC)
        elif b == 0xCC:
            instructions.append(Instruction(curr_addr, "int3", "", bytes([b]), 1))
            idx += 1
        # RET (0xC3)
        elif b == 0xC3:
            instructions.append(
                Instruction(curr_addr, "ret", "", bytes([b]), 1, is_branch=True, is_ret=True)
            )
            idx += 1
        # RET imm16 (0xC2)
        elif b == 0xC2 and idx + 3 <= size:
            imm = struct.unpack("<H", code[idx + 1 : idx + 3])[0]
            insn_bytes = code[idx : idx + 3]
            instructions.append(
                Instruction(
                    curr_addr,
                    "ret",
                    hex(imm),
                    insn_bytes,
                    3,
                    is_branch=True,
                    is_ret=True,
                )
            )
            idx += 3
        # SYSCALL (0x0F 0x05)
        elif b == 0x0F and idx + 2 <= size and code[idx + 1] == 0x05:
            instructions.append(Instruction(curr_addr, "syscall", "", code[idx : idx + 2], 2))
            idx += 2
        # PUSH reg (0x50 .. 0x57)
        elif 0x50 <= b <= 0x57:
            r = regs[b - 0x50]
            instructions.append(Instruction(curr_addr, "push", r, bytes([b]), 1))
            idx += 1
        # POP reg (0x58 .. 0x5F)
        elif 0x58 <= b <= 0x5F:
            r = regs[b - 0x58]
            instructions.append(Instruction(curr_addr, "pop", r, bytes([b]), 1))
            idx += 1
        # CALL rel32 (0xE8)
        elif b == 0xE8 and idx + 5 <= size:
            rel = struct.unpack("<i", code[idx + 1 : idx + 5])[0]
            target = curr_addr + 5 + rel
            instructions.append(
                Instruction(
                    curr_addr,
                    "call",
                    f"0x{target:08X}",
                    code[idx : idx + 5],
                    5,
                    is_branch=True,
                    is_call=True,
                    target_address=target,
                )
            )
            idx += 5
        # JMP rel32 (0xE9)
        elif b == 0xE9 and idx + 5 <= size:
            rel = struct.unpack("<i", code[idx + 1 : idx + 5])[0]
            target = curr_addr + 5 + rel
            instructions.append(
                Instruction(
                    curr_addr,
                    "jmp",
                    f"0x{target:08X}",
                    code[idx : idx + 5],
                    5,
                    is_branch=True,
                    target_address=target,
                )
            )
            idx += 5
        # JMP rel8 (0xEB)
        elif b == 0xEB and idx + 2 <= size:
            rel = struct.unpack("<b", code[idx + 1 : idx + 2])[0]
            target = curr_addr + 2 + rel
            instructions.append(
                Instruction(
                    curr_addr,
                    "jmp",
                    f"0x{target:08X}",
                    code[idx : idx + 2],
                    2,
                    is_branch=True,
                    target_address=target,
                )
            )
            idx += 2
        # JZ/JE rel8 (0x74)
        elif b == 0x74 and idx + 2 <= size:
            rel = struct.unpack("<b", code[idx + 1 : idx + 2])[0]
            target = curr_addr + 2 + rel
            instructions.append(
                Instruction(
                    curr_addr,
                    "jz",
                    f"0x{target:08X}",
                    code[idx : idx + 2],
                    2,
                    is_branch=True,
                    target_address=target,
                )
            )
            idx += 2
        # JNZ/JNE rel8 (0x75)
        elif b == 0x75 and idx + 2 <= size:
            rel = struct.unpack("<b", code[idx + 1 : idx + 2])[0]
            target = curr_addr + 2 + rel
            instructions.append(
                Instruction(
                    curr_addr,
                    "jnz",
                    f"0x{target:08X}",
                    code[idx : idx + 2],
                    2,
                    is_branch=True,
                    target_address=target,
                )
            )
            idx += 2
        # XOR reg, reg (0x31)
        elif b == 0x31 and idx + 2 <= size:
            modrm = code[idx + 1]
            src_reg = regs[(modrm >> 3) & 7]
            dst_reg = regs[modrm & 7]
            prefix_len = 1 if is_rex_w else 0
            instructions.append(
                Instruction(
                    curr_addr,
                    "xor",
                    f"{dst_reg}, {src_reg}",
                    code[idx - prefix_len : idx + 2],
                    2 + prefix_len,
                )
            )
            idx += 2
        # Default: raw byte
        else:
            prefix_len = 1 if is_rex_w else 0
            raw_bytes = code[idx - prefix_len : idx + 1]
            instructions.append(
                Instruction(
                    curr_addr,
                    "db",
                    f"0x{b:02X}",
                    raw_bytes,
                    1 + prefix_len,
                )
            )
            idx += 1

    return instructions


def disassemble(code: bytes, arch: str = "x86_64", base_addr: int = 0x1000) -> list[Instruction]:
    """Disassembles machine code into a list of Instruction objects.

    Uses Capstone if installed; falls back gracefully to the built-in x86 engine.
    """
    if is_capstone_available():
        try:
            return _disassemble_capstone(code, arch=arch, base_addr=base_addr)
        except Exception:
            pass

    # Built-in fallback
    is_64 = "64" in arch.lower()
    return _disassemble_builtin_x86(code, base_addr=base_addr, is_64=is_64)
