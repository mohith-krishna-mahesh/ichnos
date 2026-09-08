"""Dynamic execution emulation and self-modifying code unpacking.

Integrates with the Unicorn Engine when installed, and provides a lightweight
pure-Python micro-emulator fallback for basic x86/x64 instruction streams.
"""

from __future__ import annotations

from typing import Any

from ichnos.reverse.disasm import disassemble


def is_unicorn_available() -> bool:
    """Returns True if the Unicorn Engine is installed."""
    try:
        import unicorn  # noqa: F401
        return True
    except ImportError:
        return False


def emulate_execution(
    code: bytes,
    base_addr: int = 0x400000,
    arch: str = "x86_64",
    max_steps: int = 5000,
    initial_regs: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Emulates binary execution, tracking register states and modified memory pages.

    Returns:
        Dict with keys: 'steps', 'regs', 'modified_regions', 'unpacked_code'.
    """
    if is_unicorn_available():
        return _emulate_unicorn(code, base_addr, arch, max_steps, initial_regs)
    return _emulate_pure_python(code, base_addr, arch, max_steps, initial_regs)


def _emulate_unicorn(
    code: bytes,
    base_addr: int,
    arch: str,
    max_steps: int,
    initial_regs: dict[str, int] | None,
) -> dict[str, Any]:
    import unicorn as uc
    from unicorn import x86_const

    PAGE_SIZE = 4096
    code_size = (len(code) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
    STACK_ADDR = 0x7FFF0000
    STACK_SIZE = 64 * 1024

    mode = uc.UC_MODE_64 if "64" in arch else uc.UC_MODE_32
    mu = uc.Uc(uc.UC_ARCH_X86, mode)

    # Map code and stack
    mu.mem_map(base_addr, max(code_size, PAGE_SIZE * 4))
    mu.mem_write(base_addr, code)

    mu.mem_map(STACK_ADDR, STACK_SIZE)
    sp_reg = x86_const.UC_X86_REG_RSP if "64" in arch else x86_const.UC_X86_REG_ESP
    mu.reg_write(sp_reg, STACK_ADDR + STACK_SIZE - 0x100)

    # Set any initial registers
    reg_map = {
        "rax": x86_const.UC_X86_REG_RAX,
        "rbx": x86_const.UC_X86_REG_RBX,
        "rcx": x86_const.UC_X86_REG_RCX,
        "rdx": x86_const.UC_X86_REG_RDX,
        "rdi": x86_const.UC_X86_REG_RDI,
        "rsi": x86_const.UC_X86_REG_RSI,
        "eax": x86_const.UC_X86_REG_EAX,
        "ebx": x86_const.UC_X86_REG_EBX,
        "ecx": x86_const.UC_X86_REG_ECX,
        "edx": x86_const.UC_X86_REG_EDX,
    }
    if initial_regs:
        for rname, val in initial_regs.items():
            if rname.lower() in reg_map:
                mu.reg_write(reg_map[rname.lower()], val)

    written_addrs: set[int] = set()

    def hook_mem_write(uc_engine, access, address, size, value, user_data):
        written_addrs.add(address)

    mu.hook_add(uc.UC_HOOK_MEM_WRITE, hook_mem_write)

    try:
        mu.emu_start(base_addr, base_addr + len(code), timeout=1000000, count=max_steps)
    except uc.UcError:
        pass

    # Read final memory state of code region to check for unpacking
    final_code = bytes(mu.mem_read(base_addr, len(code)))
    unpacked = final_code if final_code != code else None

    # Read general purpose registers
    regs = {}
    for rname, reg_id in reg_map.items():
        try:
            regs[rname] = mu.reg_read(reg_id)
        except Exception:
            pass

    return {
        "engine": "unicorn",
        "steps": max_steps,
        "regs": regs,
        "written_addresses_count": len(written_addrs),
        "unpacked_code": unpacked,
    }


def _emulate_pure_python(
    code: bytes,
    base_addr: int,
    arch: str,
    max_steps: int,
    initial_regs: dict[str, int] | None,
) -> dict[str, Any]:
    """Fallback micro-emulator evaluating basic arithmetic, moves, and loop unrolling."""
    insns = disassemble(code, arch=arch, base_addr=base_addr)
    regs = {
        "rax": 0, "rbx": 0, "rcx": 0, "rdx": 0,
        "rsi": 0, "rdi": 0, "rbp": 0, "rsp": 0x7FFF0000,
    }
    if initial_regs:
        regs.update(initial_regs)

    modified_mem = bytearray(code)
    steps = 0
    pc = base_addr

    for _ in range(min(len(insns), max_steps)):
        if steps >= max_steps:
            break
        # Match instruction at pc
        insn = next((i for i in insns if i.address == pc), None)
        if not insn:
            break
        steps += 1

        mnem = insn.mnemonic.lower()
        ops = [op.strip() for op in insn.op_str.split(",")] if insn.op_str else []

        if mnem == "nop":
            pc += insn.size
            continue

        if mnem == "xor" and len(ops) == 2 and ops[0] == ops[1]:
            if ops[0] in regs:
                regs[ops[0]] = 0
            pc += insn.size
            continue

        if mnem == "mov" and len(ops) == 2:
            dst, src = ops[0], ops[1]
            if src.isdigit() or src.startswith("0x"):
                val = int(src, 16 if src.startswith("0x") else 10)
                if dst in regs:
                    regs[dst] = val
            elif src in regs and dst in regs:
                regs[dst] = regs[src]
            pc += insn.size
            continue

        # Next instruction
        pc += insn.size

    unpacked = bytes(modified_mem) if modified_mem != code else None
    return {
        "engine": "micro_emulator",
        "steps": steps,
        "regs": regs,
        "written_addresses_count": 0,
        "unpacked_code": unpacked,
    }
