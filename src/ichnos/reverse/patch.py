"""Binary patching and pattern scanning engine.

Supports IDA-style wildcard byte signature scanning, byte sequence replacement,
NOP filling across architectures, and binary file patching.
"""

from __future__ import annotations

import pathlib


def find_pattern(data: bytes, pattern: bytes, mask: str | None = None) -> list[int]:
    """Scans for byte patterns with optional wildcard mask (e.g. 'xxx?xx').

    If mask is None, performs exact substring matching.
    """
    matches: list[int] = []
    p_len = len(pattern)
    d_len = len(data)

    if p_len == 0 or p_len > d_len:
        return matches

    if mask is None or "?" not in mask:
        # Fast exact substring search
        start = 0
        while True:
            pos = data.find(pattern, start)
            if pos == -1:
                break
            matches.append(pos)
            start = pos + 1
        return matches

    # Mask-based scan
    for i in range(d_len - p_len + 1):
        matched = True
        for j in range(p_len):
            if j < len(mask) and mask[j] == "?":
                continue
            if data[i + j] != pattern[j]:
                matched = False
                break
        if matched:
            matches.append(i)

    return matches


def patch_bytes(data: bytes, offset: int, replacement: bytes) -> bytes:
    """Replaces bytes at the given offset with replacement bytes."""
    if offset < 0 or offset + len(replacement) > len(data):
        raise ValueError("Patch offset exceeds binary buffer bounds")
    ba = bytearray(data)
    ba[offset : offset + len(replacement)] = replacement
    return bytes(ba)


def nop_region(data: bytes, offset: int, length: int, arch: str = "x86") -> bytes:
    """Fills a region with architecture-specific NOP instructions.

    - x86 / x64: 0x90
    - ARM32: 0x00 0x00 0xA0 0xE1 (mov r0, r0)
    - ARM64: 0x1F 0x20 0x03 0xD5 (nop)
    """
    arch_lower = arch.lower()
    if "arm64" in arch_lower or "aarch64" in arch_lower:
        nop_insn = b"\x1f\x20\x03\xd5"
    elif "arm" in arch_lower:
        nop_insn = b"\x00\x00\xa0\xe1"
    else:
        nop_insn = b"\x90"

    # Repeat NOP instructions to cover length
    repeats = (length + len(nop_insn) - 1) // len(nop_insn)
    nop_stream = (nop_insn * repeats)[:length]

    return patch_bytes(data, offset, nop_stream)


def patch_file(in_path: str, out_path: str, offset: int, replacement: bytes) -> None:
    """Reads in_path, applies patch at offset, and writes to out_path."""
    src = pathlib.Path(in_path).read_bytes()
    patched = patch_bytes(src, offset, replacement)
    pathlib.Path(out_path).write_bytes(patched)


def is_keystone_available() -> bool:
    """Returns True if the Keystone assembly engine is installed."""
    try:
        import keystone  # noqa: F401

        return True
    except ImportError:
        return False


def _assemble_pure_python(mnemonic: str, arch: str) -> bytes:
    """Pure-Python fallback assembler for common patching primitives."""
    import struct

    m = mnemonic.strip().lower()
    if ";" in m:
        m = m.split(";")[0].strip()
    if not m:
        return b""

    arch_lower = arch.lower()
    is_arm = "arm" in arch_lower and "64" not in arch_lower
    is_arm64 = "arm64" in arch_lower or "aarch64" in arch_lower

    if is_arm64:
        if m == "nop":
            return b"\x1f\x20\x03\xd5"
        if m == "ret":
            return b"\xc0\x03\x5f\xd6"
    elif is_arm:
        if m == "nop":
            return b"\x00\x00\xa0\xe1"
        if m == "bx lr":
            return b"\x1e\xff\x2f\xe1"
    else:
        # x86 / x64
        if m == "nop":
            return b"\x90"
        if m == "ret":
            return b"\xc3"
        if m in ("retn", "retf"):
            return b"\xcb"
        if m == "int3":
            return b"\xcc"
        if m == "syscall":
            return b"\x0f\x05"
        if m == "sysenter":
            return b"\x0f\x34"
        if m in ("xor eax, eax", "xor eax,eax"):
            return b"\x31\xc0"
        if m in ("xor rax, rax", "xor rax,rax"):
            return b"\x48\x31\xc0"
        if m in ("xor ebx, ebx", "xor ebx,ebx"):
            return b"\x31\xdb"
        if m in ("xor rbx, rbx", "xor rbx,rbx"):
            return b"\x48\x31\xdb"
        if m in ("xor ecx, ecx", "xor ecx,ecx"):
            return b"\x31\xc9"
        if m in ("xor edx, edx", "xor edx,edx"):
            return b"\x31\xd2"
        if m in ("push eax", "push rax"):
            return b"\x50"
        if m in ("push ecx", "push rcx"):
            return b"\x51"
        if m in ("push edx", "push rdx"):
            return b"\x52"
        if m in ("push ebx", "push rbx"):
            return b"\x53"
        if m in ("pop eax", "pop rax"):
            return b"\x58"
        if m in ("pop ecx", "pop rcx"):
            return b"\x59"
        if m in ("pop edx", "pop rdx"):
            return b"\x5a"
        if m in ("pop ebx", "pop rbx"):
            return b"\x5b"
        if m.startswith("jmp "):
            target_str = m[4:].replace("short", "").replace("+", "").strip()
            try:
                rel = int(target_str, 0)
                if -128 <= rel <= 127:
                    return b"\xeb" + struct.pack("b", rel)
                return b"\xe9" + struct.pack("<i", rel)
            except ValueError:
                pass
        if m.startswith("call "):
            target_str = m[5:].replace("+", "").strip()
            try:
                rel = int(target_str, 0)
                return b"\xe8" + struct.pack("<i", rel)
            except ValueError:
                pass

    raise ValueError(
        f"Pure-Python assembler does not support instruction '{mnemonic}' for architecture '{arch}'. "
        "Install keystone-engine for full mnemonic assembly."
    )


def assemble(mnemonics: str, arch: str = "x86") -> bytes:
    """Assembles mnemonics into machine code bytes via Keystone with pure-Python fallback."""
    if is_keystone_available():
        import keystone as ks

        arch_map = {
            "x86": (ks.KS_ARCH_X86, ks.KS_MODE_32),
            "x86_64": (ks.KS_ARCH_X86, ks.KS_MODE_64),
            "x64": (ks.KS_ARCH_X86, ks.KS_MODE_64),
            "arm": (ks.KS_ARCH_ARM, ks.KS_MODE_ARM),
            "arm64": (ks.KS_ARCH_ARM64, ks.KS_MODE_ARM),
            "mips": (ks.KS_ARCH_MIPS, ks.KS_MODE_MIPS32),
        }
        ks_arch, ks_mode = arch_map.get(arch.lower(), (ks.KS_ARCH_X86, ks.KS_MODE_64))
        engine = ks.Ks(ks_arch, ks_mode)
        encoding, _ = engine.asm(mnemonics)
        return bytes(encoding)

    # Fallback to pure-Python
    lines = [line.strip() for line in mnemonics.replace(";", "\n").splitlines() if line.strip()]
    assembled = bytearray()
    for line in lines:
        assembled.extend(_assemble_pure_python(line, arch))
    return bytes(assembled)


def patch_at_offset(binary_path: str, offset: int, assembled_bytes: bytes) -> None:
    """Applies assembled bytes directly at the specified offset of a binary file in place."""
    p = pathlib.Path(binary_path)
    data = p.read_bytes()
    patched = patch_bytes(data, offset, assembled_bytes)
    p.write_bytes(patched)
