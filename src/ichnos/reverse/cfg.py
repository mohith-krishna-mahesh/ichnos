"""Control Flow Graph (CFG) generation and basic block partitioning.

Constructs basic blocks, resolves control flow edges (branch targets and fallthroughs),
computes cyclomatic complexity, and renders ASCII control flow graphs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ichnos.reverse.disasm import Instruction


@dataclass
class BasicBlock:
    """Represents a basic block of sequential, non-branching instructions."""

    id: int
    start_addr: int
    end_addr: int
    instructions: list[Instruction] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)  # Target basic block IDs
    predecessors: list[int] = field(default_factory=list)

    def size(self) -> int:
        return sum(insn.size for insn in self.instructions)


def build_cfg(instructions: list[Instruction]) -> list[BasicBlock]:
    """Partitions a list of disassembled instructions into basic blocks and links CFG edges."""
    if not instructions:
        return []

    addr_to_idx = {insn.address: i for i, insn in enumerate(instructions)}

    # Identify leaders (start of basic blocks)
    leaders = {instructions[0].address}

    for insn in instructions:
        if insn.is_branch or insn.is_call or insn.is_ret:
            # Next instruction is a leader (fallthrough)
            next_addr = insn.address + insn.size
            if next_addr in addr_to_idx:
                leaders.add(next_addr)
            # Branch target is a leader
            if insn.target_address and insn.target_address in addr_to_idx:
                leaders.add(insn.target_address)

    # Sort leaders
    sorted_leaders = sorted(leaders)
    blocks: list[BasicBlock] = []
    addr_to_block_id: dict[int, int] = {}

    for b_id, start_addr in enumerate(sorted_leaders):
        start_idx = addr_to_idx[start_addr]
        # End index is before next leader or end of list
        if b_id + 1 < len(sorted_leaders):
            end_addr = sorted_leaders[b_id + 1]
            end_idx = addr_to_idx[end_addr]
        else:
            end_idx = len(instructions)

        block_insns = instructions[start_idx:end_idx]
        last_insn = block_insns[-1]
        block = BasicBlock(
            id=b_id,
            start_addr=start_addr,
            end_addr=last_insn.address + last_insn.size,
            instructions=block_insns,
        )
        blocks.append(block)
        addr_to_block_id[start_addr] = b_id

    # Connect CFG edges (successors and predecessors)
    for block in blocks:
        last_insn = block.instructions[-1]

        if last_insn.is_ret:
            # Returns have no successors in local function CFG
            continue

        target_id = (
            addr_to_block_id.get(last_insn.target_address) if last_insn.target_address else None
        )
        fallthrough_addr = last_insn.address + last_insn.size
        fallthrough_id = addr_to_block_id.get(fallthrough_addr)

        if last_insn.mnemonic == "jmp":
            if target_id is not None:
                block.successors.append(target_id)
        elif last_insn.mnemonic in ("jz", "jnz", "je", "jne", "jg", "jl", "ja", "jb"):
            if target_id is not None:
                block.successors.append(target_id)
            if fallthrough_id is not None:
                block.successors.append(fallthrough_id)
        else:
            if fallthrough_id is not None:
                block.successors.append(fallthrough_id)

    # Populate predecessors
    for block in blocks:
        for succ_id in block.successors:
            if succ_id < len(blocks):
                blocks[succ_id].predecessors.append(block.id)

    return blocks


def cyclomatic_complexity(blocks: list[BasicBlock]) -> int:
    """Calculates McCabe's Cyclomatic Complexity: M = E - N + 2P."""
    n = len(blocks)
    if n == 0:
        return 1
    e = sum(len(b.successors) for b in blocks)
    return max(1, e - n + 2)


def render_ascii_cfg(blocks: list[BasicBlock]) -> str:
    """Renders a readable ASCII flowchart overview of the basic blocks and edges."""
    if not blocks:
        return "Empty CFG"

    lines: list[str] = ["=== Control Flow Graph ==="]

    for b in blocks:
        succ_str = ", ".join(f"Block_{s}" for s in b.successors) or "None (RET/Halt)"
        pred_str = ", ".join(f"Block_{p}" for p in b.predecessors) or "Entry"
        lines.append(f"\n[Block_{b.id}]  0x{b.start_addr:08X} - 0x{b.end_addr:08X}")
        lines.append(f"  Predecessors: {pred_str}")
        for insn in b.instructions:
            lines.append(f"    0x{insn.address:08X}: {insn.mnemonic} {insn.op_str}")
        lines.append(f"  --> Successors: {succ_str}")

    complexity = cyclomatic_complexity(blocks)
    lines.append(f"\nTotal Blocks: {len(blocks)} | Cyclomatic Complexity: {complexity}")
    return "\n".join(lines)
