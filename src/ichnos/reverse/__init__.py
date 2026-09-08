"""Reverse engineering module for Ichnos.

Provides disassembly (Capstone + built-in fallback), basic block partitioning,
Control Flow Graph (CFG) analysis, and binary patching tools.
"""

from __future__ import annotations

from ichnos.reverse import cff, cfg, disasm, emulate, gadgets, patch, patterns

__all__ = ["cff", "cfg", "disasm", "emulate", "gadgets", "patch", "patterns"]
