from __future__ import annotations

from ichnos.crypto.classical.symboltable_data import TABLES


def list_tables() -> list[str]:
    """Return a sorted list of all available symbol tables."""
    return sorted(TABLES.keys())


def get_table(name: str) -> dict[str, str]:
    """Return the char->symbol mapping for the given table name."""
    if name not in TABLES:
        raise ValueError(f"Table {name} not found")
    return TABLES[name]


def get_reverse_table(name: str) -> dict[str, str]:
    """Return the symbol->char mapping for the given table name."""
    table = get_table(name)
    return {v: k for k, v in table.items()}


def encode(text: str, table_name: str) -> list[str]:
    """Encode text using the given symbol table."""
    table = get_table(table_name)
    result = []
    for c in text:
        cu = c.upper()
        if cu in table:
            result.append(table[cu])
        else:
            result.append(c)
    return result


def decode(symbols: str | list[str], table_name: str) -> str:
    """Decode symbols using the given symbol table."""
    rev_table = get_reverse_table(table_name)
    if isinstance(symbols, str):
        # Very basic split for string input
        symbols = symbols.split()

    result = []
    for s in symbols:
        if s in rev_table:
            result.append(rev_table[s])
        else:
            result.append(s)
    return "".join(result)
