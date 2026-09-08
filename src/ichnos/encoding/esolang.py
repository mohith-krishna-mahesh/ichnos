"""Esoteric programming languages interpreters for CTF challenges."""

from __future__ import annotations

import re


def interpret_brainfuck(code: str, input_data: str = "", max_steps: int = 100_000) -> str:
    """Interpret Brainfuck code.

    Tape-based interpreter: > < + - . , [ ]
    30000-cell tape, wrapping byte values 0-255.
    """
    tape = [0] * 30000
    ptr = 0
    output: list[str] = []
    input_ptr = 0

    # Strip non-BF characters
    bf_chars = set("><+-.,[]")
    clean = [c for c in code if c in bf_chars]

    # Precompute bracket matching
    brackets: dict[int, int] = {}
    stack: list[int] = []
    for i, char in enumerate(clean):
        if char == "[":
            stack.append(i)
        elif char == "]":
            if not stack:
                return "Error: Unmatched ']'"
            j = stack.pop()
            brackets[j] = i
            brackets[i] = j

    if stack:
        return "Error: Unmatched '['"

    pc = 0
    steps = 0
    while pc < len(clean):
        if steps >= max_steps:
            break

        match clean[pc]:
            case ">":
                ptr = (ptr + 1) % len(tape)
            case "<":
                ptr = (ptr - 1) % len(tape)
            case "+":
                tape[ptr] = (tape[ptr] + 1) % 256
            case "-":
                tape[ptr] = (tape[ptr] - 1) % 256
            case ".":
                output.append(chr(tape[ptr]))
            case ",":
                if input_ptr < len(input_data):
                    tape[ptr] = ord(input_data[input_ptr])
                    input_ptr += 1
                else:
                    tape[ptr] = 0
            case "[":
                if tape[ptr] == 0:
                    pc = brackets[pc]
            case "]":
                if tape[ptr] != 0:
                    pc = brackets[pc]

        pc += 1
        steps += 1

    return "".join(output)


def interpret_ook(code: str, input_data: str = "", max_steps: int = 100_000) -> str:
    """Interpret Ook! code by translating to Brainfuck."""
    tokens = re.findall(r"Ook[.!?]\s*Ook[.!?]", code)
    mapping = {
        "Ook. Ook?": ">",
        "Ook? Ook.": "<",
        "Ook. Ook.": "+",
        "Ook! Ook!": "-",
        "Ook! Ook.": ".",
        "Ook. Ook!": ",",
        "Ook! Ook?": "[",
        "Ook? Ook!": "]",
    }
    normalized = [re.sub(r"\s+", " ", t) for t in tokens]
    bf_code = "".join(mapping.get(t, "") for t in normalized)
    return interpret_brainfuck(bf_code, input_data, max_steps)


def interpret_jsfuck(code: str) -> str:
    """Heuristic JSFuck decoder.

    Full static JSFuck evaluation is extremely complex. This handles
    common CTF patterns: String.fromCharCode calls and simple numeric
    constructions. For complex JSFuck, recommend running in a JS console.
    """
    # Pattern: String.fromCharCode(N, N, ...)
    match = re.search(r"String\.fromCharCode\(([0-9,\s]+)\)", code)
    if match:
        nums = [int(n.strip()) for n in match.group(1).split(",") if n.strip().isdigit()]
        return "".join(chr(n) for n in nums if 0 <= n < 0x110000)

    return "[JSFuck: static decode not possible — run in a JS console]"


def interpret_whitespace(code: str, input_data: str = "", max_steps: int = 100_000) -> str:
    """Interpret Whitespace code.

    Uses only space (S), tab (T), and newline (N).
    Implements: stack manipulation, arithmetic, heap, flow control, I/O.
    """
    ws = [c for c in code if c in (" ", "\t", "\n")]
    if not ws:
        return ""

    stack: list[int] = []
    call_stack: list[int] = []
    heap: dict[int, int] = {}
    output: list[str] = []

    def _read_number(pos: int) -> tuple[int, int]:
        if pos >= len(ws):
            return 0, pos
        sign = 1 if ws[pos] == " " else -1
        pos += 1
        bits: list[str] = []
        while pos < len(ws) and ws[pos] != "\n":
            bits.append("0" if ws[pos] == " " else "1")
            pos += 1
        pos += 1  # skip terminal \n
        return sign * int("".join(bits), 2) if bits else 0, pos

    def _read_label(pos: int) -> tuple[str, int]:
        chars: list[str] = []
        while pos < len(ws) and ws[pos] != "\n":
            chars.append("S" if ws[pos] == " " else "T")
            pos += 1
        pos += 1
        return "".join(chars), pos

    # Pre-scan for labels (NSS <label> \n)
    labels: dict[str, int] = {}
    scan = 0
    while scan < len(ws):
        if scan + 2 < len(ws) and ws[scan] == "\n" and ws[scan + 1] == " " and ws[scan + 2] == " ":
            lbl, scan = _read_label(scan + 3)
            labels[lbl] = scan
        else:
            scan += 1

    pc = 0
    steps = 0
    while pc < len(ws) and steps < max_steps:
        steps += 1
        if pc >= len(ws):
            break
        c1 = ws[pc]
        pc += 1

        if c1 == " ":  # Stack manipulation
            if pc >= len(ws):
                break
            c2 = ws[pc]
            pc += 1
            if c2 == " ":  # Push number
                num, pc = _read_number(pc)
                stack.append(num)
            elif c2 == "\n":
                if pc >= len(ws):
                    break
                c3 = ws[pc]
                pc += 1
                if c3 == " ":  # Dup
                    if stack:
                        stack.append(stack[-1])
                elif c3 == "\t":  # Swap
                    if len(stack) >= 2:
                        stack[-1], stack[-2] = stack[-2], stack[-1]
                elif c3 == "\n":  # Pop
                    if stack:
                        stack.pop()
            elif c2 == "\t":
                if pc >= len(ws):
                    break
                c3 = ws[pc]
                pc += 1
                if c3 == " ":  # Copy nth
                    num, pc = _read_number(pc)
                    if 0 <= num < len(stack):
                        stack.append(stack[-(num + 1)])
                elif c3 == "\n":  # Slide n
                    num, pc = _read_number(pc)
                    if stack and num > 0:
                        top = stack.pop()
                        for _ in range(min(num, len(stack))):
                            stack.pop()
                        stack.append(top)

        elif c1 == "\t":
            if pc >= len(ws):
                break
            c2 = ws[pc]
            pc += 1

            if c2 == " ":  # Arithmetic
                if pc >= len(ws):
                    break
                c3 = ws[pc]
                pc += 1
                if pc >= len(ws):
                    break
                c4 = ws[pc]
                pc += 1
                if len(stack) >= 2:
                    b = stack.pop()
                    a = stack.pop()
                    if c3 == " " and c4 == " ":
                        stack.append(a + b)
                    elif c3 == " " and c4 == "\t":
                        stack.append(a - b)
                    elif c3 == " " and c4 == "\n":
                        stack.append(a * b)
                    elif c3 == "\t" and c4 == " ":
                        stack.append(a // b if b else 0)
                    elif c3 == "\t" and c4 == "\t":
                        stack.append(a % b if b else 0)

            elif c2 == "\t":  # Heap
                if pc >= len(ws):
                    break
                c3 = ws[pc]
                pc += 1
                if c3 == " ":
                    if len(stack) >= 2:
                        val = stack.pop()
                        addr = stack.pop()
                        heap[addr] = val
                elif c3 == "\t":
                    if stack:
                        addr = stack.pop()
                        stack.append(heap.get(addr, 0))

            elif c2 == "\n":  # I/O
                if pc >= len(ws):
                    break
                c3 = ws[pc]
                pc += 1
                if c3 == " ":  # Output char
                    if stack:
                        v = stack.pop()
                        output.append(chr(v) if 0 <= v < 0x110000 else "?")
                elif c3 == "\t":  # Output number
                    if stack:
                        output.append(str(stack.pop()))

        elif c1 == "\n":  # Flow control
            if pc >= len(ws):
                break
            c2 = ws[pc]
            pc += 1
            if pc >= len(ws):
                break
            c3 = ws[pc]
            pc += 1

            if c2 == " " and c3 == " ":  # Mark label
                _, pc = _read_label(pc)
            elif c2 == " " and c3 == "\t":  # Call
                lbl, pc = _read_label(pc)
                if lbl in labels:
                    call_stack.append(pc)
                    pc = labels[lbl]
            elif c2 == " " and c3 == "\n":  # Jump
                lbl, pc = _read_label(pc)
                if lbl in labels:
                    pc = labels[lbl]
            elif c2 == "\t" and c3 == " ":  # Jump if zero
                lbl, pc = _read_label(pc)
                if stack and stack.pop() == 0 and lbl in labels:
                    pc = labels[lbl]
            elif c2 == "\t" and c3 == "\t":  # Jump if negative
                lbl, pc = _read_label(pc)
                if stack and stack.pop() < 0 and lbl in labels:
                    pc = labels[lbl]
            elif c2 == "\t" and c3 == "\n":  # Return
                if call_stack:
                    pc = call_stack.pop()
            elif c2 == "\n" and c3 == "\n":  # End
                break

    return "".join(output)


def interpret_lolcode(code: str, max_steps: int = 100_000) -> str:
    """Interpret basic LOLCODE.

    Supports: HAI/KTHXBYE, VISIBLE, I HAS A/ITZ,
    SUM OF/DIFF OF/PRODUKT OF/QUOSHUNT OF, GIMMEH, IT.
    """
    lines = [line.strip() for line in code.split("\n")]
    output: list[str] = []
    variables: dict[str, int | str] = {"IT": 0}
    steps = 0
    started = False

    def _eval(expr: str) -> int | str:
        expr = expr.strip()
        if expr.startswith("SUM OF "):
            parts = expr[7:].split(" AN ", 1)
            if len(parts) == 2:
                return int(_eval(parts[0])) + int(_eval(parts[1]))
        if expr.startswith("DIFF OF "):
            parts = expr[8:].split(" AN ", 1)
            if len(parts) == 2:
                return int(_eval(parts[0])) - int(_eval(parts[1]))
        if expr.startswith("PRODUKT OF "):
            parts = expr[11:].split(" AN ", 1)
            if len(parts) == 2:
                return int(_eval(parts[0])) * int(_eval(parts[1]))
        if expr.startswith("QUOSHUNT OF "):
            parts = expr[12:].split(" AN ", 1)
            if len(parts) == 2:
                d = int(_eval(parts[1]))
                return int(_eval(parts[0])) // d if d else 0
        if expr.startswith('"') and expr.endswith('"'):
            return expr[1:-1]
        try:
            return int(expr)
        except ValueError:
            pass
        return variables.get(expr, expr)

    for line in lines:
        steps += 1
        if steps > max_steps:
            break
        if not line or line.startswith("BTW"):
            continue
        if line.startswith("HAI"):
            started = True
            continue
        if line == "KTHXBYE":
            break
        if not started:
            continue

        if line.startswith("VISIBLE "):
            val = _eval(line[8:].strip())
            output.append(str(val))
            if not line.endswith("!"):
                output.append("\n")
        elif line.startswith("I HAS A "):
            rest = line[8:]
            if " ITZ " in rest:
                name, expr = rest.split(" ITZ ", 1)
                variables[name.strip()] = _eval(expr)
            else:
                variables[rest.strip()] = 0
        elif " R " in line:
            parts = line.split(" R ", 1)
            variables[parts[0].strip()] = _eval(parts[1])

    return "".join(output).rstrip("\n")


def interpret_deadfish(code: str) -> str:
    """Interpret Deadfish code.

    Commands: i (increment), d (decrement), s (square), o (output as char).
    If accumulator reaches -1 or 256, reset to 0.
    """
    acc = 0
    output: list[str] = []

    for char in code:
        match char:
            case "i":
                acc += 1
            case "d":
                acc -= 1
            case "s":
                acc *= acc
            case "o":
                output.append(chr(acc) if 0 <= acc < 0x110000 else "?")

        if acc == -1 or acc == 256:
            acc = 0

    return "".join(output)


# Aliases
execute_brainfuck = interpret_brainfuck
execute_ook = interpret_ook
execute_jsfuck = interpret_jsfuck
execute_whitespace = interpret_whitespace
execute_lolcode = interpret_lolcode
execute_deadfish = interpret_deadfish
