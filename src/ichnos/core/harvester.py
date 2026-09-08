"""CTF Parameter and Primitive Harvester.

Extracts mathematical, cryptographic, and structural parameters from Python scripts,
execution logs, text dumps, and key files using Python AST, regex heuristics, and key parsers.
"""

from __future__ import annotations

import ast
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

from ichnos.core.workspace import ChallengeWorkspace, FileCategory, WorkspaceFile

# Flag regex pattern covering standard CTF prefixes
FLAG_PATTERN = re.compile(
    r"(?:FLAG|CTF|NSS|picoCTF|HTB|SECUIN|DUCTF|THCon|0xL4ugh|[A-Za-z0-9_]{2,12})\{[A-Za-z0-9_\-!@#$%^&*+=?., ]+\}",
    re.IGNORECASE,
)


@dataclass
class HarvestedParameters:
    """Aggregated parameters and primitives harvested from CTF inputs."""

    # Categorized parameters (name, value)
    moduli: list[tuple[str, int]] = field(default_factory=list)
    ciphertexts: list[tuple[str, int]] = field(default_factory=list)
    exponents: list[tuple[str, int]] = field(default_factory=list)
    primes: list[tuple[str, int]] = field(default_factory=list)
    keys: list[tuple[str, Any]] = field(default_factory=list)

    # Discrete Log parameters: g, h, p
    dlog: dict[str, int] = field(default_factory=dict)

    # Elliptic curve parameters: a, b, p, gx, gy, px, py, etc.
    ecc: dict[str, int] = field(default_factory=dict)

    # Flags, cribs, hashes, and strings
    flags: list[str] = field(default_factory=list)
    hashes: list[tuple[str, str]] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)

    # Higher-order structures: matrices, vectors, cipher tuples, JWTs
    matrices: list[tuple[str, list[list[int]]]] = field(default_factory=list)
    vectors: list[tuple[str, list[int]]] = field(default_factory=list)
    cipher_tuples: list[tuple[str, tuple[Any, ...]]] = field(default_factory=list)
    jwts: list[str] = field(default_factory=list)

    # All evaluated variables
    all_vars: dict[str, Any] = field(default_factory=dict)

    # Origin sources
    sources: list[str] = field(default_factory=list)

    def get_moduli(self) -> list[int]:
        """Return unique harvested modulus values preserving order."""
        seen = set()
        res = []
        for _, n in self.moduli:
            if n not in seen:
                seen.add(n)
                res.append(n)
        return res

    def get_ciphertexts(self) -> list[int]:
        """Return unique harvested ciphertext integer values preserving order."""
        seen = set()
        res = []
        for _, c in self.ciphertexts:
            if c not in seen:
                seen.add(c)
                res.append(c)
        return res

    def get_exponents(self) -> list[int]:
        """Return unique harvested public exponent values, defaulting to [65537] if none."""
        seen = set()
        res = []
        for _, e in self.exponents:
            if e not in seen:
                seen.add(e)
                res.append(e)
        if not res and self.moduli:
            return [65537]
        return res

    def get_primes(self) -> list[int]:
        """Return unique harvested prime factors."""
        seen = set()
        res = []
        for _, p in self.primes:
            if p not in seen:
                seen.add(p)
                res.append(p)
        return res

    def summary(self) -> dict[str, Any]:
        return {
            "sources": self.sources,
            "moduli_count": len(self.moduli),
            "ciphertexts_count": len(self.ciphertexts),
            "exponents": [e for _, e in self.exponents],
            "primes_count": len(self.primes),
            "matrices_count": len(self.matrices),
            "vectors_count": len(self.vectors),
            "cipher_tuples_count": len(self.cipher_tuples),
            "jwts_count": len(self.jwts),
            "flags_found": self.flags,
            "variables_harvested": list(self.all_vars.keys()),
        }


class _EvalContext:
    """Evaluation context tracking limits for ASTEvaluator."""

    def __init__(self, env: dict[str, Any] | None = None) -> None:
        self.env = env or {}
        self.depth = 0
        self.node_count = 0
        self.start_time = time.monotonic()

    def check_limits(self) -> None:
        self.node_count += 1
        if self.node_count > ASTEvaluator.MAX_NODES:
            raise ValueError("AST node limit exceeded")
        if self.depth > ASTEvaluator.MAX_DEPTH:
            raise ValueError("AST recursion depth exceeded")
        if (time.monotonic() - self.start_time) > ASTEvaluator.TIMEOUT_SECONDS:
            raise TimeoutError("AST evaluation timed out")


class ASTEvaluator(ast.NodeVisitor):
    """Safely evaluates AST literals, calls to bytes_to_long, bytes.fromhex, int, and arithmetic.

    Hardened against:
    - Recursion depth exhaustion (depth > 50)
    - AST node explosion (node_count > 2000)
    - Exponential integer allocation (bit-length > 16384 bits)
    - Unbounded exponentiation (2**999999999999)
    - Quadratic string-to-int conversion (int('9'*100000))
    - Wall-clock timeout (> 1.0s)
    """

    MAX_DEPTH = 50
    MAX_NODES = 2000
    MAX_BITS = 16384
    MAX_EXP = 4096
    MAX_STR_INT_LEN = 8192
    MAX_HEX_LEN = 16384
    TIMEOUT_SECONDS = 1.0

    @classmethod
    def evaluate(cls, node: ast.AST, env: dict[str, Any] | None = None) -> Any:
        ctx = _EvalContext(env)
        try:
            return cls._eval_node(node, ctx)
        except Exception:
            return None

    @classmethod
    def _eval_node(cls, node: ast.AST, ctx: _EvalContext) -> Any:
        ctx.check_limits()
        ctx.depth += 1
        try:
            if isinstance(node, ast.Constant):
                if isinstance(node.value, int) and node.value.bit_length() > cls.MAX_BITS:
                    return None
                if isinstance(node.value, str) and len(node.value) > 100_000:
                    return None
                return node.value

            if isinstance(node, ast.Name):
                if node.id in ctx.env:
                    return ctx.env[node.id]
                return None

            if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
                val = cls._eval_node(node.operand, ctx)
                if isinstance(val, (int, float)):
                    if isinstance(val, int) and val.bit_length() > cls.MAX_BITS:
                        return None
                    return -val

            if isinstance(node, (ast.List, ast.Tuple)):
                return [cls._eval_node(elt, ctx) for elt in node.elts]

            if isinstance(node, ast.Dict):
                res = {}
                for k, v in zip(node.keys, node.values):
                    if k is not None:
                        res[cls._eval_node(k, ctx)] = cls._eval_node(v, ctx)
                return res

            if isinstance(node, ast.BinOp):
                left = cls._eval_node(node.left, ctx)
                right = cls._eval_node(node.right, ctx)
                if isinstance(left, int) and isinstance(right, int):
                    if left.bit_length() > cls.MAX_BITS or right.bit_length() > cls.MAX_BITS:
                        return None
                    if isinstance(node.op, ast.Add):
                        res = left + right
                        return res if res.bit_length() <= cls.MAX_BITS else None
                    if isinstance(node.op, ast.Sub):
                        res = left - right
                        return res if res.bit_length() <= cls.MAX_BITS else None
                    if isinstance(node.op, ast.Mult):
                        if left.bit_length() + right.bit_length() > cls.MAX_BITS:
                            return None
                        res = left * right
                        return res if res.bit_length() <= cls.MAX_BITS else None
                    if isinstance(node.op, ast.FloorDiv) and right != 0:
                        return left // right
                    if isinstance(node.op, ast.Mod) and right != 0:
                        return left % right
                    if isinstance(node.op, ast.Pow):
                        if 0 <= right <= cls.MAX_EXP:
                            if left in (0, 1):
                                return left
                            if left.bit_length() * right <= cls.MAX_BITS:
                                return pow(left, right)
                        return None

            if isinstance(node, ast.Call):
                # bytes.fromhex("...")
                if isinstance(node.func, ast.Attribute) and node.func.attr == "fromhex":
                    arg = cls._eval_node(node.args[0], ctx)
                    if isinstance(arg, str) and len(arg) <= cls.MAX_HEX_LEN:
                        return bytes.fromhex(arg)

                # int("...", 16) or int(...)
                if isinstance(node.func, ast.Name) and node.func.id == "int":
                    if len(node.args) == 1:
                        arg = cls._eval_node(node.args[0], ctx)
                        if isinstance(arg, str):
                            if len(arg) > cls.MAX_STR_INT_LEN:
                                return None
                            val = int(arg)
                            return val if val.bit_length() <= cls.MAX_BITS else None
                        elif isinstance(arg, int):
                            return arg if arg.bit_length() <= cls.MAX_BITS else None
                    if len(node.args) == 2:
                        arg = cls._eval_node(node.args[0], ctx)
                        base = cls._eval_node(node.args[1], ctx)
                        if isinstance(arg, str) and isinstance(base, int) and 2 <= base <= 36:
                            if len(arg) > cls.MAX_STR_INT_LEN:
                                return None
                            val = int(arg, base)
                            return val if val.bit_length() <= cls.MAX_BITS else None

                # bytes_to_long(b"...")
                if isinstance(node.func, ast.Name) and node.func.id in (
                    "bytes_to_long",
                    "bytes2long",
                ):
                    arg = cls._eval_node(node.args[0], ctx)
                    if isinstance(arg, bytes):
                        if len(arg) > cls.MAX_BITS // 8 + 1:
                            return None
                        return int.from_bytes(arg, "big")
                    if isinstance(arg, str):
                        b = arg.encode()
                        if len(b) > cls.MAX_BITS // 8 + 1:
                            return None
                        return int.from_bytes(b, "big")

                # pow(b, e, m) or pow(b, e)
                if isinstance(node.func, ast.Name) and node.func.id == "pow":
                    args = [cls._eval_node(a, ctx) for a in node.args]
                    if len(args) == 3 and all(isinstance(x, int) for x in args):
                        b, e, m = args[0], args[1], args[2]
                        if (
                            m != 0
                            and e >= 0
                            and b.bit_length() <= cls.MAX_BITS
                            and m.bit_length() <= cls.MAX_BITS
                            and e.bit_length() <= cls.MAX_BITS
                        ):
                            return pow(b, e, m)
                    if len(args) == 2 and all(isinstance(x, int) for x in args):
                        b, e = args[0], args[1]
                        if 0 <= e <= cls.MAX_EXP:
                            if b in (0, 1):
                                return b
                            if b.bit_length() * e <= cls.MAX_BITS:
                                return pow(b, e)

            return None
        finally:
            ctx.depth -= 1


class CTFHarvester:
    """Extracts parameters from challenge workspaces, code files, logs, or text strings."""

    @classmethod
    def harvest_workspace(cls, workspace: ChallengeWorkspace) -> HarvestedParameters:
        """Harvester entrypoint for a full challenge workspace."""
        params = HarvestedParameters()

        # Ingest files in order: source code first, then logs, then keys, then others
        files = (
            workspace.source_files
            + workspace.log_files
            + workspace.key_files
            + [
                f
                for f in workspace.files
                if f not in workspace.source_files + workspace.log_files + workspace.key_files
            ]
        )

        for wf in files:
            cls.harvest_file(wf, params)

        return params

    @classmethod
    def harvest_file(
        cls, wf: WorkspaceFile, params: HarvestedParameters | None = None
    ) -> HarvestedParameters:
        """Harvester for a single workspace file."""
        if params is None:
            params = HarvestedParameters()

        params.sources.append(wf.relative_path)
        data = wf.data
        text = wf.text

        # 1. Look for explicit flags immediately in source code, logs, or data files
        if wf.category in (FileCategory.SOURCE_CODE, FileCategory.OUTPUT_LOGS, FileCategory.DATA):
            for match in FLAG_PATTERN.finditer(text):
                flag = match.group(0)
                if flag not in params.flags:
                    params.flags.append(flag)

        # 2. Key files (PEM / DER)
        if wf.category == FileCategory.CRYPTO_KEYS or b"-----BEGIN " in data:
            cls._harvest_keys(data, text, wf.relative_path, params)

        # 3. Source Code (Python AST)
        if wf.category == FileCategory.SOURCE_CODE or wf.path.suffix.lower() in (".py", ".sage"):
            cls._harvest_python_ast(text, params)

        # 4. Logs / Text Regex Parsing
        cls._harvest_text_regex(text, params)

        return params

    @classmethod
    def harvest_text(cls, text: str, source_name: str = "<text>") -> HarvestedParameters:
        """Harvester for raw string / piped input."""
        params = HarvestedParameters()
        params.sources.append(source_name)

        # 1. Flags
        for match in FLAG_PATTERN.finditer(text):
            flag = match.group(0)
            if flag not in params.flags:
                params.flags.append(flag)

        # 2. Python AST (try parsing as code first)
        try:
            cls._harvest_python_ast(text, params)
        except Exception:
            pass

        # 3. Regex / Text Parsing
        cls._harvest_text_regex(text, params)

        # 4. Check for PEM keys in text
        if "-----BEGIN " in text:
            cls._harvest_keys(text.encode(), text, source_name, params)

        return params

    @classmethod
    def _harvest_keys(
        cls, data: bytes, text: str, source_name: str, params: HarvestedParameters
    ) -> None:
        """Extract RSA / ECC parameters from PEM or DER."""
        try:
            from ichnos.crypto.rsa.inspect import parse_rsa_pem

            rsa_params = parse_rsa_pem(text)
            params.moduli.append((f"{source_name}_n", rsa_params.n))
            params.exponents.append((f"{source_name}_e", rsa_params.e))
            if rsa_params.d:
                params.keys.append((f"{source_name}_d", rsa_params.d))
            if rsa_params.p:
                params.primes.append((f"{source_name}_p", rsa_params.p))
            if rsa_params.q:
                params.primes.append((f"{source_name}_q", rsa_params.q))
        except Exception:
            pass

    @classmethod
    def _harvest_python_ast(cls, code: str, params: HarvestedParameters) -> None:
        """Traverse Python AST in statement order for assignments."""
        try:
            tree = ast.parse(code)
        except Exception:
            return

        def process_node(node: ast.AST) -> None:
            if isinstance(node, ast.Assign):
                val = ASTEvaluator.evaluate(node.value, env=params.all_vars)
                if val is not None:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            cls._classify_and_store(target.id, val, params)
                        elif isinstance(target, (ast.Tuple, ast.List)) and isinstance(
                            val, (tuple, list)
                        ):
                            if len(target.elts) == len(val):
                                for sub_t, sub_v in zip(target.elts, val):
                                    if isinstance(sub_t, ast.Name):
                                        cls._classify_and_store(sub_t.id, sub_v, params)

            elif isinstance(node, ast.AnnAssign):
                if isinstance(node.target, ast.Name) and node.value:
                    val = ASTEvaluator.evaluate(node.value, env=params.all_vars)
                    if val is not None:
                        cls._classify_and_store(node.target.id, val, params)

            for child in ast.iter_child_nodes(node):
                if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    process_node(child)

        for stmt in tree.body:
            if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                process_node(stmt)

    @classmethod
    def _harvest_text_regex(cls, text: str, params: HarvestedParameters) -> None:
        """Regex scanning for assignments, numbers, and structured logs across all languages."""
        # Check JSON objects
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            cls._classify_and_store(str(k), v, params)
                except Exception:
                    pass

        # ----------------------------------------------------------------
        # Commented variable assignments (e.g. `# ct = '85c43735...'`)
        # Covers Python (#), C/JS/Go (//), SQL/Lua (--), and block (/* ... */)
        # ----------------------------------------------------------------
        comment_assign_regex = re.compile(
            r"^\s*(?:#|//|--)\s*"
            r"([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"
            r"(0x[0-9a-fA-F]+|[0-9]+[nLuU]*|b?['\"`][^'\"`]*['\"`])\s*[;,]?",
            re.MULTILINE,
        )
        for match in comment_assign_regex.finditer(text):
            var_name, val_str = match.group(1), match.group(2).strip()
            val = cls._parse_val_string(val_str)
            if val is not None:
                cls._classify_and_store(var_name, val, params)

        # Universal assignment regex covering Python, JS, TS, PHP, Lua, Go, Rust, C/C++, Java, Solidity, etc.
        assign_regex = re.compile(
            r"(?:^|[;\n])\s*(?:(?:const|let|var|local|my|our|state|final|static|public|private|protected|val|auto|"
            r"uint\d*|int\d*|uint\d*_t|int\d*_t|unsigned\s+long|unsigned\s+int|long\s+long|long|int|byte|char|"
            r"string|bytes\d*)\s+){0,4}(?:mut\s+)?[$@%]?([a-zA-Z_][a-zA-Z0-9_]*)(?:\s*:\s*[a-zA-Z0-9_<>\[\]]+)?\s*(?:[:=]|:=)\s*"
            r"(0x[0-9a-fA-F]+|[0-9]+[nLuU]*|b?['\"`][^'\"`]*['\"`])\s*[;,]?",
            re.MULTILINE,
        )

        for match in assign_regex.finditer(text):
            var_name, val_str = match.group(1), match.group(2).strip()
            val = cls._parse_val_string(val_str)
            if val is not None:
                cls._classify_and_store(var_name, val, params)

        # Also find standalone large integers on single lines (e.g. raw numbers printed without variable name)
        number_line_regex = re.compile(r"^\s*(0x[0-9a-fA-F]{30,}|[0-9]{30,})\s*$", re.MULTILINE)
        idx = 1
        for match in number_line_regex.finditer(text):
            val = cls._parse_val_string(match.group(1))
            if isinstance(val, int) and val.bit_length() >= 64:
                var_name = f"unnamed_int_{idx}"
                if var_name not in params.all_vars:
                    cls._classify_and_store(var_name, val, params)
                    idx += 1

    @staticmethod
    def _parse_val_string(s: str) -> Any:
        s = s.strip().rstrip(";,")
        try:
            if s.startswith(("0x", "0X")):
                s_hex = s.rstrip("nLuU")
                return int(s_hex, 16)
            s_clean = s.rstrip("nLuU")
            if s_clean.isdigit():
                return int(s_clean)
            if s.startswith("b'") or s.startswith('b"'):
                return ast.literal_eval(s)
            if s.startswith(("'", '"', "`")) and len(s) >= 2:
                return s[1:-1]
        except Exception:
            return None
        return None

    @classmethod
    def _classify_and_store(cls, name: str, val: Any, params: HarvestedParameters) -> None:
        """Classify a variable name and value into the appropriate parameter category."""
        if len(params.all_vars) >= 1000:
            return
        params.all_vars[name] = val
        norm = name.strip().lower()

        # Check if value is a list/tuple of items
        if isinstance(val, (list, tuple)):
            if len(val) > 0:
                # 1. 2D Matrix: list of lists/tuples of ints
                if all(isinstance(r, (list, tuple)) for r in val) and all(
                    isinstance(x, int) for r in val for x in r
                ):
                    params.matrices.append((name, [[int(x) for x in r] for r in val]))
                # 2. 1D Vector: list of ints
                elif all(isinstance(x, int) for x in val):
                    params.vectors.append((name, [int(x) for x in val]))

                # 3. Cipher Tuple (e.g. ct = ((...), ...))
                if norm in ("ct", "c", "enc", "ciphertext", "cipher") or norm.startswith(
                    ("ct_", "c_")
                ):
                    params.cipher_tuples.append((name, tuple(val)))

            if len(val) <= 32:
                for i, item in enumerate(val):
                    cls._classify_and_store(f"{name}_{i + 1}", item, params)
            else:
                # Sample first few elements for strings/flags but avoid expanding massive vectors/matrices into thousands of variables
                for i in range(min(4, len(val))):
                    cls._classify_and_store(f"{name}_{i + 1}", val[i], params)
            return

        # If value is string or bytes, check for flag or convert to int if hex or JWT
        if isinstance(val, (str, bytes)):
            s = val.decode(errors="ignore") if isinstance(val, bytes) else val
            for match in FLAG_PATTERN.finditer(s):
                f = match.group(0)
                if f not in params.flags:
                    params.flags.append(f)

            if isinstance(val, str) and val.startswith("eyJ") and "." in val:
                if val not in params.jwts:
                    params.jwts.append(val)

            # Check if hex string representing an integer
            if isinstance(val, str) and re.fullmatch(r"[0-9a-fA-F]{32,}", val):
                try:
                    int_val = int(val, 16)
                    # Also classify as integer
                    cls._classify_number(norm, name, int_val, params)
                except Exception:
                    pass

        # If value is integer
        if isinstance(val, int):
            cls._classify_number(norm, name, val, params)

    @classmethod
    def _classify_number(
        cls, norm: str, orig_name: str, val: int, params: HarvestedParameters
    ) -> None:
        # Moduli (including LWE modulus q)
        is_mod_name = (
            norm in ("n", "modulus", "mod", "pubkey", "pk", "q", "q_mod", "mod_q")
            or norm.startswith(("n_", "mod_", "q_"))
            or bool(re.match(r"^n\d+$", norm))
            or "modulus" in norm
        )
        if is_mod_name:
            if val.bit_length() >= 64:
                params.moduli.append((orig_name, val))
                return

        # Ciphertexts
        is_ct_name = (
            norm in ("c", "ct", "enc", "ciphertext", "cipher")
            or norm.startswith(("c_", "ct_"))
            or bool(re.match(r"^c\d+$", norm))
            or "cipher" in norm
            or "enc" in norm
        )
        if is_ct_name:
            if val > 0:
                params.ciphertexts.append((orig_name, val))
            return

        # Public exponents
        is_exp_name = (
            norm in ("e", "exp", "exponent", "pub_exp")
            or norm.startswith(("e_", "exp_"))
            or bool(re.match(r"^e\d+$", norm))
        )
        if is_exp_name:
            if val > 0:
                params.exponents.append((orig_name, val))
            return

        # Primes
        is_prime_name = (
            norm in ("p", "q", "r", "prime", "prime1", "prime2")
            or norm.startswith(("p_", "q_", "prime_"))
            or bool(re.match(r"^[pq]\d+$", norm))
        )
        if is_prime_name:
            params.primes.append((orig_name, val))
            return

        # Secret exponents / private keys
        if norm in ("d", "privkey", "secret", "private_key", "phi") or norm.startswith(
            ("d_", "priv_")
        ):
            params.keys.append((orig_name, val))
            return

        # Discrete Log: g, h
        if norm in ("g", "generator"):
            params.dlog["g"] = val
            return
        if norm in ("h", "public_val"):
            params.dlog["h"] = val
            return

        # Elliptic curve
        if norm in ("gx", "gy", "px", "py", "qx", "qy", "order"):
            params.ecc[norm] = val
            return

        # Large unidentified integer: if >= 512 bits, likely RSA parameter
        # Bound additions to prevent matrix/lattice vectors from ballooning RSA candidates
        if val.bit_length() >= 512:
            if len(params.moduli) < 5 and not re.search(r"_\d+$", orig_name):
                params.moduli.append((orig_name, val))
        elif val.bit_length() >= 128:
            if len(params.ciphertexts) < 5 and not re.search(r"_\d+$", orig_name):
                params.ciphertexts.append((orig_name, val))
        elif val in (3, 5, 17, 65537):
            params.exponents.append((orig_name, val))
