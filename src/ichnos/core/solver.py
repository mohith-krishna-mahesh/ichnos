"""Autonomous CTF Challenge Solver and Deterministic Attack Correlation Engine."""

from __future__ import annotations

import math
from pathlib import Path

from ichnos.binary.solver import solve_binary
from ichnos.core.detection import english_score, printable_ratio
from ichnos.core.harvester import FLAG_PATTERN, CTFHarvester, HarvestedParameters
from ichnos.core.models import Candidate, Finding, Result
from ichnos.core.solver_output import DeductionTrace
from ichnos.core.workspace import ChallengeWorkspace, FileCategory
from ichnos.crypto.classical.solver import solve_classical
from ichnos.crypto.numtheory import discrete_log, is_prime, mod_inverse
from ichnos.crypto.pqc.lwe import solve_lwe_dual_kernel
from ichnos.crypto.rsa.attacks import (
    common_modulus_attack,
    hastad_broadcast_attack,
    integer_nth_root,
    wiener_attack,
)
from ichnos.crypto.rsa.factor import factor, find_small_prime_factors
from ichnos.crypto.xor.repeating_key import crack as xor_repeat_crack
from ichnos.crypto.xor.single_byte import brute_force as xor_single_brute
from ichnos.encoding.layered import auto_decode
from ichnos.forensic.carver import carve_all
from ichnos.forensic.zip import extract_comments
from ichnos.pcap.solver import solve_pcap
from ichnos.stego.image.channels import extract_exif_from_image
from ichnos.web.solver import solve_web


def int_to_text(val: int) -> str:
    """Converts a large integer to text/string if printable."""
    if val <= 0:
        return ""
    byte_len = (val.bit_length() + 7) // 8
    try:
        b = val.to_bytes(byte_len, "big")
        try:
            return b.decode("utf-8")
        except UnicodeDecodeError:
            return b.decode("latin-1", errors="replace")
    except Exception:
        return ""


def extract_flag(text: str) -> str | None:
    """Extract standard CTF flag pattern from text."""
    match = FLAG_PATTERN.search(text)
    if match:
        return match.group(0)
    return None


def is_placeholder_flag(flag: str) -> bool:
    """Detect if a flag string is a template or dummy placeholder."""
    if "{" not in flag or "}" not in flag:
        return False
    body = flag[flag.index("{") + 1 : flag.rindex("}")]
    if not body:
        return True
    if "?" in body or "*" in body:
        return True
    if set(body) <= {"X", "x", "_", "-", "."}:
        return True
    lower_body = body.lower()
    if any(
        p in lower_body for p in ("todo", "redacted", "placeholder", "fake", "dummy", "insert_flag")
    ):
        return True
    return False


KNOWN_FLAG_PREFIXES = (
    "flag{",
    "ctf{",
    "nns{",
    "nss{",
    "picoctf{",
    "htb{",
    "secuin{",
    "ductf{",
    "thcon{",
    "0xl4ugh{",
)


def is_likely_static_flag(flag: str) -> bool:
    """Returns True only if flag appears to be genuine plaintext rather than classical ciphertext."""
    if is_placeholder_flag(flag):
        return False
    lower_f = flag.lower()
    if any(lower_f.startswith(p) for p in KNOWN_FLAG_PREFIXES):
        return True

    # If unknown prefix, test if any Caesar shift turns it into a known flag prefix
    from ichnos.crypto.classical.caesar import decrypt as caesar_dec

    for shift in range(1, 26):
        cand = caesar_dec(flag, shift)
        if any(cand.lower().startswith(p) for p in KNOWN_FLAG_PREFIXES):
            return False

    # Also check if Atbash turns it into a known prefix
    from ichnos.crypto.classical.atbash import decode as atbash_dec

    if any(atbash_dec(flag).lower().startswith(p) for p in KNOWN_FLAG_PREFIXES):
        return False

    return True


def check_plaintext(pt_str: str) -> tuple[bool, str | None]:
    """Checks if recovered plaintext contains a genuine flag or valid English text."""
    if not pt_str or len(pt_str) < 3:
        return False, None
    flag = extract_flag(pt_str)
    if flag and not is_placeholder_flag(flag):
        return True, flag
    raw_b = pt_str.encode("utf-8", errors="replace")
    if len(pt_str) >= 6 and printable_ratio(raw_b) > 0.85 and english_score(pt_str) > 0.3:
        return True, flag or pt_str
    return False, None


class AutoSolver:
    """Orchestrates ingestion, parameter harvesting, deterministic attack correlation, and reporting."""

    @classmethod
    def solve(
        cls,
        targets: list[str | Path] | str | Path | None = None,
        active_text: str | None = None,
        workspace: ChallengeWorkspace | None = None,
    ) -> tuple[DeductionTrace, Result]:
        """Main entry point for autonomous CTF challenge solving."""
        trace = DeductionTrace()

        # Step 1: Ingestion
        missing_paths: list[str] = []
        if workspace is None:
            workspace, active_text, missing_paths = cls._prepare_workspace(targets, active_text)

        cls._record_ingestion(workspace, active_text, trace, missing_paths=missing_paths)

        if missing_paths and workspace is None and not active_text:
            trace.add_step(
                "RESULT",
                "Solver aborted: specified target path(s) do not exist",
                status="failed",
            )
            return trace, cls._build_result(trace, HarvestedParameters(), status="error")

        # Step 2: Parameter Harvesting
        if workspace and workspace.files:
            params = CTFHarvester.harvest_workspace(workspace)
        elif active_text:
            params = CTFHarvester.harvest_text(active_text)
        else:
            params = HarvestedParameters()

        cls._record_harvesting(params, trace)

        # Step 3: Check Immediate Plaintext Flags (excluding placeholders and shifted ciphers)
        valid_static_flags = [f for f in params.flags if is_likely_static_flag(f)]
        if valid_static_flags:
            flag = valid_static_flags[0]
            trace.flag = flag
            trace.solved = True
            trace.attack_name = "Static Parameter Extraction"
            trace.add_step(
                "RESULT",
                f"Flag found directly in challenge source/logs: {flag}",
                [f"Matched Pattern: {flag}"],
            )
            return trace, cls._build_result(trace, params)

        # Step 4: Execute Deterministic Attack Matrix
        # 1. Lattice & Post-Quantum Cryptanalysis (LWE, knapsack, dual-kernel)
        if cls._solve_lattice_lwe(params, trace):
            return trace, cls._build_result(trace, params)

        # 2. RSA & Number Theory Suite
        if cls._solve_rsa(params, trace):
            return trace, cls._build_result(trace, params)

        # 3. Classical Cryptanalysis Suite (Caesar, Affine, Vigenere, Transposition)
        if cls._solve_classical_crypto(params, workspace, active_text, trace):
            return trace, cls._build_result(trace, params)

        # 4. Modern & Symmetric Cryptanalysis Suite (XOR, DLog)
        if cls._solve_modern_crypto(params, workspace, active_text, trace):
            return trace, cls._build_result(trace, params)

        # 5. Steganography & Metadata Analysis
        if workspace and cls._solve_stego(workspace, trace):
            return trace, cls._build_result(trace, params)

        # 6. Binary & Reverse Engineering Suite
        if workspace and cls._solve_binary(workspace, trace):
            return trace, cls._build_result(trace, params)

        # 7. Forensics & Embedded File Carving
        if workspace and cls._solve_forensics(workspace, trace):
            return trace, cls._build_result(trace, params)

        # 8. Network & PCAP Forensics
        if workspace and cls._solve_pcap(workspace, trace):
            return trace, cls._build_result(trace, params)

        # 9. Web & Token Security
        if cls._solve_web_and_passwords(params, workspace, active_text, trace):
            return trace, cls._build_result(trace, params)

        # 10. Layered Decoders & Base Encodings
        if cls._solve_layered_encodings(params, workspace, active_text, trace):
            return trace, cls._build_result(trace, params)

        # Finished without a definitive solution
        trace.add_step(
            "RESULT",
            "No deterministic exploit succeeded with current parameters",
            status="failed",
        )
        return trace, cls._build_result(trace, params)

    @classmethod
    def _is_path_like(cls, s: str) -> bool:
        s = s.strip()
        if s.startswith(("~", "/", "./", "../")) or "/" in s or "\\" in s:
            return True
        path_obj = Path(s)
        if path_obj.suffix.lower() in (
            ".py",
            ".txt",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".bmp",
            ".webp",
            ".zip",
            ".tar",
            ".gz",
            ".tgz",
            ".bz2",
            ".xz",
            ".7z",
            ".rar",
            ".bin",
            ".elf",
            ".exe",
            ".pcap",
            ".pcapng",
            ".wav",
            ".mp3",
            ".out",
            ".log",
            ".enc",
            ".c",
            ".cpp",
            ".sage",
            ".key",
            ".pem",
        ):
            return True
        return False

    @classmethod
    def _prepare_workspace(
        cls,
        targets: list[str | Path] | str | Path | None,
        active_text: str | None,
    ) -> tuple[ChallengeWorkspace | None, str | None, list[str]]:
        if targets is None or targets == [] or targets == "-":
            return None, active_text, []

        if isinstance(targets, (str, Path)):
            targets = [targets]

        real_targets: list[Path] = []
        missing_paths: list[str] = []
        literal_strings: list[str] = []

        for t in targets:
            if isinstance(t, Path):
                try:
                    p = t.expanduser().resolve()
                except Exception:
                    p = t.resolve()
                if p.exists():
                    real_targets.append(p)
                else:
                    missing_paths.append(str(t))
                continue

            s = str(t).strip()
            try:
                p = Path(s).expanduser().resolve()
                if p.exists():
                    real_targets.append(p)
                elif cls._is_path_like(s):
                    missing_paths.append(s)
                else:
                    literal_strings.append(s)
            except Exception:
                if cls._is_path_like(s):
                    missing_paths.append(s)
                else:
                    literal_strings.append(s)

        if real_targets:
            ws = ChallengeWorkspace.load(real_targets)
            return ws, active_text, missing_paths

        if literal_strings:
            combined_text = " ".join(literal_strings)
            return None, combined_text, missing_paths

        return None, active_text, missing_paths

    @classmethod
    def _record_ingestion(
        cls,
        workspace: ChallengeWorkspace | None,
        active_text: str | None,
        trace: DeductionTrace,
        missing_paths: list[str] | None = None,
    ) -> None:
        details = []
        if missing_paths:
            for mp in missing_paths:
                details.append(f"Target path not found: {mp}")
            if not workspace and not active_text:
                trace.add_step("INGESTION", "Target path(s) not found", details, status="failed")
                return

        if workspace and workspace.files:
            for wf in workspace.files:
                details.append(f"Loaded: {wf.relative_path} ({wf.category.value}, {wf.size} B)")
            trace.add_step("INGESTION", f"Workspace loaded {len(workspace.files)} file(s)", details)
        elif active_text:
            details.append(f"Loaded {len(active_text)} characters from text / stdin")
            trace.add_step("INGESTION", "Raw text target ingested", details)
        else:
            details.append(
                "Provide challenge file(s), folder, or text: 'solve <path>' or load a target with 'load <path>'."
            )
            trace.add_step(
                "INGESTION", "No input files or text provided", details, status="warning"
            )

    @classmethod
    def _record_harvesting(cls, params: HarvestedParameters, trace: DeductionTrace) -> None:
        details = []
        for name, n in params.moduli:
            details.append(f"{name} = {n} ({n.bit_length()}-bit modulus)")
        for name, c in params.ciphertexts:
            details.append(f"{name} = {c} ({c.bit_length()}-bit ciphertext)")
        for name, e in params.exponents:
            details.append(f"{name} = {e}")
        for name, p in params.primes:
            details.append(f"{name} = {p} ({p.bit_length()}-bit prime)")
        for name, k in params.keys:
            details.append(f"{name} = {k}")
        for name, mat in params.matrices:
            details.append(f"{name} = matrix ({len(mat)}x{len(mat[0]) if mat else 0})")
        for name, vec in params.vectors:
            details.append(f"{name} = vector ({len(vec)} elements)")
        for name, ct in params.cipher_tuples:
            details.append(f"{name} = cipher tuple ({len(ct)} elements)")
        for jwt in params.jwts:
            details.append(f"JWT = {jwt[:30]}... ({len(jwt)} chars)")

        title = f"Harvested {len(params.moduli)} moduli, {len(params.ciphertexts)} ciphertexts, {len(params.matrices)} matrices, {len(params.vectors)} vectors"
        trace.add_step("PARAMETER HARVESTING", title, details)

    # =========================================================================
    # 1. Lattice & Post-Quantum Cryptanalysis (LWE, CVP, Knapsack)
    # =========================================================================

    @classmethod
    def _solve_lattice_lwe(cls, params: HarvestedParameters, trace: DeductionTrace) -> bool:
        """Solves LWE and Knapsack cryptosystems via dual-kernel lattice reduction and CVP."""
        A: list[list[int]] | None = None
        B: list[int] | None = None
        q: int | None = None
        ct0: list[int] | None = None
        ct1: int | None = None

        # 1. Extract A and B from pk or matrices/vectors
        pk = params.all_vars.get("pk")
        if isinstance(pk, (tuple, list)) and len(pk) == 2:
            mat_cand, vec_cand = pk[0], pk[1]
            if isinstance(vec_cand, (list, tuple)) and all(isinstance(x, int) for x in vec_cand):
                B = [int(x) for x in vec_cand]
                m = len(B)
                if m > 0:
                    if isinstance(mat_cand, (list, tuple)):
                        if all(isinstance(r, (list, tuple)) for r in mat_cand):
                            A = [[int(x) for x in r] for r in mat_cand]
                        elif all(isinstance(x, int) for x in mat_cand) and len(mat_cand) % m == 0:
                            n = len(mat_cand) // m
                            A = [[int(mat_cand[i * n + j]) for j in range(n)] for i in range(m)]

        if A is None or B is None:
            for m_name, mat in params.matrices:
                for v_name, vec in params.vectors:
                    if len(mat) == len(vec) and len(mat) > 0 and len(mat[0]) > 0:
                        A = mat
                        B = vec
                        break
                if A is not None:
                    break

        if A is None or B is None:
            vec_dict = dict(params.vectors)
            if "pk_1" in vec_dict and "pk_2" in vec_dict:
                v1, v2 = vec_dict["pk_1"], vec_dict["pk_2"]
                if len(v2) > 0 and len(v1) % len(v2) == 0:
                    m = len(v2)
                    n = len(v1) // m
                    A = [[int(v1[i * n + j]) for j in range(n)] for i in range(m)]
                    B = v2

        if not A or not B or len(A) != len(B):
            return False

        m = len(A)
        n = len(A[0]) if m > 0 else 0
        if m < 4 or n < 2:
            return False

        # 2. Extract ciphertext ct0, ct1
        ct_cand = params.all_vars.get("ct") or params.all_vars.get("c")
        if not ct_cand and params.cipher_tuples:
            for c_name, c_val in params.cipher_tuples:
                if c_name.lower() in ("ct", "c", "ciphertext", "cipher"):
                    ct_cand = c_val
                    break
            if not ct_cand:
                ct_cand = params.cipher_tuples[0][1]

        if isinstance(ct_cand, (tuple, list)) and len(ct_cand) == 2:
            c0, c1 = ct_cand[0], ct_cand[1]
            if isinstance(c0, (list, tuple)) and isinstance(c1, int):
                ct0 = [int(x) for x in c0]
                ct1 = int(c1)
            elif isinstance(c1, (list, tuple)) and isinstance(c0, int):
                ct0 = [int(x) for x in c1]
                ct1 = int(c0)

        # 3. Extract modulus q
        if "q" in params.all_vars and isinstance(params.all_vars["q"], int):
            q = int(params.all_vars["q"])
        else:
            for mod_name, mod_val in params.moduli:
                if "q" in mod_name.lower():
                    q = mod_val
                    break

        if q is None:
            max_b = max(abs(x) for x in B)
            if ct1:
                max_b = max(max_b, abs(ct1))
            bl = max_b.bit_length()
            for cand_bits in (128, 256, 384, 512, 768, 1024, 2048):
                if cand_bits - 16 <= bl <= cand_bits:
                    q = 2**cand_bits
                    break
            if q is None:
                q = 2**bl

        trace.add_step(
            "ATTACK DEDUCTION",
            f"Lattice/LWE Cryptosystem detected (A: {m}x{n}, B: {m}, q: {q.bit_length()}-bit)",
            [f"Ciphertext present: {bool(ct0 is not None and ct1 is not None)}"],
        )

        try:
            res = solve_lwe_dual_kernel(A, B, q, ct0, ct1)
            if res.get("flag") and not is_placeholder_flag(res["flag"]):
                trace.solved = True
                trace.flag = res["flag"]
                trace.attack_name = "LWE Dual-Kernel Lattice Reduction"
                trace.add_step(
                    "ATTACK EXECUTION",
                    "Dual-kernel LLL reduction and Kannan embedding recovered flag",
                    [
                        f"Flag: {res['flag']}",
                        f"Private Key sk: {res.get('sk')}",
                        f"Prime p: {res.get('p')}",
                    ],
                )
                return True
            elif res.get("pt"):
                pt_str = int_to_text(res["pt"])
                is_valid, found_flag = check_plaintext(pt_str)
                if is_valid:
                    trace.solved = True
                    trace.flag = found_flag or pt_str
                    trace.attack_name = "LWE Dual-Kernel Lattice Reduction"
                    trace.add_step(
                        "ATTACK EXECUTION",
                        "LWE recovered plaintext message",
                        [f"Plaintext: {pt_str}"],
                    )
                    return True
        except Exception:
            pass

        return False

    # =========================================================================
    # 2. RSA Attack Suite
    # =========================================================================

    @classmethod
    def _solve_rsa(cls, params: HarvestedParameters, trace: DeductionTrace) -> bool:
        # Prioritize explicitly named moduli ('n', 'modulus') over generic/unlabeled integers
        explicit_moduli = [
            n for name, n in params.moduli if any(k in name.lower() for k in ("n", "mod"))
        ]
        other_moduli = [n for name, n in params.moduli if n not in explicit_moduli]
        moduli = list(dict.fromkeys(explicit_moduli + other_moduli))
        ciphertexts = params.get_ciphertexts()
        exponents = params.get_exponents()

        if not moduli:
            return False

        # 1. Shared Factor Attack (gcd(N_i, N_j) > 1)
        if len(moduli) >= 2:
            trace.add_step(
                "ATTACK DEDUCTION",
                "Checking for shared prime factors between moduli (Pairwise GCD)",
            )
            gcd_moduli = moduli[:30]
            for i in range(len(gcd_moduli)):
                for j in range(i + 1, len(gcd_moduli)):
                    n1, n2 = gcd_moduli[i], gcd_moduli[j]
                    g = math.gcd(n1, n2)
                    if 1 < g < n1:
                        # Shared factor identified!
                        q = g
                        trace.add_step(
                            "ATTACK DEDUCTION",
                            "RSA Common Factor identified (Shared Prime)",
                            [
                                f"Shared factor q = gcd(N_{i + 1}, N_{j + 1}) = {q} ({q.bit_length()}-bit prime)",
                                f"N_{i + 1} factored: p1 = N_{i + 1} // q ({(n1 // q).bit_length()}-bit)",
                                f"N_{j + 1} factored: p2 = N_{j + 1} // q ({(n2 // q).bit_length()}-bit)",
                            ],
                        )

                        # Decrypt all ciphertexts against n1 and n2
                        recovered_pts = []
                        best_flag = None
                        for ct in ciphertexts:
                            for target_n, target_p in [(n1, n1 // q), (n2, n2 // q)]:
                                for e in exponents:
                                    try:
                                        phi = (target_p - 1) * (q - 1)
                                        d = mod_inverse(e, phi)
                                        m = pow(ct, d, target_n)
                                        pt_str = int_to_text(m)
                                        f = extract_flag(pt_str)
                                        is_real_flag = bool(f and not is_placeholder_flag(f))
                                        is_valid_text = bool(
                                            pt_str
                                            and printable_ratio(pt_str.encode()) > 0.85
                                            and english_score(pt_str) > 0.25
                                        )

                                        if is_real_flag or is_valid_text:
                                            if pt_str not in recovered_pts:
                                                recovered_pts.append(pt_str)
                                            if is_real_flag:
                                                best_flag = f
                                    except Exception:
                                        continue

                        if recovered_pts:
                            trace.solved = True
                            trace.candidate_plaintexts = recovered_pts
                            trace.flag = best_flag or (recovered_pts[0] if recovered_pts else None)
                            trace.attack_name = "RSA Common Factor (Shared Prime)"
                            trace.add_step(
                                "ATTACK EXECUTION",
                                "Decrypted ciphertext(s) using recovered factors and private keys",
                                [f"Recovered text: {p}" for p in recovered_pts],
                            )
                            return True

        # 2. Small Prime Factor & Smooth Modulus Component Attack (Smooth RSA / B-smooth N)
        for n in moduli[:5]:
            small_factors = find_small_prime_factors(n, max_prime_bits=24)
            if small_factors:
                trace.add_step(
                    "ATTACK DEDUCTION",
                    "Checking for small prime factors and smooth modulus components (Sieve & Batch GCD)",
                )
                n_small = 1
                phi_small = 1
                for p, count in small_factors.items():
                    n_small *= p**count
                    phi_small *= (p - 1) * (p ** (count - 1))

                rem = n // n_small
                is_full = rem == 1 or is_prime(rem)
                phi_total = phi_small * ((rem - 1) if rem > 1 else 1)

                details = [
                    f"Recovered {len(small_factors)} small prime factor(s): {list(small_factors.keys())[:8]}{'...' if len(small_factors) > 8 else ''}",
                    f"N_small = {n_small.bit_length()}-bit component (out of {n.bit_length()}-bit modulus)",
                ]
                if is_full:
                    details.append(
                        f"Full modulus factorization achieved! Remainder is {'1' if rem == 1 else f'prime ({rem.bit_length()} bits)'}"
                    )
                else:
                    details.append(
                        "Partial smooth component detected (evaluating m < N_small recovery)"
                    )

                trace.add_step(
                    "ATTACK DEDUCTION",
                    "RSA Small Prime Factor component identified",
                    details,
                )

                target_moduli = []
                if is_full:
                    target_moduli.append((n, phi_total, "Full Modulus Factorization"))
                target_moduli.append((n_small, phi_small, "Partial Modulus Component"))

                for tgt_n, tgt_phi, attack_label in target_moduli:
                    for e in exponents:
                        try:
                            if math.gcd(e, tgt_phi) == 1:
                                d = mod_inverse(e, tgt_phi)
                                for c in ciphertexts:
                                    m = pow(c, d, tgt_n)
                                    pt_str = int_to_text(m)
                                    trace.candidate_plaintexts.append(pt_str)
                                    is_valid, found_flag = check_plaintext(pt_str)
                                    if is_valid:
                                        trace.solved = True
                                        trace.flag = found_flag or pt_str
                                        trace.attack_name = (
                                            f"RSA Small Prime Factor ({attack_label})"
                                        )
                                        trace.add_step(
                                            "ATTACK EXECUTION",
                                            f"Decrypted ciphertext using {attack_label.lower()}",
                                            [f"Recovered text: {pt_str}"],
                                        )
                                        return True
                        except Exception:
                            continue

        # 3. Common Modulus Attack (same N, different e1 and e2)
        if len(exponents) >= 2 and len(ciphertexts) >= 2:
            trace.add_step(
                "ATTACK DEDUCTION",
                "Checking for RSA Common Modulus vulnerability (Coprime exponents e1, e2)",
            )
            for n in moduli[:5]:
                for idx_e1 in range(len(exponents)):
                    for idx_e2 in range(idx_e1 + 1, len(exponents)):
                        e1, e2 = exponents[idx_e1], exponents[idx_e2]
                        if math.gcd(e1, e2) == 1:
                            for idx_c1 in range(len(ciphertexts)):
                                for idx_c2 in range(idx_c1 + 1, len(ciphertexts)):
                                    c1, c2 = ciphertexts[idx_c1], ciphertexts[idx_c2]
                                    try:
                                        m = common_modulus_attack(n, e1, e2, c1, c2)
                                        pt_str = int_to_text(m)
                                        trace.candidate_plaintexts.append(pt_str)
                                        is_valid, found_flag = check_plaintext(pt_str)
                                        if is_valid:
                                            trace.solved = True
                                            trace.flag = found_flag or pt_str
                                            trace.attack_name = "RSA Common Modulus Attack"
                                            trace.add_step(
                                                "ATTACK EXECUTION",
                                                "Recovered plaintext via Extended Euclidean linear combination",
                                                [f"Recovered text: {pt_str}"],
                                            )
                                            return True
                                    except Exception:
                                        continue

        # 3. Small Public Exponent / Direct Integer Root (m^e < N)
        trace.add_step(
            "ATTACK DEDUCTION",
            "Testing for Small Public Exponent unpadded direct root (m^e < N)",
        )
        for e in exponents:
            if e in (3, 5, 7, 17):
                for c in ciphertexts:
                    root = integer_nth_root(c, e)
                    if root is not None:
                        pt_str = int_to_text(root)
                        trace.candidate_plaintexts.append(pt_str)
                        is_valid, found_flag = check_plaintext(pt_str)
                        if is_valid:
                            trace.solved = True
                            trace.flag = found_flag or pt_str
                            trace.attack_name = f"RSA Direct Root (Small e={e})"
                            trace.add_step(
                                "ATTACK EXECUTION",
                                f"Extracted exact integer {e}-th root of ciphertext",
                                [f"Plaintext: {pt_str}"],
                            )
                            return True

        # 4. Wiener's Continued Fraction Attack (Small private exponent d)
        trace.add_step(
            "ATTACK DEDUCTION",
            "Testing for Small Private Exponent via Wiener's continued fractions",
        )
        for n in moduli[:5]:
            for e in exponents:
                d = wiener_attack(n, e)
                if d is not None:
                    trace.add_step(
                        "ATTACK EXECUTION",
                        "Wiener's attack succeeded! Recovered private exponent d",
                        [f"d = {d}"],
                    )
                    for c in ciphertexts:
                        m = pow(c, d, n)
                        pt_str = int_to_text(m)
                        trace.candidate_plaintexts.append(pt_str)
                        is_valid, found_flag = check_plaintext(pt_str)
                        if is_valid:
                            trace.solved = True
                            trace.flag = found_flag or pt_str
                            trace.attack_name = "RSA Wiener's Continued Fraction Attack"
                            return True

        # 5. Hastad's Broadcast Attack
        for e in exponents:
            if e in (3, 5, 7) and len(moduli) >= e and len(ciphertexts) >= e:
                trace.add_step(
                    "ATTACK DEDUCTION",
                    f"Testing Hastad's Broadcast attack with {e} moduli and e={e}",
                )
                try:
                    m = hastad_broadcast_attack(ciphertexts[:e], moduli[:e], e)
                    pt_str = int_to_text(m)
                    trace.candidate_plaintexts.append(pt_str)
                    is_valid, found_flag = check_plaintext(pt_str)
                    if is_valid:
                        trace.solved = True
                        trace.flag = found_flag or pt_str
                        trace.attack_name = f"RSA Hastad's Broadcast Attack (e={e})"
                        return True
                except Exception:
                    pass

        # 6. General Factorization & Auto Attack
        trace.add_step(
            "ATTACK DEDUCTION",
            "Attempting algebraic factorization (Fermat, Pollard's p-1, Pollard's rho)",
        )
        for n in moduli[:3]:
            factors = factor(n)
            if factors:
                p, q = factors
                phi = (p - 1) * (q - 1)
                for e in exponents:
                    try:
                        d = mod_inverse(e, phi)
                        for c in ciphertexts:
                            m = pow(c, d, n)
                            pt_str = int_to_text(m)
                            trace.candidate_plaintexts.append(pt_str)
                            is_valid, found_flag = check_plaintext(pt_str)
                            if is_valid:
                                trace.solved = True
                                trace.flag = found_flag or pt_str
                                trace.attack_name = "RSA Factorization / Auto Attack"
                                trace.add_step(
                                    "ATTACK EXECUTION",
                                    "Factored modulus and decrypted ciphertext",
                                    [f"Plaintext: {pt_str}"],
                                )
                                return True
                    except Exception:
                        continue

        return False

    # =========================================================================
    # 3. Classical Cryptanalysis Suite
    # =========================================================================

    @classmethod
    def _solve_classical_crypto(
        cls,
        params: HarvestedParameters,
        workspace: ChallengeWorkspace | None,
        active_text: str | None,
        trace: DeductionTrace,
    ) -> bool:
        candidate_texts: list[str] = []
        if active_text:
            candidate_texts.append(active_text)
        for _, val in params.all_vars.items():
            if isinstance(val, str) and 6 <= len(val) <= 2000:
                candidate_texts.append(val)
        for s in params.strings:
            if 6 <= len(s) <= 2000:
                candidate_texts.append(s)
        if workspace:
            for tf in workspace.source_files + workspace.log_files:
                candidate_texts.append(tf.text)

        seen = set()
        unique_texts = []
        for t in candidate_texts:
            clean = t.strip()
            if clean and clean not in seen:
                seen.add(clean)
                unique_texts.append(clean)

        for text in unique_texts:
            res = solve_classical(text)
            if res.get("solved") and res.get("flag") and not is_placeholder_flag(res["flag"]):
                trace.solved = True
                trace.flag = res["flag"]
                trace.attack_name = f"Classical Cryptanalysis: {res.get('method')}"
                trace.add_step(
                    "ATTACK EXECUTION",
                    f"Solved classical cipher using {res.get('method')}",
                    [f"Plaintext: {res.get('plaintext', '')[:100]}", f"Flag: {res['flag']}"],
                )
                return True
        return False

    # =========================================================================
    # 4. Modern & Symmetric Cryptanalysis Suite
    # =========================================================================

    @classmethod
    def _solve_modern_crypto(
        cls,
        params: HarvestedParameters,
        workspace: ChallengeWorkspace | None,
        active_text: str | None,
        trace: DeductionTrace,
    ) -> bool:
        candidate_bytes: list[bytes] = []
        if active_text:
            try:
                candidate_bytes.append(bytes.fromhex(active_text.strip()))
            except Exception:
                if len(active_text) <= 512 and not any(
                    k in active_text for k in ("def ", "class ", "import ", " = ")
                ):
                    candidate_bytes.append(active_text.encode("latin-1"))

        for _, val in params.all_vars.items():
            if isinstance(val, bytes) and 4 <= len(val) <= 4096:
                candidate_bytes.append(val)
            elif isinstance(val, str) and 8 <= len(val) <= 4096:
                try:
                    candidate_bytes.append(bytes.fromhex(val.strip()))
                except Exception:
                    pass

        if workspace:
            for wf in workspace.log_files:
                try:
                    candidate_bytes.append(bytes.fromhex(wf.text.strip()))
                except Exception:
                    pass

        for b in candidate_bytes:
            if len(b) < 4:
                continue

            # OpenSSL Salted__ encrypted payload parameter crack
            if b.startswith(b"Salted__"):
                try:
                    from ichnos.crypto.symmetric.openssl_brute import crack_openssl_params

                    cr_results = crack_openssl_params(
                        b,
                        workers=2,
                        ciphers=["aes-256-cbc", "aes-128-cbc"],
                        digests=["sha256", "md5"],
                    )
                    for cr in cr_results:
                        f = extract_flag(cr.plaintext.decode(errors="replace"))
                        if f and not is_placeholder_flag(f):
                            trace.solved = True
                            trace.flag = f
                            trace.attack_name = f"OpenSSL Parameter Crack ({cr.cipher}/{cr.digest})"
                            trace.add_step(
                                "ATTACK EXECUTION",
                                f"Recovered OpenSSL encryption parameters: {cr.label}",
                                [f"Flag: {f}", f"Plaintext: {cr.plaintext[:64]!r}"],
                            )
                            return True
                except Exception:
                    pass

            # Single byte XOR brute force (sample first 512 bytes for speed)
            b_sample = b[:512]
            try:
                cands = xor_single_brute(b_sample)
                for cand in cands[:3]:
                    text = cand.decoded_str
                    f = extract_flag(text)
                    if f and not is_placeholder_flag(f):
                        trace.solved = True
                        trace.flag = f
                        trace.attack_name = f"Single-Byte XOR (key={cand.key})"
                        trace.add_step(
                            "ATTACK EXECUTION",
                            f"Decrypted single-byte XOR with key {cand.key}",
                            [f"Flag: {f}"],
                        )
                        return True
            except Exception:
                pass

            # Repeating key XOR crack (sample first 1024 bytes for speed)
            if len(b) >= 20:
                try:
                    cand = xor_repeat_crack(b[:1024])
                    if cand and cand.decoded_str:
                        f = extract_flag(cand.decoded_str)
                        if f and not is_placeholder_flag(f):
                            trace.solved = True
                            trace.flag = f
                            trace.attack_name = f"Repeating-Key XOR (key={cand.key!r})"
                            trace.add_step(
                                "ATTACK EXECUTION",
                                f"Cracked repeating-key XOR with key {cand.key!r}",
                                [f"Flag: {f}"],
                            )
                            return True
                except Exception:
                    pass

        # Discrete Logarithm
        if params.dlog and all(k in params.dlog for k in ("g", "h", "p")):
            try:
                g, h, p = params.dlog["g"], params.dlog["h"], params.dlog["p"]
                if p < 10**14:
                    x = discrete_log(g, h, p)
                    if x is not None:
                        pt_str = int_to_text(x)
                        is_valid, f = check_plaintext(pt_str)
                        if is_valid:
                            trace.solved = True
                            trace.flag = f or pt_str
                            trace.attack_name = "Discrete Logarithm (BSGS)"
                            trace.add_step(
                                "ATTACK EXECUTION",
                                f"Solved discrete log: {g}^x = {h} (mod {p})",
                                [f"Recovered x: {x}", f"Plaintext: {pt_str}"],
                            )
                            return True
            except Exception:
                pass

        # ---------------------------------------------------------------
        # PRNG / LCG Timestamp-Seeded Brute-Force Attack
        # Detects `lcg(s) = (a*s + b) % m` patterns with `time.time()` seeds.
        # ---------------------------------------------------------------
        if workspace:
            import os
            import re as re_mod

            lcg_regex = re_mod.compile(
                r"\(\s*(\d+)\s*\*\s*(?:int\s*\(\s*)?[a-zA-Z_]\w*(?:\s*\))?\s*\+\s*(\d+)\s*\)\s*%\s*"
                r"(?:\(\s*2\s*\*\*\s*(\d+)\s*\)|(\d+))"
            )
            range_regex = re_mod.compile(r"for\s+\w+\s+in\s+range\s*\(\s*(\d+)\s*\)")
            time_regex = re_mod.compile(r"time\.time\(\)")

            for wf in workspace.files:
                if wf.category != FileCategory.SOURCE_CODE:
                    continue
                src = wf.text
                if not src:
                    continue

                lcg_match = lcg_regex.search(src)
                time_match = time_regex.search(src)
                if not lcg_match or not time_match:
                    continue

                lcg_a = int(lcg_match.group(1))
                lcg_b = int(lcg_match.group(2))
                if lcg_match.group(3):
                    lcg_m = 2 ** int(lcg_match.group(3))
                else:
                    lcg_m = int(lcg_match.group(4))

                range_match = range_regex.search(src)
                iterations = int(range_match.group(1)) if range_match else 1

                # Resolve ciphertext from harvested parameters
                ct_hex: str | None = None
                for name in ("ct", "c", "enc", "ciphertext", "cipher"):
                    val = params.all_vars.get(name)
                    if isinstance(val, str) and re_mod.fullmatch(r"[0-9a-fA-F]{32,}", val):
                        ct_hex = val
                        break
                    if isinstance(val, int) and val > 0:
                        h = hex(val)[2:]
                        if len(h) % 2:
                            h = "0" + h
                        ct_hex = h
                        break

                if not ct_hex:
                    continue

                try:
                    ct_bytes = bytes.fromhex(ct_hex)
                except Exception:
                    continue

                # Use file mtime as reference timestamp; fallback to current time if 0 or stale
                ref_time = None
                try:
                    mtime = os.path.getmtime(str(wf.path))
                    if mtime > 1000000000:
                        ref_time = mtime
                except Exception:
                    pass
                if not ref_time or ref_time < 1000000000:
                    import time as time_mod
                    ref_time = time_mod.time()

                trace.add_step(
                    "ATTACK DEDUCTION",
                    f"Detected LCG pattern: s = ({lcg_a} * s + {lcg_b}) % {lcg_m}, "
                    f"iterated {iterations} times with time.time() seed",
                    [f"Ciphertext: {ct_hex[:64]}...", f"Reference timestamp: {int(ref_time)}"],
                )

                try:
                    from ichnos.crypto.prng.lcg import crack_time_seeded_lcg

                    result = crack_time_seeded_lcg(
                        ct_bytes, lcg_a, lcg_b, lcg_m, iterations,
                        ref_time=ref_time, search_window=2000000,
                    )
                    if result is not None:
                        winning_t, winning_seed, key, flag_text = result
                        trace.solved = True
                        trace.flag = flag_text
                        trace.attack_name = "PRNG Timestamp Brute-Force (LCG + AES-ECB)"
                        trace.add_step(
                            "ATTACK EXECUTION",
                            "Recovered AES key via LCG timestamp search",
                            [
                                f"Winning timestamp: {winning_t}",
                                f"Winning seed: {winning_seed}",
                                f"Flag: {flag_text}",
                            ],
                        )
                        return True
                except Exception:
                    pass

        return False

    # =========================================================================
    # 5. Steganography & Metadata Analysis Suite
    # =========================================================================

    @classmethod
    def _solve_stego(cls, workspace: ChallengeWorkspace, trace: DeductionTrace) -> bool:
        # Check all workspace files for ASS vector subtitle files
        for f in workspace.files:
            if (
                f.path.suffix.lower() == ".ass"
                or b"[Script Info]" in f.data
                or b"\\p1" in f.data
            ):
                try:
                    from ichnos.stego.ass_subtitle import decode_ass_qr

                    qr_text = decode_ass_qr(f.text)
                    if qr_text:
                        flag = extract_flag(qr_text) or qr_text.strip()
                        if flag and not is_placeholder_flag(flag):
                            trace.solved = True
                            trace.flag = flag
                            trace.attack_name = "ASS Subtitle Vector QR Extraction"
                            trace.add_step(
                                "ATTACK EXECUTION",
                                f"Extracted QR code vector drawings from {f.relative_path}",
                                [f"Decoded QR payload: {qr_text}"],
                            )
                            return True
                except Exception:
                    pass

        media_files = workspace.media_files
        if not media_files:
            return False

        trace.add_step(
            "ATTACK DEDUCTION",
            f"Scanning {len(media_files)} media file(s) for EXIF metadata & steganography",
        )

        for mf in media_files:
            # 1. Native EXIF analysis
            try:
                exif_data = extract_exif_from_image(mf.data)
                for tag_name, val in exif_data.items():
                    val_str = str(val)
                    flag = extract_flag(val_str)
                    if flag and not is_placeholder_flag(flag):
                        trace.solved = True
                        trace.flag = flag
                        trace.attack_name = f"EXIF Metadata Extraction ({tag_name})"
                        trace.add_step(
                            "ATTACK EXECUTION",
                            f"Discovered flag in EXIF tag '{tag_name}' of {mf.relative_path}",
                            [f"Value: {val_str}"],
                        )
                        return True
            except Exception:
                pass

            # 2. PNG LSB Analysis & Dimension Repair
            if mf.data.startswith(b"\x89PNG\r\n\x1a\n"):
                # Dimension repair check (corrupted height/CRC mismatch)
                try:
                    from ichnos.stego.image.repair import (
                        detect_ihdr_crc_mismatch,
                        repair_png_dimensions,
                    )

                    if detect_ihdr_crc_mismatch(mf.data):
                        repaired_data, info = repair_png_dimensions(mf.data)
                        if info.get("repaired"):
                            trace.add_step(
                                "ATTACK DEDUCTION",
                                f"Detected and repaired PNG dimension tampering in {mf.relative_path}",
                                [f"Height: {info.get('original_height')} -> {info.get('correct_height')}"],
                            )
                except Exception:
                    pass

                try:
                    from ichnos.stego.image.lsb import brute_force_lsb

                    lsb_cands = brute_force_lsb(mf.data, max_results=10)
                    for cand in lsb_cands:
                        flag = extract_flag(cand.decoded_str)
                        if flag and not is_placeholder_flag(flag):
                            trace.solved = True
                            trace.flag = flag
                            trace.attack_name = f"PNG LSB Steganography ({cand.method})"
                            trace.add_step(
                                "ATTACK EXECUTION",
                                f"Recovered flag from PNG LSB in {mf.relative_path}",
                                [f"Flag: {flag}", f"Method: {cand.method}"],
                            )
                            return True
                except Exception:
                    pass

            # 3. Audio DTMF Keypad Tone Decoding
            if mf.data.startswith(b"RIFF") or mf.path.suffix.lower() in (".wav", ".wave"):
                try:
                    from ichnos.stego.audio.dtmf import decode_wav_dtmf

                    dtmf_str = decode_wav_dtmf(mf.data)
                    if dtmf_str:
                        flag = extract_flag(dtmf_str)
                        if flag and not is_placeholder_flag(flag):
                            trace.solved = True
                            trace.flag = flag
                            trace.attack_name = "Audio DTMF Tone Decoding"
                            trace.add_step(
                                "ATTACK EXECUTION",
                                f"Decoded DTMF tones in {mf.relative_path}",
                                [f"Digits: {dtmf_str}", f"Flag: {flag}"],
                            )
                            return True
                except Exception:
                    pass

        return False

    # =========================================================================
    # 6. Binary & Reverse Engineering Suite
    # =========================================================================

    @classmethod
    def _solve_binary(cls, workspace: ChallengeWorkspace, trace: DeductionTrace) -> bool:
        for wf in workspace.files:
            data = wf.data
            if not data or len(data) < 16:
                continue
            is_bin = (
                wf.category == FileCategory.BINARIES
                or data.startswith(
                    (
                        b"\x7fELF",
                        b"MZ",
                        b"\xca\xfe\xba\xbe",
                        b"\xcf\xfa\xed\xfe",
                        b"\xce\xfa\xed\xfe",
                    )
                )
                or (len(data) > 64 and printable_ratio(data) < 0.4)
            )
            if is_bin:
                try:
                    res = solve_binary(data, wf.path.name)
                    if (
                        res.get("solved")
                        and res.get("flag")
                        and not is_placeholder_flag(res["flag"])
                    ):
                        trace.solved = True
                        trace.flag = res["flag"]
                        trace.attack_name = f"Binary Analysis: {res.get('method')}"
                        trace.add_step(
                            "ATTACK EXECUTION",
                            f"Extracted flag from binary {wf.relative_path} ({res.get('method')})",
                            [f"Flag: {res['flag']}"] + res.get("findings", []),
                        )
                        return True
                except Exception:
                    pass
        return False

    # =========================================================================
    # 7. Forensics & Embedded File Carving Suite
    # =========================================================================

    @classmethod
    def _solve_forensics(cls, workspace: ChallengeWorkspace, trace: DeductionTrace) -> bool:
        for wf in workspace.files:
            data = wf.data

            # 1. ZIP Comments and Archive Inspection
            if wf.category == FileCategory.ARCHIVES or data.startswith(b"PK\x03\x04"):
                try:
                    comments = extract_comments(data)
                    for k, comment in comments.items():
                        if isinstance(comment, str):
                            flag = extract_flag(comment)
                            if flag and not is_placeholder_flag(flag):
                                trace.solved = True
                                trace.flag = flag
                                trace.attack_name = "ZIP Archive Comment Flag"
                                trace.add_step(
                                    "ATTACK EXECUTION",
                                    f"Discovered flag in ZIP comment '{k}' of {wf.relative_path}",
                                    [f"Comment: {comment}"],
                                )
                                return True
                except Exception:
                    pass

            # 2. Embedded File Carving (Native Binwalk)
            if len(data) > 128:
                try:
                    carved = carve_all(data)
                    if len(carved) > 1:
                        trace.add_step(
                            "ATTACK DEDUCTION",
                            f"Carver identified {len(carved)} embedded payload(s) in {wf.relative_path}",
                            [
                                f"Offset 0x{c['offset']:x}: {c['type']} ({c['size']} B)"
                                for c in carved
                            ],
                        )
                        for c in carved:
                            sub_data = data[c["offset"] : c["offset"] + c["size"]]
                            try:
                                sub_text = sub_data.decode("utf-8", errors="ignore")
                                flag = extract_flag(sub_text)
                                if flag and not is_placeholder_flag(flag):
                                    trace.solved = True
                                    trace.flag = flag
                                    trace.attack_name = f"Embedded File Carver ({c['type']})"
                                    trace.add_step(
                                        "ATTACK EXECUTION",
                                        f"Recovered flag from carved {c['type']} payload",
                                        [f"Flag: {flag}"],
                                    )
                                    return True
                            except Exception:
                                pass
                except Exception:
                    pass

            # 3. Acropalypse Image Recovery (CVE-2023-21036 / CVE-2023-28310)
            if data.startswith(b"\x89PNG\r\n\x1a\n") or data.startswith(b"\xff\xd8\xff"):
                try:
                    from ichnos.forensic.acropalypse import analyze_acropalypse

                    acro = analyze_acropalypse(data)
                    if acro.get("vulnerable"):
                        for payload in (acro.get("thumbnail"), acro.get("recovered_data")):
                            if payload:
                                flag = extract_flag(payload.decode("latin-1", errors="ignore"))
                                if flag and not is_placeholder_flag(flag):
                                    trace.solved = True
                                    trace.flag = flag
                                    trace.attack_name = "Acropalypse Image Recovery (CVE-2023-21036/28310)"
                                    trace.add_step(
                                        "ATTACK EXECUTION",
                                        f"Recovered uncropped flag data from Acropalypse flaw in {wf.relative_path}",
                                        [f"Flag: {flag}"],
                                    )
                                    return True
                except Exception:
                    pass

            # 4. PDF Object Stream & Hidden Text Forensics
            if data.startswith(b"%PDF"):
                try:
                    from ichnos.forensic.pdf import extract_text_objects, find_hidden_text

                    for txt in find_hidden_text(data) + extract_text_objects(data):
                        flag = extract_flag(txt)
                        if flag and not is_placeholder_flag(flag):
                            trace.solved = True
                            trace.flag = flag
                            trace.attack_name = "PDF Hidden Content Extraction"
                            trace.add_step(
                                "ATTACK EXECUTION",
                                f"Discovered hidden flag in PDF object stream of {wf.relative_path}",
                                [f"Flag: {flag}"],
                            )
                            return True
                except Exception:
                    pass

            # 5. Memory Dump & Process Environment Carving
            if len(data) > 64:
                try:
                    from ichnos.forensic.memory import carve_env_variables

                    envs = carve_env_variables(data)
                    for k, v in envs.items():
                        flag = extract_flag(f"{k}={v}") or extract_flag(v)
                        if flag and not is_placeholder_flag(flag):
                            trace.solved = True
                            trace.flag = flag
                            trace.attack_name = f"Environment Variable Carving ({k})"
                            trace.add_step(
                                "ATTACK EXECUTION",
                                f"Carved flag from environment variable '{k}' in {wf.relative_path}",
                                [f"Value: {v}", f"Flag: {flag}"],
                            )
                            return True
                except Exception:
                    pass

        return False

    # =========================================================================
    # 8. Network & PCAP Forensics
    # =========================================================================

    @classmethod
    def _solve_pcap(cls, workspace: ChallengeWorkspace, trace: DeductionTrace) -> bool:
        for wf in workspace.files:
            data = wf.data
            if not data or len(data) < 24:
                continue
            is_pcap = (
                wf.category == FileCategory.CAPTURES
                or data.startswith(
                    (
                        b"\xd4\xc3\xb2\xa1",
                        b"\xa1\xb2\xc3\xd4",
                        b"\x0a\x0d\x0d\x0a",
                        b"\x4d\x3c\xb2\xa1",
                        b"\xa1\xb2\x3c\x4d",
                    )
                )
                or wf.path.suffix.lower() in (".pcap", ".pcapng", ".cap")
            )
            if is_pcap:
                # 1. USB HID Keyboard Keystroke Reconstruction
                try:
                    from ichnos.pcap.usb import extract_usb_keyboard_data

                    usb_text = extract_usb_keyboard_data(data)
                    if usb_text:
                        flag = extract_flag(usb_text)
                        if flag and not is_placeholder_flag(flag):
                            trace.solved = True
                            trace.flag = flag
                            trace.attack_name = "USB HID Keyboard Keystroke Reconstruction"
                            trace.add_step(
                                "ATTACK EXECUTION",
                                f"Reconstructed typed keystrokes from USB capture {wf.relative_path}",
                                [f"Typed: {usb_text}", f"Flag: {flag}"],
                            )
                            return True
                except Exception:
                    pass

                try:
                    res = solve_pcap(data, wf.path.name)
                    if (
                        res.get("solved")
                        and res.get("flag")
                        and not is_placeholder_flag(res["flag"])
                    ):
                        trace.solved = True
                        trace.flag = res["flag"]
                        trace.attack_name = f"PCAP Forensics: {res.get('method')}"
                        trace.add_step(
                            "ATTACK EXECUTION",
                            f"Extracted flag from packet capture {wf.relative_path} ({res.get('method')})",
                            [f"Flag: {res['flag']}"] + res.get("findings", []),
                        )
                        return True
                except Exception:
                    pass
        return False

    # =========================================================================
    # 9. Web & Token Security
    # =========================================================================

    @classmethod
    def _solve_web_and_passwords(
        cls,
        params: HarvestedParameters,
        workspace: ChallengeWorkspace | None,
        active_text: str | None,
        trace: DeductionTrace,
    ) -> bool:
        candidate_web_sources: list[str | bytes] = []
        if active_text:
            candidate_web_sources.append(active_text)
        for jwt in params.jwts:
            candidate_web_sources.append(jwt)
        for _, val in params.all_vars.items():
            if isinstance(val, (str, bytes)):
                candidate_web_sources.append(val)
        if workspace:
            for tf in workspace.source_files + workspace.log_files:
                candidate_web_sources.append(tf.text)

        for src in candidate_web_sources:
            try:
                res = solve_web(src)
                if res.get("solved") and res.get("flag") and not is_placeholder_flag(res["flag"]):
                    trace.solved = True
                    trace.flag = res["flag"]
                    trace.attack_name = f"Web Security: {res.get('method')}"
                    trace.add_step(
                        "ATTACK EXECUTION",
                        f"Extracted flag via web security analysis ({res.get('method')})",
                        [f"Flag: {res['flag']}"] + res.get("findings", []),
                    )
                    return True
            except Exception:
                pass
        return False

    # =========================================================================
    # 10. Layered Decoders & Base Encodings Suite
    # =========================================================================

    @classmethod
    def _solve_layered_encodings(
        cls,
        params: HarvestedParameters,
        workspace: ChallengeWorkspace | None,
        active_text: str | None,
        trace: DeductionTrace,
    ) -> bool:
        # Collect candidate strings for layered decoding
        candidate_strings = []
        if active_text:
            candidate_strings.append(active_text)
        for _, val in params.all_vars.items():
            if isinstance(val, str) and len(val) >= 10:
                candidate_strings.append(val)
        if workspace:
            for lf in workspace.log_files:
                candidate_strings.append(lf.text)

        for text in candidate_strings:
            clean_text = text.strip()
            if not clean_text:
                continue

            candidates = auto_decode(clean_text, max_depth=6)
            for cand in candidates:
                decoded_text = cand.decoded_str
                flag = extract_flag(decoded_text)
                if flag:
                    trace.solved = True
                    trace.flag = flag
                    trace.attack_name = f"Layered Decoding: {' -> '.join(cand.layers)}"
                    trace.add_step(
                        "ATTACK EXECUTION",
                        f"Unlayered encoded text using sequence: {' -> '.join(cand.layers)}",
                        [f"Decoded flag: {flag}"],
                    )
                    return True

        return False

    @classmethod
    def _build_result(
        cls,
        trace: DeductionTrace,
        params: HarvestedParameters,
        status: str | None = None,
    ) -> Result:
        findings = []
        candidates = []

        if trace.solved and trace.flag:
            candidates.append(
                Candidate(
                    decoded=trace.flag,
                    method=trace.attack_name,
                    confidence=1.0,
                )
            )
            findings.append(
                Finding(
                    label=f"Flag Recovered: {trace.flag}",
                    confidence=1.0,
                    detail=f"Attack: {trace.attack_name}",
                    module="solve",
                )
            )
        elif trace.candidate_plaintexts:
            for i, cp in enumerate(trace.candidate_plaintexts[:5]):
                candidates.append(
                    Candidate(
                        decoded=cp,
                        method=trace.attack_name or f"Candidate {i + 1}",
                        confidence=0.8,
                    )
                )

        final_status = status or ("success" if trace.solved else "partial")

        from ichnos.core.models import DeductionStep
        from ichnos.core.pedagogy import get_pedagogical_note

        deduction_steps = [
            DeductionStep(
                label=s.title,
                detail="; ".join(s.details) if s.details else "",
                rationale=f"Phase: {s.phase}",
                intermediate_values={"phase": s.phase, "status": s.status},
            )
            for s in trace.steps
        ]
        learner_note = get_pedagogical_note(trace.attack_name or "CTF Deduction Pipeline")

        return Result(
            command="solve",
            input_summary=f"{len(params.sources)} source(s), {len(params.moduli)} modulus(es)",
            findings=findings,
            candidates=candidates,
            raw_output=trace.render_text(),
            status=final_status,
            steps=deduction_steps,
            learner_note=learner_note,
        )
