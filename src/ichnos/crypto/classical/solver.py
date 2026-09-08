"""Unified Classical Cryptanalysis Dispatcher.

Evaluates candidate ciphertexts against all classical ciphers:
Caesar, Atbash, Affine, Vigenere, Rail Fence, and Substitution.
"""

from __future__ import annotations

from typing import Any

from ichnos.core.detection import english_score
from ichnos.core.harvester import FLAG_PATTERN
from ichnos.crypto.classical.affine import brute_force as affine_brute_force
from ichnos.crypto.classical.atbash import decode as atbash_decode
from ichnos.crypto.classical.caesar import auto_detect as caesar_auto_detect
from ichnos.crypto.classical.substitution import solve as substitution_solve
from ichnos.crypto.classical.transposition import (
    rail_fence_brute,
)
from ichnos.crypto.classical.vigenere import crack as vigenere_crack

KNOWN_PREFIXES = ("flag{", "ctf{", "nns{", "picoctf{", "htb{", "secuin{", "ductf{")


def extract_flags_from_text(text: str) -> list[str]:
    """Extracts CTF flags from decoded text, prioritizing standard prefixes."""
    matches = [m.group(0) for m in FLAG_PATTERN.finditer(text)]
    known = [m for m in matches if m.lower().startswith(KNOWN_PREFIXES)]
    if known:
        return known
    if english_score(text) > 0.85:
        return matches
    return []


def solve_classical(ciphertext: str) -> dict[str, Any]:
    """Runs automated cryptanalysis on classical ciphertext candidates.

    Returns dict with {solved: bool, method: str, key: Any, plaintext: str, flag: str | None}.
    """
    clean_text = ciphertext.strip()
    if len(clean_text) < 4:
        return {"solved": False}

    # 1. Caesar auto-detect
    try:
        caesar_res = caesar_auto_detect(clean_text)
        if caesar_res and caesar_res.decoded_str:
            flags = extract_flags_from_text(caesar_res.decoded_str)
            if flags:
                return {
                    "solved": True,
                    "method": f"Caesar (shift={caesar_res.key})",
                    "key": caesar_res.key,
                    "plaintext": caesar_res.decoded_str,
                    "flag": flags[0],
                }
            if english_score(caesar_res.decoded_str) > 0.85:
                return {
                    "solved": True,
                    "method": f"Caesar (shift={caesar_res.key})",
                    "key": caesar_res.key,
                    "plaintext": caesar_res.decoded_str,
                    "flag": None,
                }
    except Exception:
        pass

    # 2. Atbash
    try:
        atbash_res = atbash_decode(clean_text)
        flags = extract_flags_from_text(atbash_res)
        if flags:
            return {
                "solved": True,
                "method": "Atbash",
                "key": None,
                "plaintext": atbash_res,
                "flag": flags[0],
            }
        if english_score(atbash_res) > 0.85:
            return {
                "solved": True,
                "method": "Atbash",
                "key": None,
                "plaintext": atbash_res,
                "flag": None,
            }
    except Exception:
        pass

    # 3. Affine brute force
    try:
        affine_cands = affine_brute_force(clean_text)
        if affine_cands:
            top = affine_cands[0]
            flags = extract_flags_from_text(top.decoded_str)
            if flags:
                return {
                    "solved": True,
                    "method": f"Affine ({top.key})",
                    "key": top.key,
                    "plaintext": top.decoded_str,
                    "flag": flags[0],
                }
            if top.confidence > 0.88:
                return {
                    "solved": True,
                    "method": f"Affine ({top.key})",
                    "key": top.key,
                    "plaintext": top.decoded_str,
                    "flag": None,
                }
    except Exception:
        pass

    # 4. Vigenere cracking
    if len(clean_text) >= 15:
        try:
            vig_res = vigenere_crack(clean_text)
            if vig_res and vig_res.decoded_str:
                flags = extract_flags_from_text(vig_res.decoded_str)
                if flags:
                    return {
                        "solved": True,
                        "method": f"Vigenère (key={vig_res.key})",
                        "key": vig_res.key,
                        "plaintext": vig_res.decoded_str,
                        "flag": flags[0],
                    }
                if vig_res.confidence > 0.88:
                    return {
                        "solved": True,
                        "method": f"Vigenère (key={vig_res.key})",
                        "key": vig_res.key,
                        "plaintext": vig_res.decoded_str,
                        "flag": None,
                    }
        except Exception:
            pass

    # 5. Rail Fence
    try:
        rf_cands = rail_fence_brute(clean_text, max_rails=min(12, len(clean_text)))
        for cand in rf_cands[:5]:
            flags = extract_flags_from_text(cand.decoded_str)
            if flags:
                return {
                    "solved": True,
                    "method": f"Rail Fence (rails={cand.key})",
                    "key": cand.key,
                    "plaintext": cand.decoded_str,
                    "flag": flags[0],
                }
    except Exception:
        pass

    # 6. Substitution (if sufficiently long)
    if len(clean_text) >= 40:
        try:
            sub_cand = substitution_solve(clean_text, iterations=3000, restarts=3)
            if sub_cand and sub_cand.decoded_str:
                flags = extract_flags_from_text(sub_cand.decoded_str)
                if flags:
                    return {
                        "solved": True,
                        "method": f"Monoalphabetic Substitution ({sub_cand.key})",
                        "key": sub_cand.key,
                        "plaintext": sub_cand.decoded_str,
                        "flag": flags[0],
                    }
        except Exception:
            pass

    return {"solved": False}
