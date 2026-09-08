"""Automated Web and Application Security Analysis Module.

Detects and decodes JWT tokens, attempts alg:none signature bypasses,
extracts HTML comments/hidden inputs, and parses serialized payloads.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ichnos.core.harvester import FLAG_PATTERN
from ichnos.crypto.jwt import jwt_attack_none, jwt_decode
from ichnos.web.extract import extract_assets

# Regex for JWT pattern: eyJ... . eyJ... . ...
JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]*)?")


def solve_web(data: str | bytes) -> dict[str, Any]:
    """Runs automated web token, comment, and form vulnerability analysis."""
    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
    findings: list[str] = []
    found_flags: list[str] = []
    tokens_info: list[dict[str, Any]] = []

    # 1. JWT Token Detection and Analysis
    jwt_matches = JWT_PATTERN.findall(text)
    for token in jwt_matches:
        try:
            header, payload, _ = jwt_decode(token, verify=False)
            findings.append(f"Discovered JWT (alg={header.get('alg')})")

            # Check claims for flag
            payload_str = json.dumps(payload)
            for match in FLAG_PATTERN.finditer(payload_str):
                found_flags.append(match.group(0))

            # Generate alg: none forge candidate
            none_token = jwt_attack_none(token)
            tokens_info.append(
                {
                    "original": token,
                    "header": header,
                    "payload": payload,
                    "forged_none_token": none_token,
                }
            )
        except Exception:
            pass

    if found_flags:
        return {
            "solved": True,
            "flag": found_flags[0],
            "method": "JWT Payload Claim Extraction",
            "findings": findings,
            "tokens": tokens_info,
        }

    # 2. HTML Inspection (comments, hidden inputs)
    if "<html" in text.lower() or "<form" in text.lower() or "<!--" in text:
        try:
            assets = extract_assets(text)
            comments = assets.get("comments", [])
            for c in comments:
                for match in FLAG_PATTERN.finditer(c):
                    found_flags.append(match.group(0))

            forms = assets.get("forms", [])
            for form in forms:
                for inp in form.get("inputs", []):
                    val = inp.get("value", "")
                    for match in FLAG_PATTERN.finditer(val):
                        found_flags.append(match.group(0))

            if comments:
                findings.append(f"Extracted {len(comments)} HTML comment(s)")
            if forms:
                findings.append(f"Extracted {len(forms)} HTML form(s)")
        except Exception:
            pass

    if found_flags:
        return {
            "solved": True,
            "flag": found_flags[0],
            "method": "HTML Comment / Hidden Field Extraction",
            "findings": findings,
            "tokens": tokens_info,
        }

    # 3. Serialization Artifact Detection (PHP serialized or Pickle)
    if re.search(r'O:\d+:"[^"]+":\d+:{', text):
        findings.append("Detected PHP serialized object string")
    if "cos\nsystem\n" in text or "cposix\nsystem\n" in text:
        findings.append("Detected Python pickle code execution vector")

    return {
        "solved": False,
        "flag": None,
        "findings": findings,
        "tokens": tokens_info,
    }
