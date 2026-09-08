"""HTTP security headers auditing and posture analysis."""

from __future__ import annotations

import urllib.request
from typing import Any

SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security (HSTS)",
        "weight": 20,
        "description": "Enforces secure HTTPS connections.",
        "recommendation": "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy (CSP)",
        "weight": 25,
        "description": "Restricts sources of executable scripts, objects, and styles to prevent XSS.",
        "recommendation": "Configure a restrictive Content-Security-Policy header.",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "weight": 15,
        "description": "Protects against clickjacking by denying iframe embedding.",
        "recommendation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "weight": 10,
        "description": "Prevents MIME-type sniffing.",
        "recommendation": "Set 'X-Content-Type-Options: nosniff'.",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "weight": 10,
        "description": "Controls how much referrer information is sent with requests.",
        "recommendation": "Set 'Referrer-Policy: strict-origin-when-cross-origin'.",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "weight": 10,
        "description": "Restricts browser features like camera, microphone, geolocation.",
        "recommendation": "Set 'Permissions-Policy: geolocation=(), camera=(), microphone=()'.",
    },
    "x-permitted-cross-domain-policies": {
        "name": "X-Permitted-Cross-Domain-Policies",
        "weight": 5,
        "description": "Restricts Flash/PDF cross-domain policy files.",
        "recommendation": "Set 'X-Permitted-Cross-Domain-Policies: none'.",
    },
}

INFO_LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]


def audit_headers(headers: dict[str, str]) -> dict[str, Any]:
    """Audits HTTP headers dictionary and computes a security score and checklist."""
    headers_lower = {k.lower(): v for k, v in headers.items()}

    score = 0
    max_score = sum(h["weight"] for h in SECURITY_HEADERS.values())
    present: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    information_leaks: list[dict[str, str]] = []

    for key, meta in SECURITY_HEADERS.items():
        if key in headers_lower:
            val = headers_lower[key]
            score += meta["weight"]
            present.append(
                {
                    "header": meta["name"],
                    "key": key,
                    "value": val,
                    "status": "PASS",
                }
            )
        else:
            missing.append(
                {
                    "header": meta["name"],
                    "key": key,
                    "recommendation": meta["recommendation"],
                    "status": "MISSING",
                }
            )

    for leak_key in INFO_LEAK_HEADERS:
        if leak_key in headers_lower:
            information_leaks.append(
                {
                    "header": leak_key,
                    "value": headers_lower[leak_key],
                    "warning": f"Server technology disclosed via '{leak_key}' header",
                }
            )

    grade = (
        "A"
        if score >= 85
        else ("B" if score >= 70 else ("C" if score >= 50 else ("D" if score >= 30 else "F")))
    )

    return {
        "score": score,
        "max_score": max_score,
        "percentage": round((score / max_score) * 100, 1),
        "grade": grade,
        "present_headers": present,
        "missing_headers": missing,
        "information_leaks": information_leaks,
    }


def fetch_and_audit(url: str, timeout: float = 5.0) -> dict[str, Any]:
    """Fetches headers from live URL and audits them."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    req = urllib.request.Request(url, headers={"User-Agent": "Ichnos-Security-Toolkit/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        headers_dict = dict(resp.headers)
        result = audit_headers(headers_dict)
        result["url"] = url
        result["status_code"] = resp.status
        return result
