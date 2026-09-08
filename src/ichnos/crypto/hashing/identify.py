from __future__ import annotations

import re

from ichnos.core.models import Finding


def identify_hash(hash_str: str) -> list[Finding]:
    """Identify potential hash types based on length, format, and charset."""
    findings = []

    # Check format-based hashes first
    if hash_str.startswith("$2b$") or hash_str.startswith("$2a$") or hash_str.startswith("$2y$"):
        findings.append(
            Finding(
                label="bcrypt",
                confidence=1.0,
                detail="bcrypt hash",
                module="crypto",
                command_hint="hashcat -m 3200",
            )
        )
    elif hash_str.startswith("$6$"):
        findings.append(
            Finding(
                label="SHA-512 crypt",
                confidence=1.0,
                detail="SHA-512 crypt",
                module="crypto",
                command_hint="hashcat -m 1800",
            )
        )
    elif hash_str.startswith("$5$"):
        findings.append(
            Finding(
                label="SHA-256 crypt",
                confidence=1.0,
                detail="SHA-256 crypt",
                module="crypto",
                command_hint="hashcat -m 7400",
            )
        )
    elif hash_str.startswith("$1$"):
        findings.append(
            Finding(
                label="MD5 crypt",
                confidence=1.0,
                detail="MD5 crypt",
                module="crypto",
                command_hint="hashcat -m 500",
            )
        )
    elif hash_str.startswith("$argon2"):
        findings.append(
            Finding(
                label="Argon2",
                confidence=1.0,
                detail="Argon2 hash",
                module="crypto",
                command_hint="hashcat -m 25300",
            )
        )
    elif hash_str.startswith("$pbkdf2"):
        findings.append(
            Finding(
                label="PBKDF2",
                confidence=1.0,
                detail="PBKDF2 hash",
                module="crypto",
                command_hint="hashcat -m 7100",
            )
        )
    elif len(hash_str) == 13 and re.match(r"^[./a-zA-Z0-9]{13}$", hash_str):
        findings.append(
            Finding(
                label="DES crypt",
                confidence=0.7,
                detail="Traditional DES crypt",
                module="crypto",
                command_hint="hashcat -m 1500",
            )
        )

    # Check hex-based hashes
    if re.match(r"^[a-fA-F0-9]+$", hash_str):
        length = len(hash_str)
        if length == 32:
            findings.append(
                Finding(
                    label="MD5",
                    confidence=0.9,
                    detail="MD5 (or NTLM)",
                    module="crypto",
                    command_hint="hashcat -m 0",
                )
            )
            findings.append(
                Finding(
                    label="NTLM",
                    confidence=0.7,
                    detail="NTLM (or MD5)",
                    module="crypto",
                    command_hint="hashcat -m 1000",
                )
            )
        elif length == 40:
            findings.append(
                Finding(
                    label="SHA-1",
                    confidence=0.9,
                    detail="SHA-1",
                    module="crypto",
                    command_hint="hashcat -m 100",
                )
            )
        elif length == 64:
            findings.append(
                Finding(
                    label="SHA-256",
                    confidence=0.9,
                    detail="SHA-256",
                    module="crypto",
                    command_hint="hashcat -m 1400",
                )
            )
        elif length == 128:
            findings.append(
                Finding(
                    label="SHA-512",
                    confidence=0.9,
                    detail="SHA-512",
                    module="crypto",
                    command_hint="hashcat -m 1700",
                )
            )

    return findings
