"""Memory dump and binary forensics carving tools.

Scans raw memory dumps, disk images, or arbitrary binary blobs for
security-relevant artefacts: PEM keys/certificates, environment variables,
shadow password hashes, URLs, email addresses, and IPv4 addresses.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# PEM key/certificate carving
# ---------------------------------------------------------------------------

_PEM_TYPES = (
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "CERTIFICATE",
    "PUBLIC KEY",
    "PRIVATE KEY",
)

# Build one compiled regex per PEM type.  The pattern matches the full PEM
# block including the BEGIN/END lines and base-64 body.
_PEM_PATTERNS: list[tuple[str, re.Pattern[bytes]]] = [
    (
        pem_type,
        re.compile(
            rb"-----BEGIN " + pem_type.encode() + rb"-----"
            rb"[\s\S]*?"
            rb"-----END " + pem_type.encode() + rb"-----",
        ),
    )
    for pem_type in _PEM_TYPES
]


def carve_pem_keys(data: bytes) -> list[dict]:
    """Scan for PEM-encoded keys and certificates.

    Recognised PEM types:

    - ``RSA PRIVATE KEY``
    - ``EC PRIVATE KEY``
    - ``OPENSSH PRIVATE KEY``
    - ``CERTIFICATE``
    - ``PUBLIC KEY``
    - ``PRIVATE KEY``

    Args:
        data: Raw binary data to scan.

    Returns:
        A list of dicts, each with:

        - **type** (*str*): The PEM type label (e.g. ``"RSA PRIVATE KEY"``).
        - **offset** (*int*): Byte offset of the ``-----BEGIN …-----`` line.
        - **data** (*bytes*): The full PEM block including headers.
    """
    results: list[dict] = []
    for pem_type, pattern in _PEM_PATTERNS:
        for m in pattern.finditer(data):
            results.append(
                {
                    "type": pem_type,
                    "offset": m.start(),
                    "data": m.group(0),
                }
            )

    # Sort by offset for deterministic output
    results.sort(key=lambda r: r["offset"])
    return results


# ---------------------------------------------------------------------------
# Environment variable carving
# ---------------------------------------------------------------------------

_ENV_NAMES = (
    b"FLAG",
    b"KEY",
    b"SECRET",
    b"PASSWORD",
    b"TOKEN",
)

# Match  NAME=value  terminated by null byte, newline, or end-of-data.
# Values are captured up to the first terminator.
_ENV_RE = re.compile(
    rb"(?:^|(?<![a-zA-Z0-9_]))"                        # word boundary / not part of a larger identifier
    rb"(" + b"|".join(_ENV_NAMES) + rb")"             # variable name
    rb"="
    rb"([^\x00\n\r]*)",                                # value (until NUL/NL/CR)
    re.MULTILINE,
)


def carve_env_variables(data: bytes) -> dict[str, str]:
    """Scan for common environment variable assignments.

    Looks for ``FLAG=…``, ``KEY=…``, ``SECRET=…``, ``PASSWORD=…``, and
    ``TOKEN=…`` patterns terminated by a null byte or newline.

    Args:
        data: Raw binary data to scan.

    Returns:
        A dict mapping variable names to their values (decoded as UTF-8 where
        possible, falling back to latin-1).
    """
    results: dict[str, str] = {}
    for m in _ENV_RE.finditer(data):
        name = m.group(1).decode("ascii")
        value_bytes = m.group(2)
        try:
            value = value_bytes.decode("utf-8")
        except UnicodeDecodeError:
            value = value_bytes.decode("latin-1", errors="replace")
        # If multiple occurrences, keep the last one (overwrite)
        results[name] = value
    return results


# ---------------------------------------------------------------------------
# Shadow hash carving
# ---------------------------------------------------------------------------

# /etc/shadow format:  username:$type$salt$hash:…
# type is typically 1 (MD5), 2a/2b/2y (bcrypt), 5 (SHA-256), 6 (SHA-512),
# y (yescrypt).
_SHADOW_RE = re.compile(
    rb"([a-zA-Z0-9_][a-zA-Z0-9._-]{0,31})"                # username
    rb":"
    rb"(\$([0-9a-zA-Z]+)\$[^\s:]+)"                        # $type$salt$hash
    rb":",
)


def carve_shadow_hashes(data: bytes) -> list[dict]:
    """Find ``/etc/shadow``-format password hashes.

    Matches lines of the form ``username:$type$salt$hash:…``.

    Args:
        data: Raw binary data to scan.

    Returns:
        A list of dicts, each with:

        - **username** (*str*): The account name.
        - **hash_type** (*str*): The hash algorithm identifier (e.g. ``"6"``
          for SHA-512).
        - **full_hash** (*str*): The complete ``$type$salt$hash`` string.
    """
    results: list[dict] = []
    seen: set[str] = set()
    for m in _SHADOW_RE.finditer(data):
        username = m.group(1).decode("ascii", errors="replace")
        full_hash = m.group(2).decode("ascii", errors="replace")
        hash_type = m.group(3).decode("ascii", errors="replace")

        key = f"{username}:{full_hash}"
        if key in seen:
            continue
        seen.add(key)

        results.append(
            {
                "username": username,
                "hash_type": hash_type,
                "full_hash": full_hash,
            }
        )

    return results


# ---------------------------------------------------------------------------
# URL carving
# ---------------------------------------------------------------------------

_URL_RE = re.compile(rb"https?://[\x21-\x7e]+")


def carve_urls(data: bytes) -> list[str]:
    """Extract HTTP/HTTPS URLs from binary data.

    Matches ``http://`` and ``https://`` followed by printable ASCII characters
    (0x21–0x7E).

    Args:
        data: Raw binary data to scan.

    Returns:
        A deduplicated list of URL strings, preserving first-occurrence order.
    """
    seen: set[str] = set()
    results: list[str] = []
    for m in _URL_RE.finditer(data):
        url = m.group(0).decode("ascii", errors="replace")
        if url not in seen:
            seen.add(url)
            results.append(url)
    return results


# ---------------------------------------------------------------------------
# Email carving
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(
    rb"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
)


def carve_emails(data: bytes) -> list[str]:
    """Extract email addresses from binary data.

    Args:
        data: Raw binary data to scan.

    Returns:
        A deduplicated list of email address strings, preserving first-occurrence
        order.
    """
    seen: set[str] = set()
    results: list[str] = []
    for m in _EMAIL_RE.finditer(data):
        email = m.group(0).decode("ascii", errors="replace")
        if email not in seen:
            seen.add(email)
            results.append(email)
    return results


# ---------------------------------------------------------------------------
# IPv4 carving
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(
    rb"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
)


def carve_ipv4(data: bytes) -> list[str]:
    """Extract valid IPv4 addresses from binary data.

    Each octet is validated to be in the range 0–255.

    Args:
        data: Raw binary data to scan.

    Returns:
        A deduplicated list of IPv4 address strings, preserving first-occurrence
        order.
    """
    seen: set[str] = set()
    results: list[str] = []
    for m in _IPV4_RE.finditer(data):
        ip_str = m.group(1).decode("ascii")
        octets = ip_str.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            if ip_str not in seen:
                seen.add(ip_str)
                results.append(ip_str)
    return results
