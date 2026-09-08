"""TLS/SSL certificate and cipher suite inspection."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any


def inspect_tls(host: str, port: int = 443, timeout: float = 3.0) -> dict[str, Any]:
    """Connects via TLS/SSL and extracts certificate metadata and negotiated parameters."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    try:
        with ctx.wrap_socket(s, server_hostname=host) as ssock:
            ssock.connect((host, port))
            cert = ssock.getpeercert(binary_form=False)
            cipher_info = ssock.cipher()
            tls_version = ssock.version()

            # Subject and Issuer extraction
            subject_dict: dict[str, str] = {}
            if cert and "subject" in cert:
                for rdn in cert["subject"]:
                    for k, v in rdn:
                        subject_dict[k] = v

            issuer_dict: dict[str, str] = {}
            if cert and "issuer" in cert:
                for rdn in cert["issuer"]:
                    for k, v in rdn:
                        issuer_dict[k] = v

            sans: list[str] = []
            if cert and "subjectAltName" in cert:
                for typ, val in cert["subjectAltName"]:
                    sans.append(f"{typ}:{val}")

            not_before = cert.get("notBefore") if cert else None
            not_after = cert.get("notAfter") if cert else None

            # Calculate expiration status
            expired = False
            if not_after:
                try:
                    # e.g., 'May 10 12:00:00 2025 GMT'
                    dt_after = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=timezone.utc
                    )
                    expired = datetime.now(timezone.utc) > dt_after
                except Exception:
                    pass

            return {
                "host": host,
                "port": port,
                "tls_version": tls_version,
                "cipher_suite": cipher_info[0] if cipher_info else None,
                "cipher_protocol": cipher_info[1] if cipher_info else None,
                "cipher_bits": cipher_info[2] if cipher_info else None,
                "subject": subject_dict,
                "issuer": issuer_dict,
                "subject_alt_names": sans,
                "valid_from": not_before,
                "valid_until": not_after,
                "expired": expired,
                "serial_number": cert.get("serialNumber") if cert else None,
            }
    finally:
        s.close()
