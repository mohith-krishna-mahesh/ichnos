"""Pure-socket WHOIS lookup client."""

from __future__ import annotations

import re
import socket
from typing import Any


def query_whois_server(server: str, query: str, port: int = 43, timeout: float = 5.0) -> str:
    """Connects to a WHOIS server over TCP port 43 and returns raw response."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((server, port))
        s.sendall(f"{query}\r\n".encode("utf-8"))
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        return response.decode("latin-1", errors="replace")
    finally:
        s.close()


def parse_whois_response(raw_text: str) -> dict[str, Any]:
    """Parses standard WHOIS text fields into a structured dictionary."""
    data: dict[str, Any] = {
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "name_servers": [],
        "status": [],
    }

    # Registrar
    m_reg = re.search(r"(?i)(?:Registrar|Sponsoring Registrar):\s*([^\r\n]+)", raw_text)
    if m_reg:
        data["registrar"] = m_reg.group(1).strip()

    # Creation Date
    m_created = re.search(
        r"(?i)(?:Creation Date|Created On|Registration Time):\s*([^\r\n]+)", raw_text
    )
    if m_created:
        data["creation_date"] = m_created.group(1).strip()

    # Expiration Date
    m_exp = re.search(
        r"(?i)(?:Registry Expiry Date|Expiration Date|Expires On):\s*([^\r\n]+)", raw_text
    )
    if m_exp:
        data["expiration_date"] = m_exp.group(1).strip()

    # Updated Date
    m_upd = re.search(r"(?i)(?:Updated Date|Last Updated On):\s*([^\r\n]+)", raw_text)
    if m_upd:
        data["updated_date"] = m_upd.group(1).strip()

    # Name Servers
    nss = re.findall(r"(?i)Name Server:\s*([^\r\n]+)", raw_text)
    data["name_servers"] = sorted(set(ns.strip().lower() for ns in nss))

    # Domain Status
    statuses = re.findall(r"(?i)Domain Status:\s*([^\s\r\n]+)", raw_text)
    data["status"] = sorted(set(statuses))

    return data


def lookup_whois(domain: str, timeout: float = 5.0) -> dict[str, Any]:
    """Performs full WHOIS lookup with IANA referral resolution."""
    # 1. Query IANA to find the TLD WHOIS server
    tld = domain.rstrip(".").split(".")[-1]
    iana_raw = ""
    whois_server = None

    try:
        iana_raw = query_whois_server("whois.iana.org", tld, timeout=timeout)
        m_srv = re.search(r"(?i)whois:\s*([^\r\n]+)", iana_raw)
        if m_srv:
            whois_server = m_srv.group(1).strip()
    except Exception:
        pass

    # Common fallbacks if IANA lookup fails
    if not whois_server:
        tld_defaults = {
            "com": "whois.verisign-grs.com",
            "net": "whois.verisign-grs.com",
            "org": "whois.pir.org",
            "io": "whois.nic.io",
            "info": "whois.afilias.net",
        }
        whois_server = tld_defaults.get(tld.lower(), f"whois.nic.{tld}")

    # 2. Query Authoritative WHOIS server
    raw_response = ""
    try:
        raw_response = query_whois_server(whois_server, domain, timeout=timeout)
        # Check if referral server is mentioned
        m_ref = re.search(r"(?i)Registrar WHOIS Server:\s*([^\r\n]+)", raw_response)
        if m_ref:
            referral_server = m_ref.group(1).strip()
            try:
                referral_raw = query_whois_server(referral_server, domain, timeout=timeout)
                if len(referral_raw) > len(raw_response) / 2:
                    raw_response = referral_raw
            except Exception:
                pass
    except Exception as e:
        raw_response = f"WHOIS query failed: {e}"

    parsed = parse_whois_response(raw_response)
    parsed["domain"] = domain
    parsed["whois_server"] = whois_server
    parsed["raw"] = raw_response[:2048]
    return parsed
