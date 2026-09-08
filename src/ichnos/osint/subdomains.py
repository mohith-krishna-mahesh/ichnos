"""Subdomain discovery via Certificate Transparency logs and DNS enumeration."""

from __future__ import annotations

import json
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any


def search_crt_sh(domain: str, timeout: float = 10.0) -> list[str]:
    """Queries crt.sh Certificate Transparency logs for subdomains."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "Ichnos-OSINT/1.0"})

    subdomains: set[str] = set()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.splitlines():
                    name = name.strip().lower()
                    if name.startswith("*."):
                        name = name[2:]
                    if name.endswith(domain):
                        subdomains.add(name)
    except Exception:
        pass

    return sorted(subdomains)


def check_subdomain_dns(subdomain: str) -> dict[str, Any] | None:
    """Checks if a subdomain resolves via DNS."""
    try:
        ip = socket.gethostbyname(subdomain)
        return {"subdomain": subdomain, "ip": ip}
    except Exception:
        return None


def enumerate_subdomains(
    domain: str,
    wordlist: list[str] | None = None,
    use_crt: bool = True,
    max_workers: int = 20,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """Discovers subdomains through Certificate Transparency logs and wordlist brute-forcing."""
    discovered: set[str] = set()

    if use_crt:
        crt_names = search_crt_sh(domain, timeout=timeout)
        discovered.update(crt_names)

    if wordlist:
        candidates = [f"{w.strip().lower()}.{domain}" for w in wordlist if w.strip()]
        discovered.update(candidates)

    resolved: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_subdomain_dns, name): name for name in discovered}
        for f in futures:
            res = f.result()
            if res:
                resolved.append(res)
            elif not wordlist:  # If only CRT was used, report even if currently unresolvable
                resolved.append({"subdomain": futures[f], "ip": None})

    resolved.sort(key=lambda x: x["subdomain"])
    return resolved
