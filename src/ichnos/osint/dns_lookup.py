"""DNS record lookup using DNS-over-HTTPS (DoH) and system resolvers."""

from __future__ import annotations

import json
import socket
import urllib.parse
import urllib.request
from typing import Any

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]

TYPE_MAP = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    15: "MX",
    16: "TXT",
    28: "AAAA",
}


def query_doh(domain: str, record_type: str = "A", timeout: float = 5.0) -> list[dict[str, Any]]:
    """Queries DNS records via Cloudflare DNS-over-HTTPS JSON API."""
    params = urllib.parse.urlencode({"name": domain, "type": record_type})
    url = f"https://cloudflare-dns.com/dns-query?{params}"
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/dns-json", "User-Agent": "Ichnos-OSINT/1.0"},
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            answers = data.get("Answer", [])
            records: list[dict[str, Any]] = []
            for ans in answers:
                type_id = ans.get("type", 1)
                type_name = TYPE_MAP.get(type_id, str(type_id))
                records.append(
                    {
                        "name": ans.get("name", domain),
                        "type": type_name,
                        "data": ans.get("data", ""),
                        "TTL": ans.get("TTL", 0),
                    }
                )
            return records
    except Exception:
        return []


def resolve_domain(domain: str, record_types: list[str] | None = None) -> dict[str, Any]:
    """Resolves DNS records for a domain across specified record types."""
    types_to_query = record_types if record_types else ["A", "AAAA", "MX", "TXT", "NS"]
    results: dict[str, list[dict[str, Any]]] = {}

    for r_type in types_to_query:
        recs = query_doh(domain, r_type)
        # Fallback to socket getaddrinfo for A/AAAA if DoH was unreachable
        if not recs and r_type == "A":
            try:
                addrs = socket.getaddrinfo(domain, None, socket.AF_INET)
                ips = sorted(set(a[4][0] for a in addrs))
                recs = [{"name": domain, "type": "A", "data": ip, "TTL": 0} for ip in ips]
            except Exception:
                pass
        results[r_type] = recs

    return {
        "domain": domain,
        "records": results,
    }
