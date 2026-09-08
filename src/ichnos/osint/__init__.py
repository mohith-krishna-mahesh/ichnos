"""Open-source intelligence (OSINT) module for Ichnos."""

from __future__ import annotations

from ichnos.osint import dns_lookup, subdomains, whois
from ichnos.osint.dns_lookup import query_doh, resolve_domain
from ichnos.osint.subdomains import enumerate_subdomains, search_crt_sh
from ichnos.osint.whois import lookup_whois

__all__ = [
    "dns_lookup",
    "enumerate_subdomains",
    "lookup_whois",
    "query_doh",
    "resolve_domain",
    "search_crt_sh",
    "subdomains",
    "whois",
]
