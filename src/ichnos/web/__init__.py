"""Web application reconnaissance module for Ichnos."""

from __future__ import annotations

from ichnos.web import extract, fuzz, graphql, headers, ssti
from ichnos.web.extract import extract_assets
from ichnos.web.fuzz import fuzz_paths
from ichnos.web.headers import audit_headers, fetch_and_audit

__all__ = [
    "audit_headers",
    "extract",
    "extract_assets",
    "fetch_and_audit",
    "fuzz",
    "fuzz_paths",
    "graphql",
    "headers",
    "ssti",
]
