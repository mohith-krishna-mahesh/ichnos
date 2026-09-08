"""Concurrent HTTP endpoint and directory fuzzer."""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any


def probe_path(
    base_url: str,
    path: str,
    timeout: float = 3.0,
    headers: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    """Probes a single path against base_url."""
    clean_path = path.lstrip("/")
    target = urllib.parse.urljoin(base_url.rstrip("/") + "/", clean_path)

    req_headers = {"User-Agent": "Ichnos-WebFuzzer/1.0"}
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(target, headers=req_headers, method="GET")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            return {
                "path": "/" + clean_path,
                "url": target,
                "status": resp.status,
                "content_length": len(body),
                "redirect": None,
            }
    except urllib.error.HTTPError as e:
        # HTTP error (e.g. 401, 403, 404, 500)
        body = e.read() if hasattr(e, "read") else b""
        redirect_loc = e.headers.get("Location") if hasattr(e, "headers") else None
        return {
            "path": "/" + clean_path,
            "url": target,
            "status": e.code,
            "content_length": len(body),
            "redirect": redirect_loc,
        }
    except Exception:
        return None


def fuzz_paths(
    base_url: str,
    wordlist: list[str],
    allowed_status: list[int] | None = None,
    max_workers: int = 10,
    timeout: float = 3.0,
) -> list[dict[str, Any]]:
    """Concurrently probes paths from wordlist against target base_url."""
    if not base_url.startswith(("http://", "https://")):
        base_url = "http://" + base_url

    results: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(probe_path, base_url, p, timeout) for p in wordlist]
        for f in futures:
            res = f.result()
            if res is not None:
                if allowed_status is None or res["status"] in allowed_status:
                    results.append(res)

    results.sort(key=lambda x: x["path"])
    return results
