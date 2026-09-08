"""Concurrent TCP port scanner."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any

COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1723,
    3306,
    3389,
    5900,
    8080,
]


def parse_port_range(port_spec: str | list[int]) -> list[int]:
    """Parses port specifications like '80,443,8000-8080' or a list of integers."""
    if isinstance(port_spec, list):
        return sorted(set(port_spec))

    ports: set[int] = set()
    for part in port_spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            ports.update(range(start, end + 1))
        elif part.isdigit():
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def scan_single_port(host: str, port: int, timeout: float = 0.5) -> dict[str, Any] | None:
    """Attempts a TCP connect to a single host and port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        res = s.connect_ex((host, port))
        if res == 0:
            try:
                service = socket.getservbyport(port, "tcp")
            except Exception:
                service = "unknown"
            return {
                "port": port,
                "state": "open",
                "service": service,
            }
        return None
    except Exception:
        return None
    finally:
        s.close()


def scan_ports(
    host: str,
    ports: str | list[int] | None = None,
    timeout: float = 0.5,
    max_workers: int = 50,
) -> list[dict[str, Any]]:
    """Performs concurrent TCP connect scanning against target host."""
    target_ports = parse_port_range(ports) if ports is not None else COMMON_PORTS
    open_ports: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=min(max_workers, len(target_ports) or 1)) as executor:
        futures = [executor.submit(scan_single_port, host, p, timeout) for p in target_ports]
        for f in futures:
            result = f.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])
    return open_ports
