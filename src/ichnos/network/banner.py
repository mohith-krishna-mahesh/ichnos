"""Network service banner grabbing."""

from __future__ import annotations

import socket


def grab_banner(
    host: str,
    port: int,
    timeout: float = 2.0,
    probe: bytes | None = None,
) -> str | None:
    """Connects to target service and retrieves greeting or response banner."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))

        # Default probes for well-known ports
        if probe is None:
            if port in (80, 8080, 8000, 8888):
                probe = b"HEAD / HTTP/1.0\r\nHost: " + host.encode("ascii") + b"\r\n\r\n"
            elif port in (21, 22, 25, 110, 143):
                # Server usually sends banner on connect without probe
                probe = b""
            else:
                probe = b"\r\n"

        if probe:
            s.sendall(probe)

        data = s.recv(4096)
        if data:
            return data.decode("latin-1", errors="replace").strip()
        return None
    except Exception:
        return None
    finally:
        s.close()
