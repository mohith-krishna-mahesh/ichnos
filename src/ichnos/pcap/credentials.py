"""Plaintext credential extractor from PCAP packet streams."""

from __future__ import annotations

import base64
import re
from typing import Any

from ichnos.pcap.parser import PCAPPacket


def extract_credentials(packets: list[PCAPPacket]) -> list[dict[str, Any]]:
    """Inspects packet payloads to extract plaintext credentials."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for pkt in packets:
        if not pkt.payload:
            continue

        raw = pkt.payload
        text = raw.decode("latin-1", errors="replace")

        # 1. HTTP Basic Auth: 'Authorization: Basic <b64>'
        basic_matches = re.findall(r"(?i)Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text)
        for b64_str in basic_matches:
            try:
                decoded = base64.b64decode(b64_str).decode("utf-8", errors="replace")
                key = f"http-basic:{decoded}:{pkt.ip_src}->{pkt.ip_dst}"
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        {
                            "type": "HTTP Basic Auth",
                            "credential": decoded,
                            "src": f"{pkt.ip_src}:{pkt.sport}",
                            "dst": f"{pkt.ip_dst}:{pkt.dport}",
                            "timestamp": pkt.timestamp,
                        }
                    )
            except Exception:
                pass

        # 2. FTP USER & PASS
        ftp_user = re.findall(r"(?i)^USER\s+([^\r\n]+)", text, re.MULTILINE)
        ftp_pass = re.findall(r"(?i)^PASS\s+([^\r\n]+)", text, re.MULTILINE)
        for u in ftp_user:
            key = f"ftp-user:{u}:{pkt.ip_src}"
            if key not in seen:
                seen.add(key)
                findings.append(
                    {
                        "type": "FTP Username",
                        "credential": f"USER {u.strip()}",
                        "src": f"{pkt.ip_src}:{pkt.sport}",
                        "dst": f"{pkt.ip_dst}:{pkt.dport}",
                        "timestamp": pkt.timestamp,
                    }
                )
        for p in ftp_pass:
            key = f"ftp-pass:{p}:{pkt.ip_src}"
            if key not in seen:
                seen.add(key)
                findings.append(
                    {
                        "type": "FTP Password",
                        "credential": f"PASS {p.strip()}",
                        "src": f"{pkt.ip_src}:{pkt.sport}",
                        "dst": f"{pkt.ip_dst}:{pkt.dport}",
                        "timestamp": pkt.timestamp,
                    }
                )

        # 3. HTTP Form POST parameters (user=, password=, pass=, secret=)
        post_creds = re.findall(
            r"(?i)(?:user|username|login|email)=([^&\r\n]+)&(?:password|pass|passwd|pwd)=([^&\r\n]+)",
            text,
        )
        for u, p in post_creds:
            key = f"http-post:{u}:{p}"
            if key not in seen:
                seen.add(key)
                findings.append(
                    {
                        "type": "HTTP POST Credentials",
                        "credential": f"user={u} password={p}",
                        "src": f"{pkt.ip_src}:{pkt.sport}",
                        "dst": f"{pkt.ip_dst}:{pkt.dport}",
                        "timestamp": pkt.timestamp,
                    }
                )

    return findings
