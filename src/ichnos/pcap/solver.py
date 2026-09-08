"""Automated Packet Capture (PCAP/PCAPNG) Analysis and Flag Carver.

Reassembles TCP flows, extracts plaintext credentials, parses HTTP transfers,
decodes DNS tunneling records, and carves CTF flags from packet payloads.
"""

from __future__ import annotations

from typing import Any

from ichnos.core.harvester import FLAG_PATTERN
from ichnos.crypto.xor.single_byte import xor_single
from ichnos.pcap.credentials import extract_credentials
from ichnos.pcap.dns import extract_dns_queries
from ichnos.pcap.http import parse_http_messages
from ichnos.pcap.parser import read_pcap
from ichnos.pcap.reassembly import reassemble_all_tcp_flows


def solve_pcap(data: bytes, filename: str = "capture.pcap") -> dict[str, Any]:
    """Runs end-to-end automated analysis on PCAP/PCAPNG capture data."""
    findings: list[str] = []
    found_flags: list[str] = []

    try:
        packets = read_pcap(data)
    except Exception as e:
        return {
            "solved": False,
            "flag": None,
            "error": f"Failed to parse PCAP: {e}",
            "findings": findings,
            "credentials": [],
            "packet_count": 0,
        }

    findings.append(f"Parsed {len(packets)} packets from {filename}")

    # 1. Plaintext credentials harvesting (Basic Auth, FTP, Telnet)
    try:
        creds = extract_credentials(packets)
        if creds:
            findings.append(f"Extracted {len(creds)} credential candidate(s)")
            for c in creds:
                cred_text = str(c.get("credential", ""))
                for match in FLAG_PATTERN.finditer(cred_text):
                    found_flags.append(match.group(0))
        if found_flags:
            return {
                "solved": True,
                "flag": found_flags[0],
                "method": "PCAP Plaintext Credential",
                "findings": findings,
                "credentials": creds,
                "packet_count": len(packets),
            }
    except Exception:
        creds = []

    # 2. HTTP Stream Reassembly and Body Parsing
    try:
        flows = reassemble_all_tcp_flows(packets)
        http_msgs = parse_http_messages(flows)
        if http_msgs:
            findings.append(f"Reassembled {len(http_msgs)} HTTP transaction(s)")
            for msg in http_msgs:
                # Check headers
                for k, v in msg.get("headers", {}).items():
                    for match in FLAG_PATTERN.finditer(f"{k}: {v}"):
                        found_flags.append(match.group(0))
                # Check URI
                uri = msg.get("uri", "")
                for match in FLAG_PATTERN.finditer(uri):
                    found_flags.append(match.group(0))
                # Check body preview / body
                body_prev = msg.get("body_preview", "")
                for match in FLAG_PATTERN.finditer(body_prev):
                    found_flags.append(match.group(0))

        if found_flags:
            return {
                "solved": True,
                "flag": found_flags[0],
                "method": "PCAP HTTP Stream Extraction",
                "findings": findings,
                "credentials": creds,
                "packet_count": len(packets),
            }
    except Exception:
        pass

    # 3. DNS Tunneling and TXT Exfiltration Analysis
    try:
        dns_queries = extract_dns_queries(packets)
        if dns_queries:
            findings.append(f"Extracted {len(dns_queries)} DNS querie(s)")
            for q in dns_queries:
                qname = q.get("name", "")
                for match in FLAG_PATTERN.finditer(qname):
                    found_flags.append(match.group(0))
        if found_flags:
            return {
                "solved": True,
                "flag": found_flags[0],
                "method": "PCAP DNS Query Analysis",
                "findings": findings,
                "credentials": creds,
                "packet_count": len(packets),
            }
    except Exception:
        pass

    # 4. Direct Payload Search across all packets
    for pkt in packets:
        if not pkt.payload:
            continue
        try:
            payload_text = pkt.payload.decode("latin-1")
            for match in FLAG_PATTERN.finditer(payload_text):
                found_flags.append(match.group(0))
        except Exception:
            pass

    if found_flags:
        return {
            "solved": True,
            "flag": found_flags[0],
            "method": "PCAP Payload String Match",
            "findings": findings,
            "credentials": creds,
            "packet_count": len(packets),
        }

    # 5. Single-byte XOR scan on reassembled payloads / packet stream sample
    combined_sample = b"".join(pkt.payload for pkt in packets[:200])[:65536]
    if combined_sample:
        for key in range(1, 256):
            dec = xor_single(combined_sample, key)
            try:
                dec_str = dec.decode("latin-1")
                for match in FLAG_PATTERN.finditer(dec_str):
                    return {
                        "solved": True,
                        "flag": match.group(0),
                        "method": f"PCAP XOR Stream (key={hex(key)})",
                        "findings": findings,
                        "credentials": creds,
                        "packet_count": len(packets),
                    }
            except Exception:
                pass

    return {
        "solved": False,
        "flag": None,
        "findings": findings,
        "credentials": creds,
        "packet_count": len(packets),
    }
