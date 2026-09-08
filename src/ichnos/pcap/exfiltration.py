"""ICMP and DNS exfiltration and covert channel reassembly.

Detects and extracts data exfiltrated via:
1. ICMP echo payloads (custom payloads, single-byte streams, non-standard lengths)
2. DNS subdomain tunneling (hex, base64, base32, custom chunked queries)
3. DNS TXT record covert channels
"""

from __future__ import annotations

import base64
import binascii
import re
import struct
from typing import Any

from ichnos.pcap.dns import extract_dns_queries
from ichnos.pcap.parser import PCAPPacket

# Common OS ping default filler payloads
_LINUX_PING_PATTERN = bytes(range(0x10, 0x38))  # standard incrementing bytes
_WINDOWS_PING_PATTERN = b"abcdefghijklmnopqrstuvwabcdefghi"


def _is_standard_ping_payload(payload: bytes) -> bool:
    """Checks whether ICMP payload is standard OS ping boilerplate."""
    if not payload:
        return True
    if payload == _WINDOWS_PING_PATTERN:
        return True
    # Linux ping has 8-byte timestamp + incrementing bytes
    if len(payload) >= 16:
        pattern = bytes((i & 0xFF) for i in range(len(payload) - 8))
        if payload[8:] == pattern[: len(payload) - 8]:
            return True
        # Check standard ASCII alphabet filler b" !\"#$%&'()*+,-./01234567..."
        ascii_fill = bytes((0x20 + (i % 95)) for i in range(len(payload) - 8))
        if payload[8:] == ascii_fill[: len(payload) - 8]:
            return True
    # All zeros
    if set(payload) == {0}:
        return True
    return False


def extract_icmp_payloads(
    packets: list[PCAPPacket],
    echo_requests_only: bool = True,
    filter_standard_ping: bool = False,
) -> list[dict[str, Any]]:
    """Extracts raw payloads and metadata from ICMP packets.

    Args:
        packets: List of decoded PCAP packets.
        echo_requests_only: If True, only extracts Echo Requests (type 8).
        filter_standard_ping: If True, skips default OS ping boilerplate.

    Returns:
        List of dicts with timestamp, seq, id, src, dst, and payload bytes.
    """
    results: list[dict[str, Any]] = []

    for pkt in packets:
        if pkt.protocol != "ICMP" or len(pkt.payload) < 4:
            continue

        raw = pkt.payload
        icmp_type = raw[0]
        icmp_code = raw[1]

        if echo_requests_only and icmp_type != 8:
            continue
        if not echo_requests_only and icmp_type not in (0, 8):
            continue

        icmp_id = None
        icmp_seq = None
        data = b""

        if len(raw) >= 8:
            icmp_id, icmp_seq = struct.unpack("!HH", raw[4:8])
            data = raw[8:]
        else:
            data = raw[4:]

        if filter_standard_ping and _is_standard_ping_payload(data):
            continue

        results.append(
            {
                "timestamp": pkt.timestamp,
                "type": icmp_type,
                "code": icmp_code,
                "id": icmp_id,
                "seq": icmp_seq,
                "src": pkt.ip_src,
                "dst": pkt.ip_dst,
                "payload": data,
            }
        )

    return results


def reassemble_icmp_stream(
    packets: list[PCAPPacket],
    echo_requests_only: bool = True,
    filter_standard_ping: bool = True,
) -> bytes:
    """Reassembles exfiltrated ICMP stream into contiguous bytes.

    Handles single-byte-per-packet CTF challenges as well as chunked payloads.
    """
    extracted = extract_icmp_payloads(
        packets,
        echo_requests_only=echo_requests_only,
        filter_standard_ping=filter_standard_ping,
    )

    if not extracted:
        # Retry without filtering if nothing found
        extracted = extract_icmp_payloads(
            packets,
            echo_requests_only=echo_requests_only,
            filter_standard_ping=False,
        )

    # Sort by timestamp
    extracted.sort(key=lambda x: x["timestamp"])

    chunks: list[bytes] = []
    # Check if this is a 1-byte-per-packet covert channel (often in data or seq/id)
    if extracted and all(len(x["payload"]) == 1 for x in extracted):
        return b"".join(x["payload"] for x in extracted)

    # Check if 1 byte is embedded at the first byte of payload
    first_bytes = bytes(x["payload"][0] for x in extracted if len(x["payload"]) > 0)
    if b"flag{" in first_bytes.lower() or b"ctf{" in first_bytes.lower():
        return first_bytes

    # Normal concatenation of non-empty payloads
    for item in extracted:
        payload = item["payload"]
        if payload:
            chunks.append(payload)

    raw_combined = b"".join(chunks)

    # Attempt hex decode if ASCII hex
    try:
        cleaned_hex = re.sub(r"[^0-9a-fA-F]", "", raw_combined.decode("latin-1"))
        if len(cleaned_hex) >= 8 and len(cleaned_hex) % 2 == 0:
            decoded = binascii.unhexlify(cleaned_hex)
            if any(b in decoded for b in (b"flag{", b"ctf{", b"FLAG{", b"CTF{")):
                return decoded
    except Exception:
        pass

    return raw_combined


def extract_dns_tunneling(
    packets: list[PCAPPacket],
    target_domain: str | None = None,
) -> dict[str, Any]:
    """Extracts and attempts reassembly of data exfiltrated via DNS subdomain queries.

    Args:
        packets: List of decoded PCAP packets.
        target_domain: Optional domain filter (e.g. 'evil.com'). If None, automatically
                       infers the base domain from repeated query suffixes.

    Returns:
        Dict with queries, inferred domain, raw_stream, decoded_candidates, and found_flags.
    """
    queries = extract_dns_queries(packets)
    if not queries:
        return {
            "target_domain": target_domain,
            "queries_count": 0,
            "raw_stream": b"",
            "candidates": [],
            "flags": [],
        }

    # Filter only questions (not responses)
    questions = [q for q in queries if not q.get("is_response", False)]
    if not questions:
        questions = queries

    # Infer domain if not provided
    names = [q["name"].strip(".") for q in questions if q.get("name")]
    if not target_domain and names:
        # Find common suffix of length >= 2 parts (e.g. .example.com)
        suffix_counts: dict[str, int] = {}
        for name in names:
            parts = name.split(".")
            if len(parts) >= 2:
                for i in range(1, len(parts)):
                    candidate_domain = ".".join(parts[i:]).lower()
                    suffix_counts[candidate_domain] = suffix_counts.get(candidate_domain, 0) + 1
        if suffix_counts:
            # Domain with highest occurrence having at least 1 dot
            best_domain = max(
                (d for d in suffix_counts if "." in d),
                key=lambda d: (suffix_counts[d], len(d)),
                default="",
            )
            if suffix_counts.get(best_domain, 0) >= 2:
                target_domain = best_domain

    subdomain_chunks: list[str] = []
    seen: set[str] = set()

    for name in names:
        if target_domain:
            if name.lower().endswith("." + target_domain.lower()):
                sub = name[: -(len(target_domain) + 1)]
            elif name.lower() == target_domain.lower():
                continue
            else:
                continue
        else:
            sub = name

        # Avoid immediate duplicate queries from retransmission
        if sub not in seen:
            seen.add(sub)
            subdomain_chunks.append(sub)

    # Flatten labels (e.g. a.b.c -> abc or a+b+c)
    # Often queries have format: <seq>.<chunk>.<domain> or <chunk1>.<chunk2>.<domain>
    cleaned_chunks: list[str] = []
    for chunk in subdomain_chunks:
        labels = chunk.split(".")
        # If first label is numeric sequence counter (e.g. '001', '1'), discard it or sort by it
        if len(labels) > 1 and labels[0].isdigit():
            labels = labels[1:]
        cleaned_chunks.append("".join(labels))

    raw_str = "".join(cleaned_chunks)
    raw_bytes = raw_str.encode("latin-1", errors="replace")

    candidates: list[bytes] = [raw_bytes]

    # Try hex decoding
    try:
        hex_clean = re.sub(r"[^0-9a-fA-F]", "", raw_str)
        if len(hex_clean) % 2 == 0 and len(hex_clean) >= 4:
            candidates.append(binascii.unhexlify(hex_clean))
    except Exception:
        pass

    # Try base64 decoding
    try:
        b64_clean = re.sub(r"[^A-Za-z0-9+/=_-]", "", raw_str).replace("-", "+").replace("_", "/")
        # Pad to multiple of 4
        b64_clean += "=" * ((4 - len(b64_clean) % 4) % 4)
        candidates.append(base64.b64decode(b64_clean))
    except Exception:
        pass

    # Try base32 decoding
    try:
        b32_clean = re.sub(r"[^A-Za-z2-7=]", "", raw_str.upper())
        b32_clean += "=" * ((8 - len(b32_clean) % 8) % 8)
        candidates.append(base64.b32decode(b32_clean))
    except Exception:
        pass

    # Scan for flags in all candidates
    flag_pattern = re.compile(rb"[a-zA-Z0-9_-]+{[^}\n\r]+}")
    found_flags: list[str] = []
    for cand in candidates:
        matches = flag_pattern.findall(cand)
        for m in matches:
            decoded_flag = m.decode("latin-1", errors="replace")
            if decoded_flag not in found_flags:
                found_flags.append(decoded_flag)

    return {
        "target_domain": target_domain,
        "queries_count": len(subdomain_chunks),
        "raw_stream": raw_bytes,
        "candidates": candidates,
        "flags": found_flags,
    }
