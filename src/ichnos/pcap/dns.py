"""DNS query extractor from packet capture payloads."""

from __future__ import annotations

import struct
from typing import Any

from ichnos.pcap.parser import PCAPPacket

DNS_TYPES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}


def decode_dns_name(payload: bytes, offset: int) -> tuple[str, int]:
    """Decodes a DNS domain name from label sequences at offset."""
    labels: list[str] = []
    initial_offset = offset
    jumped = False
    max_jumps = 10
    jumps = 0

    while offset < len(payload):
        length = payload[offset]
        if length == 0:
            if not jumped:
                offset += 1
            break

        # Pointer (0xC0)
        if (length & 0xC0) == 0xC0:
            if offset + 2 > len(payload):
                break
            ptr = struct.unpack("!H", payload[offset : offset + 2])[0] & 0x3FFF
            if not jumped:
                initial_offset = offset + 2
                jumped = True
            offset = ptr
            jumps += 1
            if jumps > max_jumps:
                break
            continue

        offset += 1
        if offset + length > len(payload):
            break
        label = payload[offset : offset + length].decode("latin-1", errors="replace")
        labels.append(label)
        offset += length

    domain = ".".join(labels)
    return domain, (initial_offset if jumped else offset)


def extract_dns_queries(packets: list[PCAPPacket]) -> list[dict[str, Any]]:
    """Extracts all DNS questions from UDP port 53 packets."""
    queries: list[dict[str, Any]] = []

    for pkt in packets:
        if pkt.sport != 53 and pkt.dport != 53:
            continue
        if len(pkt.payload) < 12:
            continue

        payload = pkt.payload
        tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", payload[:12])

        is_response = bool(flags & 0x8000)
        if qdcount == 0:
            continue

        offset = 12
        for _ in range(qdcount):
            try:
                name, offset = decode_dns_name(payload, offset)
                if offset + 4 <= len(payload):
                    qtype, qclass = struct.unpack("!HH", payload[offset : offset + 4])
                    offset += 4
                    type_str = DNS_TYPES.get(qtype, f"TYPE-{qtype}")
                    queries.append(
                        {
                            "transaction_id": hex(tx_id),
                            "name": name,
                            "type": type_str,
                            "is_response": is_response,
                            "client_ip": pkt.ip_src if not is_response else pkt.ip_dst,
                            "server_ip": pkt.ip_dst if not is_response else pkt.ip_src,
                            "timestamp": pkt.timestamp,
                        }
                    )
            except Exception:
                break

    return queries
