"""Network flow analysis and conversation tracking."""

from __future__ import annotations

from typing import Any

from ichnos.pcap.parser import PCAPPacket


def extract_flows(packets: list[PCAPPacket]) -> list[dict[str, Any]]:
    """Groups packets into bidirectional flows (conversations) and computes statistics."""
    flows: dict[tuple[str, str, int, int, str], dict[str, Any]] = {}

    for pkt in packets:
        if not pkt.ip_src or not pkt.ip_dst or not pkt.protocol:
            continue

        ip1, ip2 = pkt.ip_src, pkt.ip_dst
        p1, p2 = pkt.sport or 0, pkt.dport or 0
        proto = pkt.protocol

        # Canonical key: smaller endpoint first
        ep1 = (ip1, p1)
        ep2 = (ip2, p2)
        if ep1 < ep2:
            key = (ip1, ip2, p1, p2, proto)
            forward = True
        else:
            key = (ip2, ip1, p2, p1, proto)
            forward = False

        if key not in flows:
            flows[key] = {
                "endpoint_a": f"{key[0]}:{key[2]}",
                "endpoint_b": f"{key[1]}:{key[3]}",
                "protocol": proto,
                "packets_a_to_b": 0,
                "packets_b_to_a": 0,
                "bytes_a_to_b": 0,
                "bytes_b_to_a": 0,
                "total_packets": 0,
                "total_bytes": 0,
                "start_time": pkt.timestamp,
                "end_time": pkt.timestamp,
            }

        f = flows[key]
        f["total_packets"] += 1
        f["total_bytes"] += pkt.length
        f["end_time"] = max(f["end_time"], pkt.timestamp)
        f["start_time"] = min(f["start_time"], pkt.timestamp)

        if forward:
            f["packets_a_to_b"] += 1
            f["bytes_a_to_b"] += pkt.length
        else:
            f["packets_b_to_a"] += 1
            f["bytes_b_to_a"] += pkt.length

    results = []
    for f in flows.values():
        duration = round(f["end_time"] - f["start_time"], 4)
        f["duration_seconds"] = duration
        results.append(f)

    results.sort(key=lambda x: x["total_bytes"], reverse=True)
    return results
