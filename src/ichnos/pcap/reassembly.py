"""TCP stream reassembly engine.

Reconstructs continuous, deduplicated byte streams across out-of-order packets,
gaps, and retransmissions.
"""

from __future__ import annotations

from dataclasses import dataclass

from ichnos.pcap.parser import PCAPPacket


@dataclass
class TCPSegment:
    """Represents a TCP payload segment."""

    seq: int
    payload: bytes
    timestamp: float


def reassemble_stream(segments: list[TCPSegment | PCAPPacket]) -> bytes:
    """Reassembles a list of TCP segments into a contiguous byte stream.

    Sorts by sequence number, removes duplicate/retransmitted byte ranges,
    and stitches together the ordered payload.
    """
    valid_segments = [s for s in segments if len(s.payload or b"") > 0]
    if not valid_segments:
        return b""

    def get_seq(s: TCPSegment | PCAPPacket) -> int:
        return getattr(s, "seq", getattr(s, "tcp_seq", 0))

    # Sort segments by TCP sequence number, then by timestamp
    valid_segments.sort(key=lambda s: (get_seq(s), s.timestamp))

    stream = bytearray()
    next_expected_seq = get_seq(valid_segments[0])

    for seg in valid_segments:
        seq = get_seq(seg)
        data = seg.payload or b""

        if seq <= next_expected_seq:
            # Overlap or in-order
            overlap = next_expected_seq - seq
            if overlap < len(data):
                new_bytes = data[overlap:]
                stream.extend(new_bytes)
                next_expected_seq += len(new_bytes)
            # If overlap >= len(data), entire segment was already seen (retransmission); skip
        else:
            # Gap / missing packet: advance to new sequence
            stream.extend(data)
            next_expected_seq = seq + len(data)

    return bytes(stream)


def reassemble_all_tcp_flows(
    packets: list[PCAPPacket],
) -> dict[tuple[str, int, str, int], bytes]:
    """Reassembles all unidirectional TCP streams in the packet list.

    Returns mapping: `(src_ip, sport, dst_ip, dport) -> reassembled_bytes`.
    """
    flow_segments: dict[tuple[str, int, str, int], list[TCPSegment]] = {}

    for pkt in packets:
        if (
            pkt.protocol != "TCP"
            or not pkt.ip_src
            or not pkt.ip_dst
            or pkt.sport is None
            or pkt.dport is None
            or not pkt.payload
        ):
            continue

        # Extract TCP seq number from raw transport layer if available
        # In parse_packet_layers, TCP seq is at offset 4 of TCP header
        seq = getattr(pkt, "tcp_seq", 0)

        key = (pkt.ip_src, pkt.sport, pkt.ip_dst, pkt.dport)
        if key not in flow_segments:
            flow_segments[key] = []

        flow_segments[key].append(TCPSegment(seq=seq, payload=pkt.payload, timestamp=pkt.timestamp))

    return {key: reassemble_stream(segs) for key, segs in flow_segments.items()}
