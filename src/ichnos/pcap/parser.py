"""Pure-Python PCAP and PCAPNG packet reader.

Parses packet capture files without external dependencies.
Supports standard PCAP (LE/BE, microsecond and nanosecond timestamps)
and PCAPNG (Section Header Block and Enhanced Packet Blocks).
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Any


@dataclass
class PCAPPacket:
    """Represents a decoded network packet."""

    timestamp: float
    length: int
    raw: bytes
    src_mac: str | None = None
    dst_mac: str | None = None
    eth_type: int | None = None
    ip_src: str | None = None
    ip_dst: str | None = None
    protocol: str | None = None
    sport: int | None = None
    dport: int | None = None
    tcp_seq: int | None = None
    tcp_ack: int | None = None
    payload: bytes = b""


def format_mac(raw: bytes) -> str:
    """Formats 6-byte raw MAC address to colon-separated string."""
    return ":".join(f"{b:02x}" for b in raw)


def parse_packet_layers(packet_data: bytes, link_type: int = 1) -> dict[str, Any]:
    """Parses Ethernet, Linux SLL, Loopback, IP, and TCP/UDP headers."""
    info: dict[str, Any] = {
        "src_mac": None,
        "dst_mac": None,
        "eth_type": None,
        "ip_src": None,
        "ip_dst": None,
        "protocol": None,
        "sport": None,
        "dport": None,
        "tcp_seq": None,
        "tcp_ack": None,
        "payload": b"",
    }

    if len(packet_data) < 4:
        info["payload"] = packet_data
        return info

    offset = 0
    eth_type = 0

    # 1. Link Layer Decapsulation
    if link_type == 1:  # LINKTYPE_ETHERNET
        if len(packet_data) < 14:
            info["payload"] = packet_data
            return info
        dst_mac, src_mac, eth_type = struct.unpack("!6s6sH", packet_data[:14])
        info["dst_mac"] = format_mac(dst_mac)
        info["src_mac"] = format_mac(src_mac)
        offset = 14

        # Handle 802.1Q VLAN Tag (0x8100)
        if eth_type == 0x8100 and len(packet_data) >= offset + 4:
            eth_type = struct.unpack("!H", packet_data[offset + 2 : offset + 4])[0]
            offset += 4

    elif link_type == 0:  # LINKTYPE_NULL (BSD Loopback)
        family = struct.unpack("<I", packet_data[:4])[0]
        if family not in (2, 24, 28, 30):
            family = struct.unpack(">I", packet_data[:4])[0]
        eth_type = 0x0800 if family == 2 else (0x86DD if family in (24, 28, 30) else 0)
        offset = 4

    elif link_type == 113:  # LINKTYPE_LINUX_SLL (Cooked)
        if len(packet_data) < 16:
            info["payload"] = packet_data
            return info
        _, _, _, _, eth_type = struct.unpack("!HHH8sH", packet_data[:16])
        offset = 16

    elif link_type == 276:  # LINKTYPE_LINUX_SLL2
        if len(packet_data) < 20:
            info["payload"] = packet_data
            return info
        eth_type = struct.unpack("!H", packet_data[:2])[0]
        offset = 20

    elif link_type in (101, 12):  # RAW IP
        v = (packet_data[0] >> 4) & 0x0F
        eth_type = 0x0800 if v == 4 else (0x86DD if v == 6 else 0)
        offset = 0
    else:
        info["payload"] = packet_data
        return info

    info["eth_type"] = eth_type
    ip_data = packet_data[offset:]

    # 2. Network Layer Decapsulation
    if eth_type == 0x0800 and len(ip_data) >= 20:  # IPv4
        v_ihl = ip_data[0]
        ihl = (v_ihl & 0x0F) * 4
        if ihl < 20 or ihl > len(ip_data):
            info["payload"] = ip_data
            return info

        proto = ip_data[9]
        src_ip = socket.inet_ntoa(ip_data[12:16])
        dst_ip = socket.inet_ntoa(ip_data[16:20])

        info["ip_src"] = src_ip
        info["ip_dst"] = dst_ip

        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        info["protocol"] = proto_map.get(proto, f"IP-{proto}")

        transport_data = ip_data[ihl:]
        if proto == 6 and len(transport_data) >= 20:  # TCP
            sport, dport, seq, ack, offset_flags = struct.unpack("!HHIIH", transport_data[:14])
            tcp_offset = ((offset_flags >> 12) & 0x0F) * 4
            info["sport"] = sport
            info["dport"] = dport
            info["tcp_seq"] = seq
            info["tcp_ack"] = ack
            if 20 <= tcp_offset <= len(transport_data):
                info["payload"] = transport_data[tcp_offset:]
            else:
                info["payload"] = transport_data[20:]
        elif proto == 17 and len(transport_data) >= 8:  # UDP
            sport, dport, ulen = struct.unpack("!HHH", transport_data[:6])
            info["sport"] = sport
            info["dport"] = dport
            if 8 <= ulen <= len(transport_data):
                info["payload"] = transport_data[8:ulen]
            else:
                info["payload"] = transport_data[8:]
        else:
            info["payload"] = transport_data

    elif eth_type == 0x86DD and len(ip_data) >= 40:  # IPv6
        next_hdr = ip_data[6]
        src_ip = socket.inet_ntop(socket.AF_INET6, ip_data[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, ip_data[24:40])
        info["ip_src"] = src_ip
        info["ip_dst"] = dst_ip

        proto_map = {6: "TCP", 17: "UDP", 58: "ICMPv6"}
        info["protocol"] = proto_map.get(next_hdr, f"IPv6-{next_hdr}")
        transport_data = ip_data[40:]

        if next_hdr == 6 and len(transport_data) >= 20:
            sport, dport, seq, ack, offset_flags = struct.unpack("!HHIIH", transport_data[:14])
            tcp_offset = ((offset_flags >> 12) & 0x0F) * 4
            info["sport"] = sport
            info["dport"] = dport
            if 20 <= tcp_offset <= len(transport_data):
                info["payload"] = transport_data[tcp_offset:]
            else:
                info["payload"] = transport_data[20:]
        elif next_hdr == 17 and len(transport_data) >= 8:
            sport, dport, ulen = struct.unpack("!HHH", transport_data[:6])
            info["sport"] = sport
            info["dport"] = dport
            if 8 <= ulen <= len(transport_data):
                info["payload"] = transport_data[8:ulen]
            else:
                info["payload"] = transport_data[8:]
        else:
            info["payload"] = transport_data

    return info


MAX_PACKETS = 250_000


def read_pcap(data: bytes) -> list[PCAPPacket]:
    """Parses raw bytes of a PCAP or PCAPNG file and returns list of PCAPPacket."""
    if len(data) < 24:
        raise ValueError("File too short to be a valid PCAP/PCAPNG capture")

    # Check for PCAPNG (0x0A0D0D0A)
    if data[:4] == b"\n\r\r\n":
        return read_pcapng(data)

    # Standard PCAP
    magic = data[:4]
    endian = "<"
    nanosec = False

    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
    elif magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        endian = "<" if magic == b"\x4d\x3c\xb2\xa1" else ">"
        nanosec = True
    else:
        raise ValueError("Invalid PCAP magic bytes")

    v_maj, v_min, tz, sigfigs, snaplen, link_type = struct.unpack(f"{endian}HHIIII", data[4:24])

    packets: list[PCAPPacket] = []
    offset = 24
    total_len = len(data)

    while offset + 16 <= total_len and len(packets) < MAX_PACKETS:
        ts_sec, ts_sub, caplen, origlen = struct.unpack(f"{endian}IIII", data[offset : offset + 16])
        offset += 16

        if caplen < 0 or offset + caplen > total_len:
            break

        pkt_raw = data[offset : offset + caplen]
        offset += caplen

        ts = float(ts_sec) + (float(ts_sub) / 1e9 if nanosec else float(ts_sub) / 1e6)
        layers = parse_packet_layers(pkt_raw, link_type)

        packets.append(
            PCAPPacket(
                timestamp=ts,
                length=origlen,
                raw=pkt_raw,
                src_mac=layers["src_mac"],
                dst_mac=layers["dst_mac"],
                eth_type=layers["eth_type"],
                ip_src=layers["ip_src"],
                ip_dst=layers["ip_dst"],
                protocol=layers["protocol"],
                sport=layers["sport"],
                dport=layers["dport"],
                tcp_seq=layers["tcp_seq"],
                tcp_ack=layers["tcp_ack"],
                payload=layers["payload"],
            )
        )

    return packets


def read_pcapng(data: bytes) -> list[PCAPPacket]:
    """Parses PCAPNG format blocks."""
    packets: list[PCAPPacket] = []
    offset = 0
    total_len = len(data)
    endian = "<"
    ts_resolutions: dict[int, float] = {}  # interface_id -> multiplier
    default_link_type = 1

    while offset + 8 <= total_len and len(packets) < MAX_PACKETS:
        block_type, block_len = struct.unpack(f"{endian}II", data[offset : offset + 8])
        if block_len < 12 or offset + block_len > total_len:
            break

        body = data[offset + 8 : offset + block_len - 4]

        # Section Header Block (0x0A0D0D0A)
        if block_type == 0x0A0D0D0A:
            if len(body) >= 4:
                bom = body[:4]
                if bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                elif bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"

        # Interface Description Block (0x00000001)
        elif block_type == 0x00000001:
            if len(body) >= 4:
                link_t = struct.unpack(f"{endian}H", body[:2])[0]
                iface_id = len(ts_resolutions)
                default_link_type = link_t
                ts_resolutions[iface_id] = 1e-6  # Default microsecond

        # Simple Packet Block (0x00000003)
        elif block_type == 0x00000003:
            if len(body) >= 4:
                origlen = struct.unpack(f"{endian}I", body[:4])[0]
                caplen = min(origlen, len(body) - 4)
                pkt_raw = body[4 : 4 + caplen]
                layers = parse_packet_layers(pkt_raw, default_link_type)
                packets.append(
                    PCAPPacket(
                        timestamp=0.0,
                        length=origlen,
                        raw=pkt_raw,
                        src_mac=layers["src_mac"],
                        dst_mac=layers["dst_mac"],
                        eth_type=layers["eth_type"],
                        ip_src=layers["ip_src"],
                        ip_dst=layers["ip_dst"],
                        protocol=layers["protocol"],
                        sport=layers["sport"],
                        dport=layers["dport"],
                        tcp_seq=layers["tcp_seq"],
                        tcp_ack=layers["tcp_ack"],
                        payload=layers["payload"],
                    )
                )

        # Enhanced Packet Block (0x00000006)
        elif block_type == 0x00000006:
            if len(body) >= 20:
                iface_id, ts_hi, ts_lo, caplen, origlen = struct.unpack(f"{endian}IIIII", body[:20])
                ts_raw = (ts_hi << 32) | ts_lo
                res_mult = ts_resolutions.get(iface_id, 1e-6)
                ts = float(ts_raw) * res_mult

                caplen = min(max(0, caplen), len(body) - 20)
                pkt_raw = body[20 : 20 + caplen]
                layers = parse_packet_layers(pkt_raw, default_link_type)

                packets.append(
                    PCAPPacket(
                        timestamp=ts,
                        length=origlen,
                        raw=pkt_raw,
                        src_mac=layers["src_mac"],
                        dst_mac=layers["dst_mac"],
                        eth_type=layers["eth_type"],
                        ip_src=layers["ip_src"],
                        ip_dst=layers["ip_dst"],
                        protocol=layers["protocol"],
                        sport=layers["sport"],
                        dport=layers["dport"],
                        tcp_seq=layers["tcp_seq"],
                        tcp_ack=layers["tcp_ack"],
                        payload=layers["payload"],
                    )
                )

        offset += block_len

    return packets
