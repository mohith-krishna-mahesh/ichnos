"""Tests for advanced PCAP analysis modules.

Covers:
- Bluetooth HCI/L2CAP/HID packet scanning
- 802.11 WPA/WPA2 4-way handshake extractor
- ICMP and DNS covert channel exfiltration stream reassembler
"""

from ichnos.pcap.bluetooth import scan_bluetooth_packets
from ichnos.pcap.exfiltration import (
    extract_dns_tunneling,
    extract_icmp_payloads,
    reassemble_icmp_stream,
)
from ichnos.pcap.parser import PCAPPacket
from ichnos.pcap.wifi import extract_wpa_handshakes


def test_bluetooth_scanner():
    empty_res = scan_bluetooth_packets(b"")
    assert empty_res["bt_packets_count"] == 0

    # Synthetic capture bytes with GATT string
    dummy_pcap = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20 + b"GATT_FLAG{ble_keystroke_found}_service"
    res = scan_bluetooth_packets(dummy_pcap)
    assert any("FLAG{ble_keystroke_found}" in s for s in res["carved_strings"])


def test_wifi_wpa_extractor():
    # PCAP header only (no packets)
    global_hdr = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x69\x00\x00\x00"
    res = extract_wpa_handshakes(global_hdr)
    assert isinstance(res, list)
    assert len(res) == 0


def test_icmp_exfiltration_reassembly():
    # Create synthetic ICMP echo request packets
    # Type 8, code 0, cksum 0, id 1, seq 1..4
    flag_text = b"FLAG{icmp_tunnel_exfil}"

    packets: list[PCAPPacket] = []
    # Send 1 byte per packet
    for idx, b in enumerate(flag_text):
        icmp_raw = bytes([8, 0, 0, 0, 0, 1, 0, idx]) + bytes([b])
        pkt = PCAPPacket(
            timestamp=1000.0 + idx,
            length=len(icmp_raw),
            raw=icmp_raw,
            protocol="ICMP",
            ip_src="192.168.1.10",
            ip_dst="192.168.1.1",
            payload=icmp_raw,
        )
        packets.append(pkt)

    extracted = extract_icmp_payloads(packets)
    assert len(extracted) == len(flag_text)

    stream = reassemble_icmp_stream(packets)
    assert flag_text in stream


def test_dns_tunneling_extraction():
    # Queries like: 666c61677b646e737d.tunnel.attacker.com (hex for 'flag{dns}')
    import struct

    queries_data = [
        "666c6167.tunnel.attacker.com",
        "7b646e73.tunnel.attacker.com",
        "7d.tunnel.attacker.com",
    ]

    packets: list[PCAPPacket] = []
    for idx, name in enumerate(queries_data):
        # Build DNS payload
        # 12-byte header: tx_id=1, flags=0x0100 (standard query), qdcount=1
        dns_hdr = struct.pack("!HHHHHH", idx + 1, 0x0100, 1, 0, 0, 0)
        # Encode question name
        name_bytes = bytearray()
        for part in name.split("."):
            name_bytes.append(len(part))
            name_bytes.extend(part.encode("latin-1"))
        name_bytes.append(0)  # root
        name_bytes.extend(struct.pack("!HH", 1, 1))  # Type A, Class IN

        payload = bytes(dns_hdr + name_bytes)
        pkt = PCAPPacket(
            timestamp=2000.0 + idx,
            length=len(payload),
            raw=payload,
            protocol="UDP",
            sport=54321,
            dport=53,
            ip_src="10.0.0.5",
            ip_dst="8.8.8.8",
            payload=payload,
        )
        packets.append(pkt)

    res = extract_dns_tunneling(packets)
    assert res["queries_count"] == 3
    assert res["target_domain"] == "tunnel.attacker.com"
    assert any(b"flag{dns}" in c for c in res["candidates"])
