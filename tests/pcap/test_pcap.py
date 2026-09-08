import socket
import struct

from ichnos.pcap.credentials import extract_credentials
from ichnos.pcap.dns import extract_dns_queries
from ichnos.pcap.flows import extract_flows
from ichnos.pcap.http import reconstruct_http
from ichnos.pcap.parser import PCAPPacket, read_pcap


def build_pcap_packet(
    src_ip: str,
    dst_ip: str,
    proto: int,
    sport: int,
    dport: int,
    payload: bytes,
    ts: float = 1700000000.0,
) -> bytes:
    """Constructs an Ethernet + IPv4 + TCP/UDP frame wrapped in PCAP packet record."""
    # Ethernet
    dst_mac = b"\x00\x11\x22\x33\x44\x55"
    src_mac = b"\x66\x77\x88\x99\xaa\xbb"
    eth_hdr = struct.pack("!6s6sH", dst_mac, src_mac, 0x0800)

    # Transport
    if proto == 6:  # TCP
        seq = 1000
        ack = 0
        offset_flags = (5 << 12) | 0x02  # 20 bytes, SYN
        trans_hdr = struct.pack("!HHIIH", sport, dport, seq, ack, offset_flags) + b"\x00" * 6
    elif proto == 17:  # UDP
        ulen = 8 + len(payload)
        trans_hdr = struct.pack("!HHHH", sport, dport, ulen, 0)
    else:
        trans_hdr = b""

    # IPv4
    ip_payload = trans_hdr + payload
    total_len = 20 + len(ip_payload)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        54321,
        0,
        64,
        proto,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )

    frame = eth_hdr + ip_hdr + ip_payload

    # PCAP packet record header
    sec = int(ts)
    usec = int((ts - sec) * 1e6)
    rec_hdr = struct.pack("<IIII", sec, usec, len(frame), len(frame))
    return rec_hdr + frame


def build_pcap_file(packet_records: list[bytes]) -> bytes:
    # Classic PCAP LE microsecond header
    # magic=0xa1b2c3d4, v_maj=2, v_min=4, tz=0, sigfigs=0, snaplen=65535, link_type=1 (Ethernet)
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    return global_hdr + b"".join(packet_records)


def test_pcap_parsing_and_flows():
    pkt1 = build_pcap_packet(
        "10.0.0.1", "10.0.0.2", proto=6, sport=12345, dport=80, payload=b"SYN_DATA", ts=1700000000.0
    )
    pkt2 = build_pcap_packet(
        "10.0.0.2", "10.0.0.1", proto=6, sport=80, dport=12345, payload=b"ACK_DATA", ts=1700000001.0
    )
    raw_pcap = build_pcap_file([pkt1, pkt2])

    packets = read_pcap(raw_pcap)
    assert len(packets) == 2
    assert packets[0].ip_src == "10.0.0.1"
    assert packets[0].ip_dst == "10.0.0.2"
    assert packets[0].protocol == "TCP"
    assert packets[0].sport == 12345
    assert packets[0].dport == 80

    flows = extract_flows(packets)
    assert len(flows) == 1
    flow = flows[0]
    assert flow["total_packets"] == 2
    assert flow["protocol"] == "TCP"
    assert flow["duration_seconds"] == 1.0


def test_pcap_dns_queries():
    # DNS Question: ctf.example.com Type A
    # QName: \x03ctf\x07example\x03com\x00
    qname = b"\x03ctf\x07example\x03com\x00"
    dns_payload = (
        struct.pack("!HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    )
    pkt = build_pcap_packet(
        "192.168.1.50", "8.8.8.8", proto=17, sport=54321, dport=53, payload=dns_payload
    )
    raw_pcap = build_pcap_file([pkt])

    packets = read_pcap(raw_pcap)
    queries = extract_dns_queries(packets)
    assert len(queries) == 1
    assert queries[0]["name"] == "ctf.example.com"
    assert queries[0]["type"] == "A"
    assert queries[0]["transaction_id"] == "0x1337"


def test_pcap_credentials_and_http():
    http_req = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: secret.ctf.local\r\n"
        b"Authorization: Basic YWRtaW46c3VwZXJzZWNyZXQ=\r\n"
        b"Content-Length: 29\r\n\r\n"
        b"user=hacker&password=p@ssword"
    )
    pkt_http = build_pcap_packet(
        "192.168.1.10", "10.10.10.10", proto=6, sport=50000, dport=80, payload=http_req
    )

    ftp_req1 = b"USER flag_admin\r\n"
    ftp_req2 = b"PASS flag{ftp_plaintext_pass}\r\n"
    pkt_ftp1 = build_pcap_packet(
        "192.168.1.10", "10.10.10.20", proto=6, sport=50001, dport=21, payload=ftp_req1
    )
    pkt_ftp2 = build_pcap_packet(
        "192.168.1.10", "10.10.10.20", proto=6, sport=50001, dport=21, payload=ftp_req2
    )

    raw_pcap = build_pcap_file([pkt_http, pkt_ftp1, pkt_ftp2])
    packets = read_pcap(raw_pcap)

    creds = extract_credentials(packets)
    cred_types = [c["type"] for c in creds]
    assert "HTTP Basic Auth" in cred_types
    assert "FTP Username" in cred_types
    assert "FTP Password" in cred_types
    assert any("admin:supersecret" in c["credential"] for c in creds)
    assert any("flag{ftp_plaintext_pass}" in c["credential"] for c in creds)

    http_msgs = reconstruct_http(packets)
    assert len(http_msgs) == 1
    assert http_msgs[0]["method"] == "POST"
    assert http_msgs[0]["url"] == "http://secret.ctf.local/login"


def test_tcp_stream_reassembly_out_of_order_and_retransmission():
    """Tests TCP stream reassembly handling out-of-order segments and duplicate retransmissions."""
    from ichnos.pcap.reassembly import reassemble_stream

    # Base IP/TCP template
    def make_tcp_pkt(seq: int, payload: bytes, ts: float) -> PCAPPacket:
        return PCAPPacket(
            timestamp=ts,
            length=len(payload) + 40,
            raw=payload,
            src_mac="",
            dst_mac="",
            eth_type=0x0800,
            ip_src="192.168.1.100",
            ip_dst="10.0.0.1",
            protocol="TCP",
            sport=44444,
            dport=80,
            tcp_seq=seq,
            tcp_ack=1,
            payload=payload,
        )

    # 3 segments out-of-order + 1 duplicate retransmission:
    # 1. seq=1000, len=16: b"FLAG{reassembly_"
    # 2. seq=1016, len=12: b"out_of_order"
    # 3. seq=1028, len=9:  b"_working}"
    pkt1 = make_tcp_pkt(1000, b"FLAG{reassembly_", ts=1.0)
    pkt2 = make_tcp_pkt(1016, b"out_of_order", ts=3.0)
    pkt3 = make_tcp_pkt(1028, b"_working}", ts=4.0)
    pkt1_dup = make_tcp_pkt(1000, b"FLAG{reassembly_", ts=2.0)  # Duplicate retransmit

    # Feed in scrambled order: pkt2, pkt1, pkt1_dup, pkt3
    scrambled = [pkt2, pkt1, pkt1_dup, pkt3]
    assembled = reassemble_stream(scrambled)
    assert assembled == b"FLAG{reassembly_out_of_order_working}"


def test_pcapng_epb_and_spb():
    """Tests parsing PCAPNG format with Section Header, Interface Desc, EPB and SPB."""
    # Construct IPv4 UDP DNS packet
    dst_mac = b"\x00\x11\x22\x33\x44\x55"
    src_mac = b"\x66\x77\x88\x99\xaa\xbb"
    eth_hdr = struct.pack("!6s6sH", dst_mac, src_mac, 0x0800)
    payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04test\x03org\x00\x00\x01\x00\x01"
    udp_hdr = struct.pack("!HHHH", 53000, 53, 8 + len(payload), 0)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp_hdr) + len(payload),
        1,
        0,
        64,
        17,
        0,
        socket.inet_aton("1.2.3.4"),
        socket.inet_aton("8.8.4.4"),
    )
    frame = eth_hdr + ip_hdr + udp_hdr + payload

    def pad4(data: bytes) -> bytes:
        pad = (4 - (len(data) % 4)) % 4
        return data + b"\x00" * pad

    # 1. Section Header Block (0x0A0D0D0A)
    # magic(4)=0x1A2B3C4D, major(2)=1, minor(2)=0, section_len(8)=-1
    shb = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb_len = 8 + len(shb) + 4
    shb_block = struct.pack("<II", 0x0A0D0D0A, shb_len) + shb + struct.pack("<I", shb_len)

    # 2. Interface Description Block (0x00000001)
    # link_type(2)=1 (Ethernet), reserved(2)=0, snaplen(4)=65535
    idb = struct.pack("<HHI", 1, 0, 65535)
    idb_len = 8 + len(idb) + 4
    idb_block = struct.pack("<II", 0x00000001, idb_len) + idb + struct.pack("<I", idb_len)

    # 3. Enhanced Packet Block (0x00000006)
    padded_frame = pad4(frame)
    # iface_id(4)=0, ts_hi(4)=0, ts_lo(4)=1000000, caplen(4), origlen(4)
    epb_body = struct.pack("<IIIII", 0, 0, 1000000, len(frame), len(frame)) + padded_frame
    epb_len = 8 + len(epb_body) + 4
    epb_block = struct.pack("<II", 0x00000006, epb_len) + epb_body + struct.pack("<I", epb_len)

    # 4. Simple Packet Block (0x00000003)
    spb_body = struct.pack("<I", len(frame)) + padded_frame
    spb_len = 8 + len(spb_body) + 4
    spb_block = struct.pack("<II", 0x00000003, spb_len) + spb_body + struct.pack("<I", spb_len)

    pcapng_data = shb_block + idb_block + epb_block + spb_block
    packets = read_pcap(pcapng_data)

    assert len(packets) == 2
    assert packets[0].protocol == "UDP"
    assert packets[0].ip_src == "1.2.3.4"
    assert packets[0].ip_dst == "8.8.4.4"
    assert packets[0].sport == 53000
    assert packets[0].dport == 53
    assert packets[0].timestamp == 1.0  # 1000000 * 1e-6

    # SPB
    assert packets[1].protocol == "UDP"
    assert packets[1].ip_src == "1.2.3.4"
    assert packets[1].dport == 53


def test_link_layer_null_loopback_and_sll():
    """Tests parsing captures with non-Ethernet link types (Loopback / Linux SLL)."""
    # Create an IPv4 ICMP packet
    ip_payload = b"\x08\x00\xf7\xff\x00\x00\x00\x00ping_payload"  # ICMP Echo
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(ip_payload),
        1234,
        0,
        64,
        1,
        0,
        socket.inet_aton("127.0.0.1"),
        socket.inet_aton("127.0.0.1"),
    )
    ip_pkt = ip_hdr + ip_payload

    # 1. LINKTYPE_NULL (0): 4-byte family (AF_INET = 2 in little-endian or big-endian)
    null_frame = struct.pack("<I", 2) + ip_pkt
    pcap_null_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 0)  # link_type = 0
    rec_null = struct.pack("<IIII", 1700000000, 0, len(null_frame), len(null_frame)) + null_frame
    pcap_null = pcap_null_hdr + rec_null

    pkts_null = read_pcap(pcap_null)
    assert len(pkts_null) == 1
    assert pkts_null[0].protocol == "ICMP"
    assert pkts_null[0].ip_src == "127.0.0.1"
    assert b"ping_payload" in pkts_null[0].payload

    # 2. LINKTYPE_LINUX_SLL (113): 16-byte cooked header, proto = 0x0800 at offset 14
    sll_hdr = struct.pack("!HHH8sH", 0, 1, 6, b"\x00" * 8, 0x0800)
    sll_frame = sll_hdr + ip_pkt
    pcap_sll_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 113)  # link_type = 113
    rec_sll = struct.pack("<IIII", 1700000000, 0, len(sll_frame), len(sll_frame)) + sll_frame
    pcap_sll = pcap_sll_hdr + rec_sll

    pkts_sll = read_pcap(pcap_sll)
    assert len(pkts_sll) == 1
    assert pkts_sll[0].protocol == "ICMP"
    assert pkts_sll[0].ip_src == "127.0.0.1"


def test_multi_protocol_capture_integration():
    """Realistic multi-protocol capture test containing DNS, out-of-order HTTP, and ICMP."""
    # 1. DNS query & response
    qname = b"\x07example\x03org\x00"
    dns_query = (
        struct.pack("!HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    )
    pkt_dns = build_pcap_packet(
        "192.168.1.15",
        "8.8.8.8",
        proto=17,
        sport=60000,
        dport=53,
        payload=dns_query,
        ts=1700000100.0,
    )

    # 2. HTTP response in 2 TCP packets arriving out-of-order
    # Packet A: seq=2000, len=30: b"HTTP/1.1 200 OK\r\nContent-Type: "
    # Packet B: seq=2030, len=35: b"text/plain\r\n\r\nFLAG{multi_proto_pcap}"
    def make_tcp_frame(src_ip, dst_ip, sport, dport, seq, ack, payload):
        dst_mac = b"\x00\x11\x22\x33\x44\x55"
        src_mac = b"\x66\x77\x88\x99\xaa\xbb"
        eth_hdr = struct.pack("!6s6sH", dst_mac, src_mac, 0x0800)
        offset_flags = (5 << 12) | 0x18  # ACK+PSH
        trans_hdr = struct.pack("!HHIIH", sport, dport, seq, ack, offset_flags) + b"\x00" * 6
        ip_payload = trans_hdr + payload
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(ip_payload),
            555,
            0,
            64,
            6,
            0,
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
        )
        frame = eth_hdr + ip_hdr + ip_payload
        rec_hdr = struct.pack("<IIII", 1700000101, 0, len(frame), len(frame))
        return rec_hdr + frame

    tcp_frag2 = make_tcp_frame(
        "93.184.216.34",
        "192.168.1.15",
        80,
        55555,
        2030,
        100,
        b"text/plain\r\n\r\nFLAG{multi_proto_pcap}",
    )
    tcp_frag1 = make_tcp_frame(
        "93.184.216.34", "192.168.1.15", 80, 55555, 2000, 100, b"HTTP/1.1 200 OK\r\nContent-Type: "
    )

    pcap_bytes = build_pcap_file([pkt_dns, tcp_frag2, tcp_frag1])
    packets = read_pcap(pcap_bytes)
    assert len(packets) == 3

    # Check flows
    flows = extract_flows(packets)
    assert len(flows) == 2  # DNS UDP flow and HTTP TCP flow

    # Check DNS queries
    dns_queries = extract_dns_queries(packets)
    assert len(dns_queries) == 1
    assert dns_queries[0]["name"] == "example.org"

    # Check reconstructed HTTP
    http_msgs = reconstruct_http(packets)
    assert len(http_msgs) == 1
    assert http_msgs[0]["type"] == "response"
    assert http_msgs[0]["status_code"] == 200
    assert "FLAG{multi_proto_pcap}" in http_msgs[0]["body_preview"]


def test_solve_pcap_http_flag():
    from ichnos.pcap.solver import solve_pcap

    pkt = build_pcap_packet(
        "93.184.216.34",
        "192.168.1.15",
        6,
        80,
        55555,
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nFLAG{solve_pcap_works}",
    )
    pcap_data = build_pcap_file([pkt])
    res = solve_pcap(pcap_data)
    assert res["solved"] is True
    assert res["flag"] == "FLAG{solve_pcap_works}"
