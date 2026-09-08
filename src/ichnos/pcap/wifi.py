"""802.11 WPA/WPA2 4-Way Handshake (EAPOL) Extractor.

Extracts WPA/WPA2 authentication handshakes from wireless packet captures,
exporting Hashcat mode 22000 formatted hashes for password auditing.
"""

from __future__ import annotations

import struct
from typing import Any


def extract_wpa_handshakes(pcap_data: bytes) -> list[dict[str, Any]]:
    """Extracts WPA/WPA2 4-way handshakes from raw PCAP bytes.

    Returns:
        List of dicts with: 'ssid', 'ap_mac', 'client_mac', 'anonce', 'snonce', 'mic', 'hashcat_22000'.
    """
    if len(pcap_data) < 24:
        return []

    # Parse PCAP global header
    magic = struct.unpack("<I", pcap_data[:4])[0]
    endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    _link_type = struct.unpack(f"{endian}I", pcap_data[20:24])[0]

    handshakes: list[dict[str, Any]] = []

    # Scan for EAPOL ethertype: 0x888E
    pos = 24
    eapol_frames: list[dict[str, Any]] = []
    ap_ssids: dict[str, str] = {}

    while pos + 16 <= len(pcap_data):
        hdr = pcap_data[pos : pos + 16]
        incl_len = struct.unpack(f"{endian}I", hdr[8:12])[0]
        pos += 16
        if pos + incl_len > len(pcap_data):
            break
        pkt = pcap_data[pos : pos + incl_len]
        pos += incl_len

        # Check for 802.11 Beacon frame (SSID extraction)
        beacon_idx = pkt.find(b"\x80\x00")
        if beacon_idx != -1 and len(pkt) > beacon_idx + 38:
            bssid_bytes = pkt[beacon_idx + 16 : beacon_idx + 22]
            bssid_str = ":".join(f"{b:02x}" for b in bssid_bytes)
            # Tagged parameters start at fixed offset 36 in management frame
            tag_idx = beacon_idx + 36
            if tag_idx + 2 < len(pkt) and pkt[tag_idx] == 0:  # Tag 0: SSID
                ssid_len = pkt[tag_idx + 1]
                if tag_idx + 2 + ssid_len <= len(pkt):
                    ssid = pkt[tag_idx + 2 : tag_idx + 2 + ssid_len].decode("utf-8", errors="ignore")
                    if ssid:
                        ap_ssids[bssid_str] = ssid

        # Check for EAPOL ethertype (0x888e)
        eapol_idx = pkt.find(b"\x88\x8e")
        if eapol_idx != -1 and eapol_idx + 2 + 4 < len(pkt):
            eapol_body = pkt[eapol_idx + 2 :]
            version, packet_type, body_len = struct.unpack(">BBH", eapol_body[:4])
            if packet_type == 3:  # EAPOL-Key
                key_desc_type = eapol_body[4]
                if key_desc_type in (2, 254) and len(eapol_body) >= 99:  # RSN/WPA2 key descriptor
                    key_info = struct.unpack(">H", eapol_body[5:7])[0]
                    # Key nonce is at offset 17 (32 bytes)
                    nonce = eapol_body[17:49]
                    # Key MIC is at offset 81 (16 bytes)
                    mic = eapol_body[81:97]

                    # Extract MAC addresses from Ethernet/802.11 header preceding EAPOL
                    src_mac = ":".join(f"{b:02x}" for b in pkt[max(0, eapol_idx - 6) : eapol_idx])
                    dst_mac = ":".join(f"{b:02x}" for b in pkt[max(0, eapol_idx - 12) : eapol_idx - 6])

                    is_mic_set = bool(key_info & 0x0100)
                    eapol_frames.append({
                        "key_info": key_info,
                        "is_mic_set": is_mic_set,
                        "nonce": nonce,
                        "mic": mic,
                        "src_mac": src_mac,
                        "dst_mac": dst_mac,
                        "raw_eapol": eapol_body[: 4 + body_len],
                    })

    # Pair message 1 (AP Anonce, no MIC) with message 2 (Client Snonce, with MIC)
    msg1_list = [f for f in eapol_frames if not f["is_mic_set"]]
    msg2_list = [f for f in eapol_frames if f["is_mic_set"] and any(b != 0 for b in f["mic"])]

    for m2 in msg2_list:
        ap_mac = m2["dst_mac"]
        client_mac = m2["src_mac"]
        snonce = m2["nonce"]
        mic = m2["mic"]

        # Find matching msg1 from same AP
        matching_m1 = next((m1 for m1 in msg1_list if m1["src_mac"] == ap_mac), None)
        anonce = matching_m1["nonce"] if matching_m1 else bytes(32)

        ssid = ap_ssids.get(ap_mac, "UnknownSSID")
        eapol_hex = m2["raw_eapol"].hex()

        # Build Hashcat 22000 line:
        # WPA*02*MIC*MAC_AP*MAC_CLIENT*SSID_HEX*ANONCE*EAPOL
        hashcat_line = (
            f"WPA*02*{mic.hex()}*{ap_mac.replace(':', '')}*"
            f"{client_mac.replace(':', '')}*{ssid.encode().hex()}*"
            f"{anonce.hex()}*{eapol_hex}"
        )

        handshakes.append({
            "ssid": ssid,
            "ap_mac": ap_mac,
            "client_mac": client_mac,
            "anonce": anonce.hex(),
            "snonce": snonce.hex(),
            "mic": mic.hex(),
            "hashcat_22000": hashcat_line,
        })

    return handshakes
