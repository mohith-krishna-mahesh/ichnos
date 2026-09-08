"""Tests for DTMF audio tone decoding and USB HID keystroke extraction."""

from __future__ import annotations

import math
import struct

from ichnos.pcap.usb import extract_usb_keyboard_data
from ichnos.stego.audio.dtmf import detect_dtmf_tones, goertzel


def test_goertzel_algorithm():
    sample_rate = 8000
    target_freq = 697.0
    duration_s = 0.05
    num_samples = int(sample_rate * duration_s)

    # Generate pure sine wave at 697 Hz
    samples = [math.sin(2 * math.pi * target_freq * i / sample_rate) for i in range(num_samples)]

    # Magnitude at 697 Hz should be much higher than at 1209 Hz
    mag_697 = goertzel(samples, 697.0, sample_rate)
    mag_1209 = goertzel(samples, 1209.0, sample_rate)

    assert mag_697 > mag_1209 * 5


def test_dtmf_tone_detection():
    sample_rate = 8000
    # Generate tone '1' = 697 Hz + 1209 Hz for 80ms
    duration_s = 0.08
    num_samples = int(sample_rate * duration_s)
    samples = [
        0.5 * math.sin(2 * math.pi * 697 * i / sample_rate)
        + 0.5 * math.sin(2 * math.pi * 1209 * i / sample_rate)
        for i in range(num_samples)
    ]

    decoded = detect_dtmf_tones(samples, sample_rate, frame_ms=40, threshold=0.1)
    assert "1" in decoded


def test_usb_hid_keyboard_decoding():
    # PCAP global header (24 bytes) - little endian, linktype = 1 (EN10MB)
    # Magic: \xd4\xc3\xb2\xa1, version: 2.4, thiszone: 0, sigfigs: 0, snaplen: 65535, network: 1
    global_hdr = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    # Packet header: ts_sec, ts_usec, incl_len, orig_len
    # Ethernet (14) + IP (20) + UDP (8) + 8-byte HID report
    # We test with packets that contain 8-byte HID reports
    # Key 'h' (0x0B), Key 'i' (0x0C)
    reports = [
        # 'h'
        bytes([0, 0, 0x0B, 0, 0, 0, 0, 0]),
        # release
        bytes([0, 0, 0, 0, 0, 0, 0, 0]),
        # 'i'
        bytes([0, 0, 0x0C, 0, 0, 0, 0, 0]),
        # release
        bytes([0, 0, 0, 0, 0, 0, 0, 0]),
    ]

    pcap_data = bytearray(global_hdr)
    for rep in reports:
        pkt_hdr = struct.pack("<IIII", 0, 0, len(rep), len(rep))
        pcap_data.extend(pkt_hdr)
        pcap_data.extend(rep)

    typed = extract_usb_keyboard_data(bytes(pcap_data))
    assert typed == "hi"
