"""End-to-end integration tests for the Omnichannel AutoSolver."""

from pathlib import Path

from ichnos.core.solver import AutoSolver
from ichnos.crypto.classical.caesar import encrypt as caesar_encrypt
from ichnos.crypto.jwt import jwt_encode
from ichnos.crypto.xor.single_byte import xor_single


def test_autosolve_caesar():
    """Test AutoSolver solves Caesar encrypted text autonomously."""
    plaintext = "flag{caesar_automation_works}"
    ciphertext = caesar_encrypt(plaintext, shift=7)
    trace, res = AutoSolver.solve(active_text=ciphertext)

    assert trace.solved is True
    assert trace.flag == plaintext
    assert "Caesar" in trace.attack_name


def test_autosolve_single_byte_xor():
    """Test AutoSolver solves single-byte XOR hex autonomously."""
    plaintext = b"flag{xor_automation_works}"
    ciphertext_hex = xor_single(plaintext, 0x42).hex()
    trace, res = AutoSolver.solve(active_text=ciphertext_hex)

    assert trace.solved is True
    assert trace.flag == plaintext.decode()
    assert "XOR" in trace.attack_name


def test_autosolve_jwt():
    """Test AutoSolver discovers and extracts flag from JWT token payload."""
    token = jwt_encode(
        header={"typ": "JWT", "alg": "HS256"},
        payload={"sub": "admin", "flag": "flag{jwt_token_harvested}"},
        key="secret123",
    )
    trace, res = AutoSolver.solve(active_text=token)

    assert trace.solved is True
    assert trace.flag == "flag{jwt_token_harvested}"
    assert "JWT" in trace.attack_name or "Web" in trace.attack_name


def test_autosolve_binary_strings(tmp_path: Path):
    """Test AutoSolver discovers flag embedded inside executable binary file."""
    bin_file = tmp_path / "chall.bin"
    # Minimal binary header + embedded flag string
    dummy_elf = (
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32 + b"flag{binary_carver_works}\x00" + b"\x90" * 16
    )
    bin_file.write_bytes(dummy_elf)

    trace, res = AutoSolver.solve(str(bin_file))
    assert trace.solved is True
    assert trace.flag == "flag{binary_carver_works}"
    assert "Binary" in trace.attack_name


def test_autosolve_lwe_compact():
    """Test AutoSolver deterministically solves the Compact-LWE challenge."""
    output_path = Path("scratch/output.py")
    if not output_path.exists():
        return

    trace, res = AutoSolver.solve(str(output_path))
    assert trace.solved is True
    assert trace.flag == "NNS{lwe,compact,broken:https://eprint.iacr.org/2017/742.pdf}"
    assert "LWE" in trace.attack_name


def test_autosolve_pcap(tmp_path: Path):
    """Test AutoSolver extracts flag from packet capture file."""
    from tests.pcap.test_pcap import build_pcap_file, build_pcap_packet

    pkt = build_pcap_packet(
        "93.184.216.34",
        "192.168.1.15",
        6,
        80,
        55555,
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nflag{omnichannel_pcap_success}",
    )
    pcap_data = build_pcap_file([pkt])
    pcap_path = tmp_path / "traffic.pcap"
    pcap_path.write_bytes(pcap_data)

    trace, res = AutoSolver.solve(str(pcap_path))
    assert trace.solved is True
    assert trace.flag == "flag{omnichannel_pcap_success}"
    assert "PCAP" in trace.attack_name
