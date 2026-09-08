from unittest.mock import MagicMock, patch

from ichnos.network.banner import grab_banner
from ichnos.network.scanner import parse_port_range, scan_ports, scan_single_port
from ichnos.network.tls import inspect_tls


def test_parse_port_range():
    assert parse_port_range("80") == [80]
    assert parse_port_range("80,443") == [80, 443]
    assert parse_port_range("8000-8003") == [8000, 8001, 8002, 8003]
    assert parse_port_range("80,8000-8002,443") == [80, 443, 8000, 8001, 8002]
    assert parse_port_range([22, 80, 22]) == [22, 80]


@patch("socket.socket")
def test_scan_single_port(mock_socket_cls):
    mock_s = MagicMock()
    mock_socket_cls.return_value = mock_s

    # Open port
    mock_s.connect_ex.return_value = 0
    res = scan_single_port("192.168.1.1", 80)
    assert res is not None
    assert res["port"] == 80
    assert res["state"] == "open"

    # Closed port
    mock_s.connect_ex.return_value = 111
    res_closed = scan_single_port("192.168.1.1", 81)
    assert res_closed is None


@patch("socket.socket")
def test_scan_ports(mock_socket_cls):
    mock_s = MagicMock()
    mock_socket_cls.return_value = mock_s
    # Port 80 is open, 443 is closed
    mock_s.connect_ex.side_effect = lambda addr: 0 if addr[1] == 80 else 111

    res = scan_ports("192.168.1.1", ports="80,443")
    assert len(res) == 1
    assert res[0]["port"] == 80


@patch("socket.socket")
def test_grab_banner(mock_socket_cls):
    mock_s = MagicMock()
    mock_socket_cls.return_value = mock_s
    mock_s.recv.return_value = b"SSH-2.0-OpenSSH_9.3\r\n"

    banner = grab_banner("10.0.0.1", 22)
    assert banner == "SSH-2.0-OpenSSH_9.3"


@patch("ssl.create_default_context")
@patch("socket.socket")
def test_inspect_tls(mock_socket_cls, mock_ssl_ctx):
    mock_ctx_inst = MagicMock()
    mock_ssl_ctx.return_value = mock_ctx_inst

    mock_ssock = MagicMock()
    mock_ctx_inst.wrap_socket.return_value.__enter__.return_value = mock_ssock

    mock_ssock.getpeercert.return_value = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("commonName", "Let's Encrypt Authority"),),),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        "notBefore": "Jan  1 00:00:00 2024 GMT",
        "notAfter": "Jan  1 00:00:00 2030 GMT",
        "serialNumber": "0123456789ABCDEF",
    }
    mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    mock_ssock.version.return_value = "TLSv1.3"

    res = inspect_tls("example.com")
    assert res["host"] == "example.com"
    assert res["tls_version"] == "TLSv1.3"
    assert res["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
    assert res["subject"]["commonName"] == "example.com"
    assert res["issuer"]["commonName"] == "Let's Encrypt Authority"
    assert "DNS:example.com" in res["subject_alt_names"]
    assert res["expired"] is False
