import json
from unittest.mock import MagicMock, patch

from ichnos.osint.dns_lookup import query_doh
from ichnos.osint.subdomains import search_crt_sh
from ichnos.osint.whois import parse_whois_response


def test_parse_whois_response():
    sample_whois = """
    Domain Name: EXAMPLE.COM
    Registry Domain ID: 2336799_DOMAIN_COM-VRSN
    Registrar WHOIS Server: whois.iana.org
    Registrar: RESERVED-Internet Assigned Numbers Authority
    Updated Date: 2023-08-14T07:01:38Z
    Creation Date: 1995-08-14T04:00:00Z
    Registry Expiry Date: 2024-08-13T04:00:00Z
    Name Server: A.IANA-SERVERS.NET
    Name Server: B.IANA-SERVERS.NET
    Domain Status: clientDeleteProhibited
    Domain Status: clientTransferProhibited
    """
    data = parse_whois_response(sample_whois)
    assert data["registrar"] == "RESERVED-Internet Assigned Numbers Authority"
    assert "1995-08-14" in data["creation_date"]
    assert "2024-08-13" in data["expiration_date"]
    assert "a.iana-servers.net" in data["name_servers"]
    assert "b.iana-servers.net" in data["name_servers"]
    assert "clientDeleteProhibited" in data["status"]


@patch("urllib.request.urlopen")
def test_query_doh(mock_urlopen):
    mock_resp = MagicMock()
    mock_data = {
        "Status": 0,
        "Answer": [{"name": "example.com.", "type": 1, "TTL": 300, "data": "93.184.216.34"}],
    }
    mock_resp.read.return_value = json.dumps(mock_data).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    records = query_doh("example.com", record_type="A")
    assert len(records) == 1
    assert records[0]["type"] == "A"
    assert records[0]["data"] == "93.184.216.34"
    assert records[0]["TTL"] == 300


@patch("urllib.request.urlopen")
def test_search_crt_sh(mock_urlopen):
    mock_resp = MagicMock()
    mock_data = [
        {"name_value": "*.example.com\nadmin.example.com"},
        {"name_value": "api.example.com"},
        {"name_value": "otherdomain.com"},
    ]
    mock_resp.read.return_value = json.dumps(mock_data).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    subdomains = search_crt_sh("example.com")
    assert "example.com" in subdomains
    assert "admin.example.com" in subdomains
    assert "api.example.com" in subdomains
    assert "otherdomain.com" not in subdomains
