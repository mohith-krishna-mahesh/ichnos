from unittest.mock import MagicMock, patch

from ichnos.web.extract import extract_assets
from ichnos.web.fuzz import fuzz_paths
from ichnos.web.headers import audit_headers


def test_audit_headers():
    # Headers with HSTS, CSP, and an information leak
    sample_headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3",
    }
    report = audit_headers(sample_headers)
    assert report["score"] == 45  # HSTS (20) + CSP (25)
    assert any(h["key"] == "strict-transport-security" for h in report["present_headers"])
    assert any(h["key"] == "x-frame-options" for h in report["missing_headers"])
    assert len(report["information_leaks"]) == 2
    assert report["information_leaks"][0]["header"] == "server"


def test_extract_assets():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <script src="/js/app.js"></script>
        <!-- CTF FLAG: flag{html_comments_leak_secrets} -->
    </head>
    <body>
        <a href="/dashboard">Dashboard</a>
        <a href="https://external.com">External</a>
        <img src="/img/logo.png" />
        <form action="/login" method="POST">
            <input type="text" name="username" value="" />
            <input type="password" name="password" value="" />
        </form>
        <p>Contact us at admin@cyberchallenge.org or support@ichnos.sec</p>
        <script>
            const endpoint = '/api/v1/users';
        </script>
    </body>
    </html>
    """
    res = extract_assets(html)
    assert "/dashboard" in res["links"]
    assert "https://external.com" in res["links"]
    assert "/js/app.js" in res["scripts"]
    assert "/img/logo.png" in res["images"]
    assert any("flag{html_comments_leak_secrets}" in c for c in res["comments"])
    assert len(res["forms"]) == 1
    assert res["forms"][0]["action"] == "/login"
    assert "admin@cyberchallenge.org" in res["emails"]
    assert "support@ichnos.sec" in res["emails"]
    assert "/api/v1/users" in res["api_endpoints"]


@patch("urllib.request.urlopen")
def test_fuzz_paths(mock_urlopen):
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = b"OK content"
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    results = fuzz_paths("http://example.com", ["admin", "robots.txt"], max_workers=2)
    assert len(results) == 2
    assert results[0]["status"] == 200
    assert results[0]["content_length"] == 10
