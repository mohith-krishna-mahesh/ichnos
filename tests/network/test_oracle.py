"""Unit tests for remote oracle secret recovery client."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ichnos.network.oracle import (
    OracleClient,
    ResumeState,
    is_success,
    recover_byte,
    recover_secret,
)


def test_is_success():
    assert is_success("HALTED", "HALTED")
    assert is_success(1, "1")
    assert is_success({"status": "HALTED"}, "HALTED", success_key="status")
    assert not is_success({"status": "TIMEOUT"}, "HALTED", success_key="status")
    assert not is_success("RUNNING", "HALTED")


def test_resume_state():
    with tempfile.TemporaryDirectory() as tmpdir:
        checkpoint = Path(tmpdir) / "state.json"
        state = ResumeState(str(checkpoint))
        assert state.get(0) is None

        state.set(0, 0x41)
        state.set(1, 0x42)
        assert state.get(0) == 0x41
        assert state.get(1) == 0x42

        # Reload from disk
        state2 = ResumeState(str(checkpoint))
        assert state2.get(0) == 0x41
        assert state2.get(1) == 0x42
        assert state2.get(2) is None


def test_oracle_client_query():
    client = OracleClient("http://test.local/oracle", token="secret_token")

    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({"results": ["OK", "FAIL"]}).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        res = client.query(["prog1", "prog2"])
        assert res == ["OK", "FAIL"]
        assert mock_urlopen.called

        req = mock_urlopen.call_args[0][0]
        assert req.get_header("Authorization") == "Bearer secret_token"
        assert req.get_header("Content-type") == "application/json"


def test_oracle_client_submit():
    client = OracleClient("http://test.local/oracle")

    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({"flag": "ichnos{flag}"}).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = client.submit("41424344")
        assert res == {"flag": "ichnos{flag}"}


def test_oracle_client_key_error():
    client = OracleClient("http://test.local/oracle")

    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({"unexpected": []}).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        with pytest.raises(KeyError):
            client.query(["prog1"])


def test_recover_byte():
    client = MagicMock()
    # Let target secret at addr 2 be 0x15 (21)
    def fake_query(progs):
        res = []
        for p in progs:
            # check if 15 is in the hex program
            res.append("HALTED" if "15" in p else "TIMEOUT")
        return res

    client.query.side_effect = fake_query

    val = recover_byte(
        client=client,
        addr=2,
        batch_size=8,
        program_template="addr:{addr:02x},guess:{guess:02x}",
        success_value="HALTED",
        alphabet_size=32,
    )
    assert val == 0x15


def test_recover_secret_e2e():
    # Secret is b"TEST" = [0x54, 0x45, 0x53, 0x54]
    secret = b"TEST"
    client = MagicMock()

    def fake_query(progs):
        res = []
        for p in progs:
            # Parse addr and guess
            # template: "a={addr:02x}&g={guess:02x}"
            parts = dict(kv.split("=") for kv in p.split("&"))
            a = int(parts["a"], 16)
            g = int(parts["g"], 16)
            res.append("HALTED" if secret[a] == g else "ERR")
        return res

    client.query.side_effect = fake_query
    client.submit.return_value = {"status": "correct", "flag": "ichnos{oracle_solved}"}

    progress_events = []

    def on_prog(addr, val, total):
        progress_events.append((addr, val, total))

    result = recover_secret(
        client=client,
        length=4,
        batch_size=16,
        program_template="a={addr:02x}&g={guess:02x}",
        success_value="HALTED",
        workers=2,
        on_progress=on_prog,
        submit_on_finish=True,
    )

    assert result.secret_bytes == b"TEST"
    assert result.secret_hex == "54455354"
    assert result.recovered_count == 4
    assert result.total_length == 4
    assert result.submit_response == {"status": "correct", "flag": "ichnos{oracle_solved}"}
    assert len(progress_events) == 4
