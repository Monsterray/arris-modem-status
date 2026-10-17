"""Offline checks through real request preparation, parsing, and CLI output."""

import hashlib
import hmac
import json

import pytest
import requests

from arris_modem_status import ArrisModemStatusClient
from arris_modem_status.cli.main import main as cli_main
from arris_modem_status.cli.monitor import main as monitor_main
from arris_modem_status.exceptions import ArrisParsingError


@pytest.fixture
def modem_wire(monkeypatch, mock_modem_responses):
    """Replace only the HTTP adapter; keep Requests preparation and the real client."""
    password = ' $@!"\\雪 '
    key = hmac.new(("public" + password).encode(), b"challenge", hashlib.md5).hexdigest().upper()
    calls = []

    def send(adapter, request, **kwargs):
        calls.append((request, kwargs))
        response = requests.Response()
        response.status_code = 200
        response.request = request
        response.url = request.url
        if request.method == "GET":
            assert request.url.endswith("/Login.html")
            response._content = b"<html>Login</html>"
            return response
        body = json.loads(request.body)
        action = request.headers["SOAPAction"].strip('"')
        digest, timestamp = request.headers["HNAP_AUTH"].split()
        signing_key = b"withoutloginkey" if body.get("Login", {}).get("Action") == "request" else key.encode()
        assert (
            digest == hmac.new(signing_key, (timestamp + '"' + action + '"').encode(), hashlib.md5).hexdigest().upper()
        )
        if "Login" in body:
            if body["Login"]["Action"] == "request":
                data = {
                    "LoginResponse": {
                        "Challenge": "challenge",
                        "PublicKey": "public",
                        "Cookie": "synthetic-uid",
                        "LoginResult": "OK",
                    }
                }
            else:
                assert (
                    body["Login"]["LoginPassword"]
                    == hmac.new(key.encode(), b"challenge", hashlib.md5).hexdigest().upper()
                )
                assert request.headers["Cookie"] == f"uid=synthetic-uid; PrivateKey={key}"
                data = {"LoginResponse": {"LoginResult": "OK"}}
        else:
            assert request.headers["Cookie"] == f"uid=synthetic-uid; PrivateKey={key}"
            assert action.endswith("/GetMultipleHNAPs")
            names = body["GetMultipleHNAPs"]
            if "GetCustomerStatusSoftware" in names:
                data = json.loads(mock_modem_responses["software_info"])
            elif "GetCustomerStatusLog" in names:
                data = {
                    "GetMultipleHNAPsResponse": {
                        "GetCustomerStatusLogResponse": {
                            "CustomerStatusLogList": "0^01/13/2026 14:23:45^^Warning^Synthetic T3 timeout"
                        }
                    }
                }
            else:
                data = json.loads(mock_modem_responses["complete_status"])
        response._content = json.dumps(data).encode()
        return response

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", send)
    monkeypatch.setattr(requests.Session, "get", lambda self, url, **kwargs: self.request("GET", url, **kwargs))
    monkeypatch.setattr("arris_modem_status.client.main.time.sleep", lambda _: None)
    return password, calls


def test_complete_cli_preserves_wrapped_logs(modem_wire, monkeypatch, tmp_path, capsys):
    """A successful full CLI run must preserve data from each requested endpoint."""
    password, calls = modem_wire
    path = tmp_path / "password"
    path.write_text(password + "\n", encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        ["arris-modem-status", "--password-file", str(path), "--hmac-algorithm", "md5", "--timeout", "60"],
    )
    assert cli_main() is None
    captured = capsys.readouterr()
    assert "ARRIS MODEM STATUS SUMMARY" in captured.err
    output = json.loads(captured.out)
    assert output["model_name"] == "S34"
    assert len(output["downstream_channels"]) == len(output["upstream_channels"]) == 3
    assert [entry["message"] for entry in output["log_entries"]] == ["Synthetic T3 timeout"]
    assert len(calls) == 8  # Public GET, challenge, login, five status POSTs.


def test_cli_reports_the_timeout_it_actually_uses(modem_wire, monkeypatch, tmp_path, capsys):
    """Exported metadata must match the timeout sent to the real HTTP adapter."""
    password, calls = modem_wire
    path = tmp_path / "password"
    path.write_text(password, encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        [
            "arris-modem-status",
            "--password-file",
            str(path),
            "--hmac-algorithm",
            "md5",
            "--channels-only",
            "--quiet",
            "--timeout",
            "60",
        ],
    )
    assert cli_main() is None
    output = json.loads(capsys.readouterr().out)
    assert tuple(output["configuration"]["timeout"]) == calls[-1][1]["timeout"] == (2, 60)
    assert len(calls) == 4


def test_bounded_monitor_reuses_wire_session(modem_wire, monkeypatch, tmp_path, capsys):
    """Repeated real-client samples keep one login and emit parseable JSON lines."""
    password, calls = modem_wire
    path = tmp_path / "password"
    path.write_text(password + "\n", encoding="utf-8")
    sleeps = []
    monkeypatch.setattr("arris_modem_status.cli.monitor.time.sleep", sleeps.append)
    assert (
        monitor_main(["--password-file", str(path), "--hmac-algorithm", "md5", "--channels-only", "--samples", "3"])
        == 0
    )
    output = capsys.readouterr()
    samples = [json.loads(line) for line in output.out.splitlines()]
    assert len(samples) == 3
    assert all(len(sample["downstream_channels"]) == len(sample["upstream_channels"]) == 3 for sample in samples)
    assert len(calls) == 6  # One public GET, two login POSTs, three status POSTs.
    assert sleeps.count(900) == 2
    assert password not in output.out + output.err


@pytest.mark.parametrize("result", ["FAILED", "LOCKUP", "REBOOT", "UNKNOWN", None, 0])
def test_rejected_challenge_never_submits_credentials(result, monkeypatch, mock_modem_responses):
    """Even field-complete challenges must stop when the modem rejects phase one."""
    data = json.loads(mock_modem_responses["challenge_response"])
    data["LoginResponse"]["LoginResult"] = result
    calls = []

    def post(*args, **kwargs):
        calls.append(kwargs["json"])
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps(data if len(calls) == 1 else {"LoginResponse": {"LoginResult": "OK"}}).encode()
        return response

    with ArrisModemStatusClient(password="synthetic", max_retries=0) as client:
        monkeypatch.setattr(client.session, "post", post)
        with pytest.raises(ArrisParsingError, match="challenge"):
            client.authenticate()
        assert len(calls) == 1
        assert calls[0]["Login"]["Action"] == "request"
